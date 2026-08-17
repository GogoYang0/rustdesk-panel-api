// Package strategy 策略域服务（设计 §3.1 StrategyService / §4.4 指派
// 传播）：CRUD、候选与目标候选、指派清单、assign/unassign（宿主表
// strategyGuid 直写 + AssertStrategyTargets 复核 + {success, errors}
// 部分成功语义）。删除走 DeleteWithDetach 事务置空三处引用（共享知识 9）。
package strategy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/jsonutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// 固定文案（共享知识 1 逐字节）。
const (
	msgStrategyNotFound  = "Strategy not found"
	msgStrategyNameTaken = "Strategy name already exists"
	msgInvalidTargetType = "Invalid target_type"
)

// assign/unassign 逐目标失败 reason（openapi assign/unassign description
// 固定语义：缺失走 not found 文案，未绑定本策略走 not bound 文案）。
const (
	reasonDeviceNotFound = "Device not found"
	reasonUserNotFound   = "User does not exist"
	reasonGroupNotFound  = "Device group not found"

	reasonDeviceNotBound = "Device is not bound to this strategy"
	reasonUserNotBound   = "User is not bound to this strategy"
	reasonGroupNotBound  = "Device group is not bound to this strategy"
)

// 目标形态枚举（openapi target_type 契约）。
const (
	targetDevice      = "device"
	targetUser        = "user"
	targetDeviceGroup = "device_group"
)

// TargetPage 目标形态 oneOf 载荷（恰好一个成员非 nil，handler 据此
// 选择序列化分支）。
type TargetPage struct {
	Devices *dto.PageResult[dto.DeviceTargetView]
	Users   *dto.PageResult[dto.UserTargetView]
	Groups  *dto.PageResult[dto.DeviceGroupTargetView]
}

// Service 策略域服务。
type Service struct {
	authz      *rbac.AuthorizationService
	strategies *repository.StrategyRepo
	peers      *repository.PeerRepo
	users      *repository.UserRepo
	groups     *repository.DeviceGroupRepo
	now        func() time.Time // 注入时钟（单测可控）
}

// NewService 构建服务。
func NewService(
	authz *rbac.AuthorizationService,
	strategies *repository.StrategyRepo,
	peers *repository.PeerRepo,
	users *repository.UserRepo,
	groups *repository.DeviceGroupRepo,
) *Service {
	return &Service{
		authz: authz, strategies: strategies, peers: peers, users: users, groups: groups,
		now: time.Now,
	}
}

// ==================== CRUD（strategies.view/create/edit/delete） ====================

// List GET /api/strategies（Perm(strategies.view) 路由已挡）：
// name LIKE；name ASC + guid ASC 决胜（openapi 契约）。
func (s *Service) List(ctx context.Context, q dto.StrategyListQuery) (dto.PageResult[dto.StrategyView], error) {
	conds := make([]repository.Clause, 0, 1)
	if q.Name != "" {
		conds = append(conds, repository.Clause{Field: "name", Op: repository.OpLike, Value: "%" + q.Name + "%"})
	}
	rows, total, err := s.strategies.List(ctx, repository.Query{
		Where:   conds,
		OrderBy: "name ASC, guid ASC",
		Limit:   q.PageSize,
		Offset:  pageOffset(q.Current, q.PageSize),
	})
	if err != nil {
		return dto.PageResult[dto.StrategyView]{}, fmt.Errorf("strategy: list: %w", err)
	}
	data := make([]dto.StrategyView, 0, len(rows))
	for i := range rows {
		data = append(data, viewOf(rows[i]))
	}
	return dto.PageResult[dto.StrategyView]{Data: data, Total: total}, nil
}

// Get GET /api/strategies/{guid}：404 "Strategy not found"。
func (s *Service) Get(ctx context.Context, guid string) (dto.StrategyView, error) {
	st, err := s.load(ctx, guid)
	if err != nil {
		return dto.StrategyView{}, err
	}
	return viewOf(*st), nil
}

// Create POST /api/strategies（Perm(strategies.create)）：重名 400；
// config_options 未传存空串（读取端解析为 {}）。
func (s *Service) Create(ctx context.Context, req dto.StrategyUpsertRequest) (dto.StrategyView, error) {
	if err := s.assertNameFree(ctx, req.Name, ""); err != nil {
		return dto.StrategyView{}, err
	}
	now := s.now()
	st := &entity.Strategy{
		Guid: uuid.NewString(), Name: req.Name,
		Note:          noteOr(req.Note),
		ConfigOptions: marshalOptions(req.ConfigOptions),
		CreatedAt:     now, UpdatedAt: now,
	}
	if err := s.strategies.Create(ctx, st); err != nil {
		return dto.StrategyView{}, fmt.Errorf("strategy: create: %w", err)
	}
	return viewOf(*st), nil
}

// Update PATCH /api/strategies/{guid}（Perm(strategies.edit)）：
// 重名 400；note/config_options 三态（nil=保持原值，提供即覆盖；
// 空对象覆盖为 "{}"）。
func (s *Service) Update(ctx context.Context, guid string, req dto.StrategyUpsertRequest) (dto.StrategyView, error) {
	st, err := s.load(ctx, guid)
	if err != nil {
		return dto.StrategyView{}, err
	}
	if err := s.assertNameFree(ctx, req.Name, st.Name); err != nil {
		return dto.StrategyView{}, err
	}
	st.Name = req.Name
	if req.Note != nil {
		st.Note = *req.Note
	}
	if req.ConfigOptions != nil {
		st.ConfigOptions = marshalOptions(req.ConfigOptions)
	}
	if err := s.strategies.Update(ctx, st); err != nil {
		return dto.StrategyView{}, fmt.Errorf("strategy: update: %w", err)
	}
	return viewOf(*st), nil
}

// Delete DELETE /api/strategies/{guid}（Perm(strategies.delete)）：
// 404 后 DeleteWithDetach 事务显式置空 peers/users/device_groups
// 三处 strategyGuid 引用（共享知识 9，方言无关）。
func (s *Service) Delete(ctx context.Context, guid string) error {
	if _, err := s.load(ctx, guid); err != nil {
		return err
	}
	return s.strategies.DeleteWithDetach(ctx, guid)
}

// ==================== 候选（strategies.assign） ====================

// Candidates GET /api/strategies/candidates：{guid,name,note} name ASC。
func (s *Service) Candidates(ctx context.Context, q dto.PaginationQuery) (dto.PageResult[dto.StrategyCandidateView], error) {
	rows, total, err := s.strategies.List(ctx, repository.Query{
		OrderBy: "name ASC, guid ASC",
		Limit:   q.PageSize,
		Offset:  pageOffset(q.Current, q.PageSize),
	})
	if err != nil {
		return dto.PageResult[dto.StrategyCandidateView]{}, fmt.Errorf("strategy: candidates: %w", err)
	}
	data := make([]dto.StrategyCandidateView, 0, len(rows))
	for i := range rows {
		data = append(data, dto.StrategyCandidateView{Guid: rows[i].Guid, Name: rows[i].Name, Note: rows[i].Note})
	}
	return dto.PageResult[dto.StrategyCandidateView]{Data: data, Total: total}, nil
}

// TargetCandidates GET /api/strategies/target-candidates：
//   - device：scope 过滤设备（{uuid,id}，peers.id ASC）；
//   - user：须 global scope（403 MsgAssignUserGlobal）；非管理员
//     操作者只见非管理员用户；is_protected 为保护账号判定。
func (s *Service) TargetCandidates(ctx context.Context, actorGuid, targetType string, q dto.PaginationQuery) (TargetPage, error) {
	scope, err := s.authz.GetPermissionScope(ctx, actorGuid, rbac.CodeStrategiesAssign)
	if err != nil {
		return TargetPage{}, err
	}
	switch targetType {
	case targetDevice:
		rows, total, err := s.peers.ListScoped(ctx, guidSet(scope), repository.DeviceFilter{Current: q.Current, PageSize: q.PageSize})
		if err != nil {
			return TargetPage{}, fmt.Errorf("strategy: device candidates: %w", err)
		}
		data := make([]dto.DeviceTargetView, 0, len(rows))
		for i := range rows {
			data = append(data, dto.DeviceTargetView{UUID: rows[i].UUID, ID: rows[i].ID})
		}
		return TargetPage{Devices: &dto.PageResult[dto.DeviceTargetView]{Data: data, Total: total}}, nil
	case targetUser:
		if !scope.Global {
			return TargetPage{}, rbac.ErrForbidden(rbac.MsgAssignUserGlobal)
		}
		actor, err := s.authz.GetCurrentUser(ctx, actorGuid)
		if err != nil {
			return TargetPage{}, err
		}
		rows, total, err := s.users.ListPagedPublic(ctx, !actor.IsAdmin, q.Current, q.PageSize)
		if err != nil {
			return TargetPage{}, fmt.Errorf("strategy: user candidates: %w", err)
		}
		data, err := s.userTargets(ctx, rows)
		if err != nil {
			return TargetPage{}, err
		}
		return TargetPage{Users: &dto.PageResult[dto.UserTargetView]{Data: data, Total: total}}, nil
	default:
		return TargetPage{}, rbac.ErrBadRequest(msgInvalidTargetType)
	}
}

// Assignments GET /api/strategies/{guid}/assignments（target_type 必填）：
// device/device_group 形态按 scope 过滤；device_group 按 name ASC。
func (s *Service) Assignments(ctx context.Context, actorGuid, guid, targetType string, q dto.PaginationQuery) (TargetPage, error) {
	if _, err := s.load(ctx, guid); err != nil {
		return TargetPage{}, err
	}
	scope, err := s.authz.GetPermissionScope(ctx, actorGuid, rbac.CodeStrategiesAssign)
	if err != nil {
		return TargetPage{}, err
	}
	switch targetType {
	case targetDevice:
		rows, total, err := s.peers.ListByStrategy(ctx, guid, guidSet(scope), q.Current, q.PageSize)
		if err != nil {
			return TargetPage{}, fmt.Errorf("strategy: device assignments: %w", err)
		}
		data := make([]dto.DeviceTargetView, 0, len(rows))
		for i := range rows {
			data = append(data, dto.DeviceTargetView{UUID: rows[i].UUID, ID: rows[i].ID})
		}
		return TargetPage{Devices: &dto.PageResult[dto.DeviceTargetView]{Data: data, Total: total}}, nil
	case targetUser:
		if !scope.Global {
			return TargetPage{}, rbac.ErrForbidden(rbac.MsgAssignUserGlobal)
		}
		rows, total, err := s.users.ListByStrategy(ctx, guid, q.Current, q.PageSize)
		if err != nil {
			return TargetPage{}, fmt.Errorf("strategy: user assignments: %w", err)
		}
		data, err := s.userTargets(ctx, rows)
		if err != nil {
			return TargetPage{}, err
		}
		return TargetPage{Users: &dto.PageResult[dto.UserTargetView]{Data: data, Total: total}}, nil
	case targetDeviceGroup:
		rows, total, err := s.groups.ListByStrategy(ctx, guid, q.Current, q.PageSize)
		if err != nil {
			return TargetPage{}, fmt.Errorf("strategy: group assignments: %w", err)
		}
		data := make([]dto.DeviceGroupTargetView, 0, len(rows))
		for i := range rows {
			data = append(data, dto.DeviceGroupTargetView{Guid: rows[i].Guid, Name: rows[i].Name})
		}
		return TargetPage{Groups: &dto.PageResult[dto.DeviceGroupTargetView]{Data: data, Total: total}}, nil
	default:
		return TargetPage{}, rbac.ErrBadRequest(msgInvalidTargetType)
	}
}

// ==================== assign / unassign（§4.4） ====================

// Assign POST /api/strategies/{guid}/assign（§4.4 顺序）：
// AssertStrategyTargets（403/400 族）→ 策略 404 → 逐目标存在性 →
// 存在者事务性回写宿主表 strategyGuid。部分成功 200 {success, errors}。
func (s *Service) Assign(ctx context.Context, actorGuid, guid, targetType string, targets []string) (dto.AssignResult, error) {
	targets = dedup(targets)
	if _, err := s.authz.AssertStrategyTargets(ctx, actorGuid, targetType, targets); err != nil {
		return dto.AssignResult{}, err
	}
	if _, err := s.load(ctx, guid); err != nil {
		return dto.AssignResult{}, err
	}
	switch targetType {
	case targetDeviceGroup:
		rows, err := s.groups.FindByGuids(ctx, targets)
		if err != nil {
			return dto.AssignResult{}, fmt.Errorf("strategy: find groups: %w", err)
		}
		res := split(targets, guidSetOf(rows, func(i int) string { return rows[i].Guid }), reasonGroupNotFound)
		if len(res.Success) > 0 {
			if err := s.groups.UpdateColumnsByGuids(ctx, res.Success, map[string]any{"strategyGuid": guid}); err != nil {
				return dto.AssignResult{}, fmt.Errorf("strategy: assign groups: %w", err)
			}
		}
		return res, nil
	case targetDevice:
		rows, err := s.peers.FindByUUIDs(ctx, targets)
		if err != nil {
			return dto.AssignResult{}, fmt.Errorf("strategy: find devices: %w", err)
		}
		res := split(targets, uuidSetOf(rows), reasonDeviceNotFound)
		if len(res.Success) > 0 {
			if err := s.peers.UpdateColumnsByUUIDs(ctx, res.Success, map[string]any{"strategyGuid": guid}); err != nil {
				return dto.AssignResult{}, fmt.Errorf("strategy: assign devices: %w", err)
			}
		}
		return res, nil
	case targetUser:
		rows, err := s.users.FindByGuids(ctx, targets)
		if err != nil {
			return dto.AssignResult{}, fmt.Errorf("strategy: find users: %w", err)
		}
		res := split(targets, guidSetOf(rows, func(i int) string { return rows[i].Guid }), reasonUserNotFound)
		if len(res.Success) > 0 {
			if err := s.users.UpdateColumnsByGuids(ctx, res.Success, map[string]any{"strategyGuid": guid}); err != nil {
				return dto.AssignResult{}, fmt.Errorf("strategy: assign users: %w", err)
			}
		}
		return res, nil
	default:
		return dto.AssignResult{}, rbac.ErrBadRequest(msgInvalidTargetType)
	}
}

// Unassign POST /api/strategies/{guid}/unassign：解绑 = 置 NULL；
// 额外校验目标当前确已绑定本策略（未绑定/不存在记入 errors，不报 4xx）。
func (s *Service) Unassign(ctx context.Context, actorGuid, guid, targetType string, targets []string) (dto.AssignResult, error) {
	targets = dedup(targets)
	if _, err := s.authz.AssertStrategyTargets(ctx, actorGuid, targetType, targets); err != nil {
		return dto.AssignResult{}, err
	}
	if _, err := s.load(ctx, guid); err != nil {
		return dto.AssignResult{}, err
	}
	res := dto.AssignResult{Success: []string{}, Errors: []dto.AssignError{}}
	bound := func(cur *string) bool { return cur != nil && *cur == guid }
	switch targetType {
	case targetDeviceGroup:
		rows, err := s.groups.FindByGuids(ctx, targets)
		if err != nil {
			return dto.AssignResult{}, fmt.Errorf("strategy: find groups: %w", err)
		}
		byGuid := guidMapOf(rows, func(i int) string { return rows[i].Guid })
		for _, t := range targets {
			g, ok := byGuid[t]
			switch {
			case !ok:
				res.Errors = append(res.Errors, dto.AssignError{TargetGuid: t, Reason: reasonGroupNotFound})
			case !bound(g.StrategyGuid):
				res.Errors = append(res.Errors, dto.AssignError{TargetGuid: t, Reason: reasonGroupNotBound})
			default:
				res.Success = append(res.Success, t)
			}
		}
		if len(res.Success) > 0 {
			if err := s.groups.UpdateColumnsByGuids(ctx, res.Success, map[string]any{"strategyGuid": nil}); err != nil {
				return dto.AssignResult{}, fmt.Errorf("strategy: unassign groups: %w", err)
			}
		}
		return res, nil
	case targetDevice:
		rows, err := s.peers.FindByUUIDs(ctx, targets)
		if err != nil {
			return dto.AssignResult{}, fmt.Errorf("strategy: find devices: %w", err)
		}
		byUUID := make(map[string]entity.Peer, len(rows))
		for i := range rows {
			byUUID[rows[i].UUID] = rows[i]
		}
		for _, t := range targets {
			p, ok := byUUID[t]
			switch {
			case !ok:
				res.Errors = append(res.Errors, dto.AssignError{TargetGuid: t, Reason: reasonDeviceNotFound})
			case !bound(p.StrategyGuid):
				res.Errors = append(res.Errors, dto.AssignError{TargetGuid: t, Reason: reasonDeviceNotBound})
			default:
				res.Success = append(res.Success, t)
			}
		}
		if len(res.Success) > 0 {
			if err := s.peers.UpdateColumnsByUUIDs(ctx, res.Success, map[string]any{"strategyGuid": nil}); err != nil {
				return dto.AssignResult{}, fmt.Errorf("strategy: unassign devices: %w", err)
			}
		}
		return res, nil
	case targetUser:
		rows, err := s.users.FindByGuids(ctx, targets)
		if err != nil {
			return dto.AssignResult{}, fmt.Errorf("strategy: find users: %w", err)
		}
		byGuid := guidMapOf(rows, func(i int) string { return rows[i].Guid })
		for _, t := range targets {
			u, ok := byGuid[t]
			switch {
			case !ok:
				res.Errors = append(res.Errors, dto.AssignError{TargetGuid: t, Reason: reasonUserNotFound})
			case !bound(u.StrategyGuid):
				res.Errors = append(res.Errors, dto.AssignError{TargetGuid: t, Reason: reasonUserNotBound})
			default:
				res.Success = append(res.Success, t)
			}
		}
		if len(res.Success) > 0 {
			if err := s.users.UpdateColumnsByGuids(ctx, res.Success, map[string]any{"strategyGuid": nil}); err != nil {
				return dto.AssignResult{}, fmt.Errorf("strategy: unassign users: %w", err)
			}
		}
		return res, nil
	default:
		return dto.AssignResult{}, rbac.ErrBadRequest(msgInvalidTargetType)
	}
}

// ==================== 内部辅助 ====================

// load 策略存在性（404 "Strategy not found" 收口）。
func (s *Service) load(ctx context.Context, guid string) (*entity.Strategy, error) {
	st, err := s.strategies.FindByID(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, rbac.ErrNotFoundErr(msgStrategyNotFound)
		}
		return nil, err
	}
	return st, nil
}

// assertNameFree 重名校验（create 全查 / update 排除自身当前名）。
func (s *Service) assertNameFree(ctx context.Context, name, except string) error {
	if name == except {
		return nil
	}
	_, err := s.strategies.FindByName(ctx, name)
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return rbac.ErrBadRequest(msgStrategyNameTaken)
}

// userTargets 组装用户形态目标行（name = displayName || username；
// is_protected 走授权服务保护账号判定）。
func (s *Service) userTargets(ctx context.Context, rows []entity.User) ([]dto.UserTargetView, error) {
	guids := make([]string, 0, len(rows))
	for i := range rows {
		guids = append(guids, rows[i].Guid)
	}
	protected, err := s.authz.GetEffectiveProtectionMap(ctx, guids)
	if err != nil {
		return nil, err
	}
	data := make([]dto.UserTargetView, 0, len(rows))
	for i := range rows {
		u := &rows[i]
		name := u.DisplayName
		if name == "" {
			name = u.Username
		}
		data = append(data, dto.UserTargetView{Guid: u.Guid, Name: name, IsProtected: protected[u.Guid]})
	}
	return data, nil
}

// viewOf 实体 → 视图（config_options 解析防御，恒非 nil；
// 解析走单源 jsonutil（M3 批复 #1，共享知识 21），与 heartbeat 同语义）。
func viewOf(st entity.Strategy) dto.StrategyView {
	return dto.StrategyView{
		Guid:          st.Guid,
		Name:          st.Name,
		Note:          st.Note,
		ConfigOptions: jsonutil.ParseConfigOptions(st.ConfigOptions),
		CreatedAt:     st.CreatedAt,
		UpdatedAt:     st.UpdatedAt,
	}
}

// marshalOptions config_options 请求值 → DB JSON 串（nil → 空串；
// 空对象 → "{}"；Marshal 失败不可达——值已由 map[string]string 约束）。
func marshalOptions(opts *map[string]string) string {
	if opts == nil {
		return ""
	}
	raw, err := json.Marshal(*opts)
	if err != nil {
		return ""
	}
	return string(raw)
}

// noteOr note 指针兜底（nil → 空串）。
func noteOr(note *string) string {
	if note == nil {
		return ""
	}
	return *note
}

// split 逐目标核对存在性：存在者入 success（保持请求顺序），
// 缺失者记入 errors（reason 固定文案）。
func split(targets []string, found map[string]struct{}, reason string) dto.AssignResult {
	res := dto.AssignResult{Success: []string{}, Errors: []dto.AssignError{}}
	for _, t := range targets {
		if _, ok := found[t]; ok {
			res.Success = append(res.Success, t)
			continue
		}
		res.Errors = append(res.Errors, dto.AssignError{TargetGuid: t, Reason: reason})
	}
	return res
}

// guidSetOf guid 主键实体集合 → 存在性集合。
func guidSetOf[E any](rows []E, key func(int) string) map[string]struct{} {
	set := make(map[string]struct{}, len(rows))
	for i := range rows {
		set[key(i)] = struct{}{}
	}
	return set
}

// uuidSetOf 设备集合 → uuid 存在性集合。
func uuidSetOf(rows []entity.Peer) map[string]struct{} {
	set := make(map[string]struct{}, len(rows))
	for i := range rows {
		set[rows[i].UUID] = struct{}{}
	}
	return set
}

// guidMapOf guid 主键实体集合 → guid → 实体映射。
func guidMapOf[E any](rows []E, key func(int) string) map[string]E {
	m := make(map[string]E, len(rows))
	for i := range rows {
		m[key(i)] = rows[i]
	}
	return m
}

// guidSet rbac.PermissionScope → 仓储 GuidSet（Global 语义等价透传）。
func guidSet(scope rbac.PermissionScope) repository.GuidSet {
	if scope.Global {
		return repository.GuidSet{Global: true}
	}
	guids := make([]string, 0, len(scope.DeviceGroupGuids))
	for g := range scope.DeviceGroupGuids {
		guids = append(guids, g)
	}
	return repository.GuidSet{Guids: guids}
}

// pageOffset 1 起页码 → SQL offset。
func pageOffset(current, pageSize int) int {
	if pageSize <= 0 || current <= 1 {
		return 0
	}
	return (current - 1) * pageSize
}

// dedup 去重（保持首次出现顺序；target_guids 去重契约）。
func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
