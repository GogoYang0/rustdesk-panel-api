// Package devicegroup 本文件：设备组域服务（设计 §3.1 DeviceGroupService）：
// accessible（Auth+状态复核，RBAC scope ∪ 显式授权双源）、列表/CRUD
// （AdminGuard 文案由路由中间件承担）、strategy-targets（Perm
// (strategies.assign) scope 过滤）、批量加入/移出设备（body=peer.id[]）。
package devicegroup

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// 业务文案（共享知识 1 固定文案逐字节）。注意重名冲突码差异：
// 设备组/策略为 400，角色/用户组为 409。
const (
	msgGroupNameExists   = "Device group name already exists"
	msgGroupNotFound     = "Device group does not exist"
	msgGroupReferenced   = "Device group is referenced by role assignments"
	msgDeviceIDsRequired = "Device ids are required"
)

// GroupService 设备组域服务。
type GroupService struct {
	authz  *rbac.AuthorizationService
	groups *repository.DeviceGroupRepo
	peers  *repository.PeerRepo
	now    func() time.Time // 注入时钟（单测可控）
}

// NewGroupService 构建服务。
func NewGroupService(
	authz *rbac.AuthorizationService,
	groups *repository.DeviceGroupRepo,
	peers *repository.PeerRepo,
) *GroupService {
	return &GroupService{authz: authz, groups: groups, peers: peers, now: time.Now}
}

// ==================== 查询 ====================

// Accessible GET /api/device-group/accessible（Auth+状态复核；无权限码）：
// 管理员全量；非管理员 = devices.view RBAC scope ∪ device_group_user_
// permissions 显式授权组（scope 为空时自然回退显式授权源）。name LIKE。
func (s *GroupService) Accessible(ctx context.Context, actorGuid, name string) (dto.PageResult[dto.AccessibleGroupView], error) {
	user, err := s.authz.GetCurrentUser(ctx, actorGuid)
	if err != nil {
		return dto.PageResult[dto.AccessibleGroupView]{}, err
	}
	scope := rbac.PermissionScope{DeviceGroupGuids: map[string]struct{}{}}
	if user.IsAdmin {
		scope.Global = true
	} else {
		// ComputeScopeFor 不做空 scope 403：accessible 无权限码语义，
		// 空时由 ListAccessible 的 EXISTS 分支回退 dgup 显式授权源。
		scope, err = s.authz.ComputeScopeFor(ctx, user.Guid, rbac.CodeDevicesView)
		if err != nil {
			return dto.PageResult[dto.AccessibleGroupView]{}, err
		}
	}
	rows, total, err := s.groups.ListAccessible(ctx, actorGuid, guidSet(scope), name, repository.Query{OrderBy: "name ASC"})
	if err != nil {
		return dto.PageResult[dto.AccessibleGroupView]{}, fmt.Errorf("devicegroup: list accessible: %w", err)
	}
	data := make([]dto.AccessibleGroupView, 0, len(rows))
	for i := range rows {
		data = append(data, dto.AccessibleGroupView{Guid: rows[i].Guid, Name: rows[i].Name, Note: rows[i].Note})
	}
	return dto.PageResult[dto.AccessibleGroupView]{Data: data, Total: total}, nil
}

// List GET /api/device-groups（AdminGuard 由路由承担）：name LIKE、
// name ASC；device_count 批量计数防行级 N+1。
func (s *GroupService) List(ctx context.Context, q dto.DeviceGroupListQuery) (dto.PageResult[dto.DeviceGroupView], error) {
	rows, total, err := s.groups.List(ctx, repository.Query{
		Where:   nameLike(q.Name),
		OrderBy: "name ASC",
		Limit:   q.PageSize,
		Offset:  pageOffset(q.Current, q.PageSize),
	})
	if err != nil {
		return dto.PageResult[dto.DeviceGroupView]{}, fmt.Errorf("devicegroup: list: %w", err)
	}
	return dto.PageResult[dto.DeviceGroupView]{Data: s.views(ctx, rows), Total: total}, nil
}

// StrategyTargets GET /api/device-groups/strategy-targets
// （Perm(strategies.assign) 路由已挡，scope 与中间件同语义复取）：
// global 全量 / scoped 仅授权组；guid ASC（openapi 契约）。
func (s *GroupService) StrategyTargets(ctx context.Context, actorGuid string, q dto.PaginationQuery) (dto.PageResult[dto.DeviceGroupTargetView], error) {
	scope, err := s.authz.GetPermissionScope(ctx, actorGuid, rbac.CodeStrategiesAssign)
	if err != nil {
		return dto.PageResult[dto.DeviceGroupTargetView]{}, err
	}
	gs := guidSet(scope)
	query := repository.Query{OrderBy: "guid ASC", Limit: q.PageSize, Offset: pageOffset(q.Current, q.PageSize)}
	if !gs.Global {
		if len(gs.Guids) == 0 {
			return dto.PageResult[dto.DeviceGroupTargetView]{Data: []dto.DeviceGroupTargetView{}, Total: 0}, nil
		}
		query.Where = []repository.Clause{{Field: "guid", Op: repository.OpIn, Value: gs.Guids}}
	}
	rows, total, err := s.groups.List(ctx, query)
	if err != nil {
		return dto.PageResult[dto.DeviceGroupTargetView]{}, fmt.Errorf("devicegroup: strategy targets: %w", err)
	}
	data := make([]dto.DeviceGroupTargetView, 0, len(rows))
	for i := range rows {
		data = append(data, dto.DeviceGroupTargetView{Guid: rows[i].Guid, Name: rows[i].Name})
	}
	return dto.PageResult[dto.DeviceGroupTargetView]{Data: data, Total: total}, nil
}

// ==================== CRUD（AdminGuard） ====================

// Create POST /api/device-groups：重名 400（角色/用户组才是 409）。
func (s *GroupService) Create(ctx context.Context, req dto.DeviceGroupUpsertRequest) (dto.DeviceGroupView, error) {
	if err := s.assertNameFree(ctx, req.Name, ""); err != nil {
		return dto.DeviceGroupView{}, err
	}
	note := ""
	if req.Note != nil {
		note = *req.Note
	}
	now := s.now()
	g := &entity.DeviceGroup{Guid: uuid.NewString(), Name: req.Name, Note: note, CreatedAt: now, UpdatedAt: now}
	if err := s.groups.Create(ctx, g); err != nil {
		return dto.DeviceGroupView{}, fmt.Errorf("devicegroup: create: %w", err)
	}
	return s.view(ctx, *g), nil
}

// Update PATCH /api/device-groups/{guid}：404 + 重名 400；note 三态
// （nil=保持原值，提供即覆盖）。Save 全量保存（实体已整行加载）。
func (s *GroupService) Update(ctx context.Context, guid string, req dto.DeviceGroupUpsertRequest) (dto.DeviceGroupView, error) {
	g, err := s.groups.FindByID(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.DeviceGroupView{}, rbac.ErrNotFoundErr(msgGroupNotFound)
		}
		return dto.DeviceGroupView{}, err
	}
	if err := s.assertNameFree(ctx, req.Name, g.Name); err != nil {
		return dto.DeviceGroupView{}, err
	}
	g.Name = req.Name
	if req.Note != nil {
		g.Note = *req.Note
	}
	if err := s.groups.Update(ctx, g); err != nil {
		return dto.DeviceGroupView{}, fmt.Errorf("devicegroup: update: %w", err)
	}
	return s.view(ctx, *g), nil
}

// Delete DELETE /api/device-groups/{guid}：404；被角色授权引用 → 400
// （RESTRICT 语义应用层计数检查）；事务置空组内设备归属（方言无关）。
func (s *GroupService) Delete(ctx context.Context, guid string) error {
	if _, err := s.groups.FindByID(ctx, guid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return rbac.ErrNotFoundErr(msgGroupNotFound)
		}
		return err
	}
	refs, err := s.groups.CountRoleRefs(ctx, guid)
	if err != nil {
		return fmt.Errorf("devicegroup: count role refs: %w", err)
	}
	if refs > 0 {
		return rbac.ErrBadRequest(msgGroupReferenced)
	}
	return s.groups.DeleteWithDetachPeers(ctx, guid)
}

// ==================== 批量加入 / 移出设备（body=peer.id[]） ====================

// AddDevices POST /api/device-groups/{guid}：按 peers.id 匹配，命中的
// 设备全部移入本组（已在本组亦计）；added_count = 命中数（不存在的
// ID 不计）。
func (s *GroupService) AddDevices(ctx context.Context, guid string, ids []string) (dto.AddDevicesResult, error) {
	if len(ids) == 0 {
		return dto.AddDevicesResult{}, rbac.ErrBadRequest(msgDeviceIDsRequired)
	}
	if _, err := s.groups.FindByID(ctx, guid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.AddDevicesResult{}, rbac.ErrNotFoundErr(msgGroupNotFound)
		}
		return dto.AddDevicesResult{}, err
	}
	rows, err := s.peers.FindByIDs(ctx, dedup(ids))
	if err != nil {
		return dto.AddDevicesResult{}, fmt.Errorf("devicegroup: find peers by id: %w", err)
	}
	uuids := make([]string, 0, len(rows))
	for i := range rows {
		uuids = append(uuids, rows[i].UUID)
	}
	if err := s.peers.UpdateColumnsByUUIDs(ctx, uuids, map[string]any{"deviceGroupGuid": guid}); err != nil {
		return dto.AddDevicesResult{}, fmt.Errorf("devicegroup: add devices: %w", err)
	}
	return dto.AddDevicesResult{AddedCount: int64(len(uuids))}, nil
}

// RemoveDevices DELETE /api/device-groups/{guid}/devices：仅统计当前
// 属于本组的设备；移出置 NULL，removed_count = 实际移出数。
func (s *GroupService) RemoveDevices(ctx context.Context, guid string, ids []string) (dto.RemoveDevicesResult, error) {
	if len(ids) == 0 {
		return dto.RemoveDevicesResult{}, rbac.ErrBadRequest(msgDeviceIDsRequired)
	}
	if _, err := s.groups.FindByID(ctx, guid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.RemoveDevicesResult{}, rbac.ErrNotFoundErr(msgGroupNotFound)
		}
		return dto.RemoveDevicesResult{}, err
	}
	rows, err := s.peers.FindByIDs(ctx, dedup(ids))
	if err != nil {
		return dto.RemoveDevicesResult{}, fmt.Errorf("devicegroup: find peers by id: %w", err)
	}
	uuids := make([]string, 0, len(rows))
	for i := range rows {
		if p := rows[i]; p.DeviceGroupGuid != nil && *p.DeviceGroupGuid == guid {
			uuids = append(uuids, p.UUID)
		}
	}
	if err := s.peers.UpdateColumnsByUUIDs(ctx, uuids, map[string]any{"deviceGroupGuid": nil}); err != nil {
		return dto.RemoveDevicesResult{}, fmt.Errorf("devicegroup: remove devices: %w", err)
	}
	return dto.RemoveDevicesResult{RemovedCount: int64(len(uuids))}, nil
}

// ==================== 内部辅助 ====================

// assertNameFree 重名校验（create 全查 / update 排除自身当前名）。
func (s *GroupService) assertNameFree(ctx context.Context, name, except string) error {
	if name == except {
		return nil
	}
	_, err := s.groups.FindByName(ctx, name)
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return rbac.ErrBadRequest(msgGroupNameExists)
}

// views 批量组装 DeviceGroupView（device_count 一次 GROUP BY）。
func (s *GroupService) views(ctx context.Context, rows []entity.DeviceGroup) []dto.DeviceGroupView {
	guids := make([]string, 0, len(rows))
	for i := range rows {
		guids = append(guids, rows[i].Guid)
	}
	counts, err := s.peers.CountPeersByGroups(ctx, guids)
	if err != nil {
		counts = map[string]int64{}
	}
	out := make([]dto.DeviceGroupView, 0, len(rows))
	for i := range rows {
		g := &rows[i]
		out = append(out, dto.DeviceGroupView{
			Guid:         g.Guid,
			Name:         g.Name,
			Note:         g.Note,
			StrategyGuid: g.StrategyGuid,
			DeviceCount:  counts[g.Guid],
			CreatedAt:    g.CreatedAt,
			UpdatedAt:    g.UpdatedAt,
		})
	}
	return out
}

// view 单行组装（Create/Update 响应）。
func (s *GroupService) view(ctx context.Context, g entity.DeviceGroup) dto.DeviceGroupView {
	return s.views(ctx, []entity.DeviceGroup{g})[0]
}

// nameLike name LIKE 条件（空名不过滤）。
func nameLike(name string) []repository.Clause {
	if name == "" {
		return nil
	}
	return []repository.Clause{{Field: "name", Op: repository.OpLike, Value: "%" + name + "%"}}
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

// dedup 去重（保持首次出现顺序）。
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
