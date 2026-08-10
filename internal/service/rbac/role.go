// Package rbac（service 层）本文件：角色域服务（设计 §3.1 RoleService）：
// 列表/详情（roles.view）、创建/更新/删除（super administrator 路线，
// 403 文案 "Super administrator permission required" 由路由中间件承担）、
// 保护影响面。写路径全部事务内显式审计（allowed，before/after 快照，
// 共享知识 13）；权限码校验（system_only 拒绝 + requires 依赖链）。
//
// 注意：本包与 internal/rbac 包同名，后者以 rbaccore 别名引用；
// StatusError/文案常量经 rbaccore 前缀访问。
package rbac

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	rbaccore "github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// 业务文案（共享知识 1 固定文案逐字节；msgConfirmUnprotect 与
// msgRoleInvalidUUID 为未锁定文案，契约测试同源锁定）。
const (
	msgRoleNotFound     = "Role not found"
	msgRoleNameExists   = "Role name already exists" // 409
	msgConfirmUnprotect = "Confirmation required to remove protected account"
	msgPermissionDenied = "Permission code cannot be assigned: %s" // 400
	msgMissingDeps      = "Missing permission dependencies: %s"    // 400
	msgRoleInvalidUUID  = "Validation failed (uuid is expected)"   // 400

	stateNull         = "null"
	auditTargetRole   = "role"
	auditActionCreate = "roles.create"
	auditActionUpdate = "roles.update"
	auditActionDelete = "roles.delete"
)

// RoleService 角色域服务。
type RoleService struct {
	authz       *rbaccore.AuthorizationService
	db          *gorm.DB
	roles       *repository.RoleRepo
	rolePerms   *repository.RolePermissionRepo
	assignments *repository.AssignmentRepo
	asgGroups   *repository.AssignmentGroupRepo
	audits      *repository.ConsoleAuditRepo
	now         func() time.Time // 注入时钟（单测可控）
}

// NewRoleService 构建角色服务。
func NewRoleService(
	authz *rbaccore.AuthorizationService,
	db *gorm.DB,
	roles *repository.RoleRepo,
	rolePerms *repository.RolePermissionRepo,
	assignments *repository.AssignmentRepo,
	asgGroups *repository.AssignmentGroupRepo,
	audits *repository.ConsoleAuditRepo,
) *RoleService {
	return &RoleService{
		authz: authz, db: db, roles: roles, rolePerms: rolePerms,
		assignments: assignments, asgGroups: asgGroups, audits: audits,
		now: time.Now,
	}
}

// ==================== 查询（roles.view） ====================

// List GET /api/roles：name/note LIKE、name ASC + guid ASC 决胜排序。
// 角色为全局资源，无 scope 过滤（Perm(roles.view) 由路由承担）。
func (s *RoleService) List(ctx context.Context, q dto.RoleListQuery) (dto.RolePage, error) {
	rows, total, err := s.roles.ListPaged(ctx, q.Name, q.Note, repository.Query{
		OrderBy: "name ASC, guid ASC",
		Limit:   q.PageSize,
		Offset:  pageOffset(q.Current, q.PageSize),
	})
	if err != nil {
		return dto.RolePage{}, fmt.Errorf("role: list: %w", err)
	}
	data := make([]dto.RoleView, 0, len(rows))
	for i := range rows {
		data = append(data, roleView(rows[i]))
	}
	return dto.RolePage{Data: data, Total: total}, nil
}

// Get GET /api/roles/{guid}：guid 须 uuid v4（否则 400），含权限码
// 清单（目录顺序）。
func (s *RoleService) Get(ctx context.Context, guid string) (dto.RoleDetail, error) {
	if err := requireUUIDv4(guid); err != nil {
		return dto.RoleDetail{}, err
	}
	role, err := s.roles.FindByID(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.RoleDetail{}, rbaccore.ErrNotFoundErr(msgRoleNotFound)
		}
		return dto.RoleDetail{}, err
	}
	codes, err := s.rolePerms.CodesByRoles(ctx, []string{guid})
	if err != nil {
		return dto.RoleDetail{}, fmt.Errorf("role: codes: %w", err)
	}
	return dto.RoleDetail{
		Guid:             role.Guid,
		Name:             role.Name,
		Note:             role.Note,
		ProtectedAccount: role.ProtectedAccount,
		CreatedAt:        role.CreatedAt,
		UpdatedAt:        role.UpdatedAt,
		// 零权限角色 permissions 恒为 []（null 违反 openapi array 契约）。
		Permissions: nonNil(orderByCatalog(codes[guid])),
	}, nil
}

// ProtectionImpact GET /api/roles/{guid}/protection-impact：挂在该角色
// 上的用户数（不分页）。
func (s *RoleService) ProtectionImpact(ctx context.Context, guid string) (dto.ProtectionImpact, error) {
	if err := requireUUIDv4(guid); err != nil {
		return dto.ProtectionImpact{}, err
	}
	if _, err := s.roles.FindByID(ctx, guid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.ProtectionImpact{}, rbaccore.ErrNotFoundErr(msgRoleNotFound)
		}
		return dto.ProtectionImpact{}, err
	}
	n, err := s.roles.CountAssignments(ctx, guid)
	if err != nil {
		return dto.ProtectionImpact{}, fmt.Errorf("role: count assignments: %w", err)
	}
	return dto.ProtectionImpact{AffectedMemberCount: n}, nil
}

// ==================== 写路径（super administrator） ====================

// Create POST /api/roles：权限码校验 → 重名 409 → 事务（角色 + 权限码
// + allowed 审计 afterState 快照）。
func (s *RoleService) Create(ctx context.Context, actorGuid string, req dto.RoleCreateRequest) (dto.RoleView, error) {
	codes := dedupCodes(req.Permissions)
	if err := s.validatePermissionCodes(codes); err != nil {
		return dto.RoleView{}, err
	}
	if err := s.assertNameFree(ctx, req.Name, ""); err != nil {
		return dto.RoleView{}, err
	}
	now := s.now()
	role := &entity.Role{
		Guid:             uuid.NewString(),
		Name:             req.Name,
		Note:             req.Note,
		ProtectedAccount: req.ProtectedAccount,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.roles.CreateTx(tx, role); err != nil {
			return err
		}
		if err := s.rolePerms.ReplaceForRoleTx(tx, role.Guid, codes); err != nil {
			return err
		}
		return s.audits.CreateAuditTx(tx, rbaccore.AuditRecord{
			ActorUserGuid: actorGuid,
			TargetType:    auditTargetRole,
			TargetGuid:    role.Guid,
			Action:        auditActionCreate,
			Result:        rbaccore.AuditResultAllowed,
			BeforeState:   stateNull,
			AfterState:    rbaccore.RedactJSON(roleSnapshotOf(role, codes)),
			RequestID:     rbaccore.RequestIDFrom(ctx),
		})
	})
	if err != nil {
		return dto.RoleView{}, fmt.Errorf("role: create: %w", err)
	}
	return roleView(*role), nil
}

// Update PATCH /api/roles/{guid}：404 → 权限码校验 → 重名 409（排除
// 自身）→ 取消保护 confirm 门槛 → 事务（保存 + 权限码重建 + before/
// after 审计）。三态语义：nil 字段/nil permissions 保持原值。
func (s *RoleService) Update(ctx context.Context, actorGuid, guid string, req dto.RoleUpdateRequest) (dto.RoleView, error) {
	if err := requireUUIDv4(guid); err != nil {
		return dto.RoleView{}, err
	}
	role, err := s.roles.FindByID(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.RoleView{}, rbaccore.ErrNotFoundErr(msgRoleNotFound)
		}
		return dto.RoleView{}, err
	}
	oldCodes, err := s.rolePerms.CodesByRoles(ctx, []string{guid})
	if err != nil {
		return dto.RoleView{}, fmt.Errorf("role: old codes: %w", err)
	}
	before := append([]string(nil), oldCodes[guid]...)

	// 权限码：提供（含空数组）即全量替换；nil 保持原值。
	codes := before
	if req.Permissions != nil {
		codes = dedupCodes(req.Permissions)
		if err := s.validatePermissionCodes(codes); err != nil {
			return dto.RoleView{}, err
		}
	}
	// 名称：nil 保持原值；提供即覆盖（重名排除自身）。
	name := role.Name
	if req.Name != nil {
		if err := s.assertNameFree(ctx, *req.Name, role.Name); err != nil {
			return dto.RoleView{}, err
		}
		name = *req.Name
	}
	// note：nil 保持原值。
	if req.Note != nil {
		role.Note = *req.Note
	}
	// 取消保护（true→false）须显式 confirm。
	protect := role.ProtectedAccount
	if req.ProtectedAccount != nil {
		if protect && !*req.ProtectedAccount && !req.ConfirmProtectedAccountChange {
			return dto.RoleView{}, rbaccore.ErrBadRequest(msgConfirmUnprotect)
		}
		protect = *req.ProtectedAccount
	}

	beforeState := roleSnapshotOf(role, before)
	role.Name = name
	role.ProtectedAccount = protect
	role.UpdatedAt = s.now()
	afterState := roleSnapshotOf(role, codes)

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.roles.UpdateTx(tx, role); err != nil {
			return err
		}
		if req.Permissions != nil {
			if err := s.rolePerms.ReplaceForRoleTx(tx, role.Guid, codes); err != nil {
				return err
			}
		}
		return s.audits.CreateAuditTx(tx, rbaccore.AuditRecord{
			ActorUserGuid: actorGuid,
			TargetType:    auditTargetRole,
			TargetGuid:    role.Guid,
			Action:        auditActionUpdate,
			Result:        rbaccore.AuditResultAllowed,
			BeforeState:   rbaccore.RedactJSON(beforeState),
			AfterState:    rbaccore.RedactJSON(afterState),
			RequestID:     rbaccore.RequestIDFrom(ctx),
		})
	})
	if err != nil {
		return dto.RoleView{}, fmt.Errorf("role: update: %w", err)
	}
	return roleView(*role), nil
}

// Delete DELETE /api/roles/{guid}：404 → 事务（级联删权限码/指派/指派
// 组关联 + 角色行 + beforeState 全量快照审计）。
func (s *RoleService) Delete(ctx context.Context, actorGuid, guid string) error {
	if err := requireUUIDv4(guid); err != nil {
		return err
	}
	role, err := s.roles.FindByID(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return rbaccore.ErrNotFoundErr(msgRoleNotFound)
		}
		return err
	}
	before, err := s.deleteSnapshot(ctx, role)
	if err != nil {
		return err
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.roles.DeleteCascadeTx(tx, guid); err != nil {
			return err
		}
		return s.audits.CreateAuditTx(tx, rbaccore.AuditRecord{
			ActorUserGuid: actorGuid,
			TargetType:    auditTargetRole,
			TargetGuid:    guid,
			Action:        auditActionDelete,
			Result:        rbaccore.AuditResultAllowed,
			BeforeState:   rbaccore.RedactJSON(before),
			AfterState:    stateNull,
			RequestID:     rbaccore.RequestIDFrom(ctx),
		})
	})
	if err != nil {
		return fmt.Errorf("role: delete: %w", err)
	}
	return nil
}

// ==================== 内部辅助 ====================

// validatePermissionCodes 写路径权限码校验（共享知识 2）：
//   - 未知码或 system_only 码（IsAssignable=false）→ 400
//     "Permission code cannot be assigned: {code}"（按输入顺序首个违规）；
//   - requires 依赖链：任一依赖不在本次码集 → 400
//     "Missing permission dependencies: {dep, ...}"（按目录顺序去重列出）。
func (s *RoleService) validatePermissionCodes(codes []string) error {
	set := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		set[c] = struct{}{}
	}
	for _, c := range codes {
		if !rbaccore.IsAssignable(c) {
			return rbaccore.ErrBadRequest(fmt.Sprintf(msgPermissionDenied, c))
		}
	}
	missing := make([]string, 0)
	seen := make(map[string]struct{})
	for _, d := range rbaccore.Catalog() { // 目录顺序保证输出稳定
		if _, ok := set[d.Code]; !ok {
			continue
		}
		for _, dep := range d.Requires {
			if _, ok := set[dep]; ok {
				continue
			}
			if _, dup := seen[dep]; dup {
				continue
			}
			seen[dep] = struct{}{}
			missing = append(missing, dep)
		}
	}
	if len(missing) > 0 {
		return rbaccore.ErrBadRequest(fmt.Sprintf(msgMissingDeps, joinComma(missing)))
	}
	return nil
}

// assertNameFree 重名 409 判定（大小写不敏感）；exclude 为自身现名
// （改名保持原值时 FindByNameCI 命中自身不算冲突）。
func (s *RoleService) assertNameFree(ctx context.Context, name, exclude string) error {
	existing, err := s.roles.FindByNameCI(ctx, name)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil
		}
		return err
	}
	if exclude != "" && existing.Name == exclude {
		return nil
	}
	return rbaccore.ErrConflictMsg(msgRoleNameExists)
}

// deleteSnapshot 角色删除前全量快照：角色 + 权限码 + 全部指派（含
// 组关联）（验收锁定项：beforeState 含 assignments+groups）。
func (s *RoleService) deleteSnapshot(ctx context.Context, role *entity.Role) (roleDeleteSnapshot, error) {
	codesByRole, err := s.rolePerms.CodesByRoles(ctx, []string{role.Guid})
	if err != nil {
		return roleDeleteSnapshot{}, fmt.Errorf("role: snapshot codes: %w", err)
	}
	asgs, err := s.assignments.ListByRole(ctx, role.Guid)
	if err != nil {
		return roleDeleteSnapshot{}, fmt.Errorf("role: snapshot assignments: %w", err)
	}
	asgGuids := make([]string, 0, len(asgs))
	for _, a := range asgs {
		asgGuids = append(asgGuids, a.Guid)
	}
	groupsByAsg := map[string][]string{}
	if len(asgGuids) > 0 {
		groupsByAsg, err = s.asgGroups.GroupsByAssignments(ctx, asgGuids)
		if err != nil {
			return roleDeleteSnapshot{}, fmt.Errorf("role: snapshot groups: %w", err)
		}
	}
	out := roleDeleteSnapshot{
		Role:        roleSnapshotOf(role, codesByRole[role.Guid]),
		Assignments: make([]assignmentSnapshot, 0, len(asgs)),
	}
	for _, a := range asgs {
		out.Assignments = append(out.Assignments, assignmentSnapshot{
			UserGuid:         a.UserGuid,
			ScopeType:        a.ScopeType,
			DeviceGroupGuids: nonNil(groupsByAsg[a.Guid]),
		})
	}
	return out, nil
}

// roleSnapshot 角色 + 权限码快照（before/after 审计载荷；snake_case
// 与响应契约一致）。
type roleSnapshot struct {
	Guid             string   `json:"guid"`
	Name             string   `json:"name"`
	Note             string   `json:"note"`
	ProtectedAccount bool     `json:"protected_account"`
	Permissions      []string `json:"permissions"`
}

// roleSnapshotOf 构建角色快照（permissions 经非 nil 归一）。
func roleSnapshotOf(r *entity.Role, codes []string) roleSnapshot {
	return roleSnapshot{
		Guid:             r.Guid,
		Name:             r.Name,
		Note:             r.Note,
		ProtectedAccount: r.ProtectedAccount,
		Permissions:      nonNil(codes),
	}
}

// assignmentSnapshot 指派快照行。
type assignmentSnapshot struct {
	UserGuid         string   `json:"user_guid"`
	ScopeType        string   `json:"scope_type"`
	DeviceGroupGuids []string `json:"device_group_guids"`
}

// roleDeleteSnapshot 删除前全量快照（角色 + 权限码 + 指派 + 组关联）。
type roleDeleteSnapshot struct {
	Role        roleSnapshot         `json:"role"`
	Assignments []assignmentSnapshot `json:"assignments"`
}

// roleView 实体 → 行视图。
func roleView(r entity.Role) dto.RoleView {
	return dto.RoleView{
		Guid:             r.Guid,
		Name:             r.Name,
		Note:             r.Note,
		ProtectedAccount: r.ProtectedAccount,
		CreatedAt:        r.CreatedAt,
		UpdatedAt:        r.UpdatedAt,
	}
}

// orderByCatalog 权限码按目录定义顺序稳定输出（未知码排最后）。
func orderByCatalog(codes []string) []string {
	cat := rbaccore.Catalog()
	order := make(map[string]int, len(cat))
	for i, d := range cat {
		order[d.Code] = i
	}
	out := append([]string(nil), codes...)
	sort.Slice(out, func(i, j int) bool {
		return order[out[i]] < order[out[j]]
	})
	return out
}

// requireUUIDv4 路径参数 guid 的 uuid v4 校验（roles 域契约：非法 400）。
func requireUUIDv4(guid string) error {
	id, err := uuid.Parse(guid)
	if err != nil || id.Variant() != uuid.RFC4122 || id.Version() != 4 {
		return rbaccore.ErrBadRequest(msgRoleInvalidUUID)
	}
	return nil
}

// dedupCodes 权限码去重（保持首次出现顺序）。
func dedupCodes(in []string) []string {
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

// joinComma 逗号 + 空格连接（依赖缺失清单展示）。
func joinComma(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// nonNil 保证数组非 nil（快照/DTO 的 JSON 恒为数组）。
func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// pageOffset 分页偏移换算（current∈[1,∞)，pageSize<=0 视为不分页）。
func pageOffset(current, pageSize int) int {
	if pageSize <= 0 || current <= 1 {
		return 0
	}
	return (current - 1) * pageSize
}
