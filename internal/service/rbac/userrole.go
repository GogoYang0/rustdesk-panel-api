// Package rbac（service 层）本文件：用户角色指派服务（设计 §3.1
// UserRoleService）：getUserRoles / eligibility / replaceUserRoles。
//
// ReplaceUserRoles 防护链（设计 §T05 验收 + openapi PUT 描述）：
// 自改 403 → 目标 404 → 保护账号复核（AssertUserMutation）→
// 超管目标仅保护角色 → 角色存在性 404 → scope 形态校验（device_group
// 仅 device 档码 / 须带组 / global 不得带组）→ 非超管组范围包含校验。
// 替换为事务整删整插 + 事务内 allowed 审计（共享知识 13）。
package rbac

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	rbaccore "github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// 用户角色域文案（锁定文案逐字节；scope 形态文案为未锁定项，
// 契约测试同源锁定）。
const (
	msgUserNotFound      = "User does not exist"
	msgGroupNotFound     = "Device group does not exist"
	msgRoleDupAssignment = "Duplicate role assignment"
	msgGroupScopeCodes   = "Device group scope can only contain device-scoped permissions"
	msgGroupScopeNeeds   = "Device group scope requires at least one device group"
	msgGlobalScopeNoGups = "Global scope must not contain device groups"

	auditTargetUser    = "user"
	auditActionAssign  = "roles.assign"
	reasonEligible     = "eligible"
	reasonSelfTarget   = "self_target"
	reasonTargetProt   = "target_protected"
	reasonProtectedRol = "protected_role"
	reasonSuperTarget  = "super_admin_target"
)

// UserRoleService 用户角色指派服务。
type UserRoleService struct {
	authz       *rbaccore.AuthorizationService
	db          *gorm.DB
	roles       *repository.RoleRepo
	rolePerms   *repository.RolePermissionRepo
	assignments *repository.AssignmentRepo
	asgGroups   *repository.AssignmentGroupRepo
	users       *repository.UserRepo
	groups      *repository.DeviceGroupRepo
	audits      *repository.ConsoleAuditRepo
	now         func() time.Time
}

// NewUserRoleService 构建服务。
func NewUserRoleService(
	authz *rbaccore.AuthorizationService,
	db *gorm.DB,
	roles *repository.RoleRepo,
	rolePerms *repository.RolePermissionRepo,
	assignments *repository.AssignmentRepo,
	asgGroups *repository.AssignmentGroupRepo,
	users *repository.UserRepo,
	groups *repository.DeviceGroupRepo,
	audits *repository.ConsoleAuditRepo,
) *UserRoleService {
	return &UserRoleService{
		authz: authz, db: db, roles: roles, rolePerms: rolePerms,
		assignments: assignments, asgGroups: asgGroups, users: users,
		groups: groups, audits: audits, now: time.Now,
	}
}

// GetUserRoles GET /api/users/{guid}/roles：assignment 清单
// （createdAt ASC）+ 聚合 scope（任一 global → global；否则任一
// device_group → device_group；无指派 → none）。
func (s *UserRoleService) GetUserRoles(ctx context.Context, userGuid string) (dto.UserRolesResult, error) {
	if err := s.requireTargetUser(ctx, userGuid); err != nil {
		return dto.UserRolesResult{}, err
	}
	return s.result(ctx, userGuid)
}

// Eligibility GET /api/users/{guid}/roles/eligibility：全部角色逐行
// 给出可指派判定与 reason_code（决策矩阵，验收锁定全分支）。
func (s *UserRoleService) Eligibility(ctx context.Context, actorGuid, userGuid string) (dto.EligibilityResult, error) {
	if err := s.requireTargetUser(ctx, userGuid); err != nil {
		return dto.EligibilityResult{}, err
	}
	target, err := s.targetUser(ctx, userGuid)
	if err != nil {
		return dto.EligibilityResult{}, err
	}
	actor, err := s.authz.GetCurrentUser(ctx, actorGuid)
	if err != nil {
		return dto.EligibilityResult{}, err
	}
	targetProtected, err := s.authz.GetEffectiveProtectionMap(ctx, []string{userGuid})
	if err != nil {
		return dto.EligibilityResult{}, fmt.Errorf("userrole: protection: %w", err)
	}
	roles, _, err := s.roles.ListPaged(ctx, "", "", repository.Query{OrderBy: "name ASC, guid ASC"})
	if err != nil {
		return dto.EligibilityResult{}, fmt.Errorf("userrole: roles: %w", err)
	}
	selfTarget := actorGuid == userGuid
	rows := make([]dto.EligibilityRow, 0, len(roles))
	for i := range roles {
		r := roles[i]
		eligible, reason := true, reasonEligible
		switch {
		case selfTarget:
			eligible, reason = false, reasonSelfTarget
		case targetProtected[userGuid] && !actor.IsAdmin:
			eligible, reason = false, reasonTargetProt
		case r.ProtectedAccount && !actor.IsAdmin:
			eligible, reason = false, reasonProtectedRol
		case target.IsAdmin && !r.ProtectedAccount:
			// 目标为超管且角色非保护：只有超管操作者能到这里
			// （非超管在 target_protected 分支已拒绝）。
			eligible, reason = false, reasonSuperTarget
		}
		rows = append(rows, dto.EligibilityRow{
			RoleGuid:         r.Guid,
			RoleName:         r.Name,
			ProtectedAccount: r.ProtectedAccount,
			Eligible:         eligible,
			ReasonCode:       reason,
		})
	}
	return dto.EligibilityResult{Data: rows}, nil
}

// ReplaceUserRoles PUT /api/users/{guid}/roles：全量替换 + 防护链 +
// 事务内 allowed 审计；返回替换后的 {data, effective_scope}。
func (s *UserRoleService) ReplaceUserRoles(ctx context.Context, actorGuid, userGuid string, req dto.ReplaceRolesRequest) (dto.UserRolesResult, error) {
	// 1. 自改拒绝（自改即目标必然存在，最先判定）。
	if actorGuid == userGuid {
		return dto.UserRolesResult{}, rbaccore.ErrForbidden(rbaccore.MsgSelfRoleChange)
	}
	// 2. 目标存在 404 + 保护账号复核 403（AssertUserMutation 一站式）。
	if err := s.authz.AssertUserMutation(ctx, actorGuid, userGuid, rbaccore.CodeRolesAssign); err != nil {
		return dto.UserRolesResult{}, err
	}
	target, err := s.targetUser(ctx, userGuid)
	if err != nil {
		return dto.UserRolesResult{}, err
	}
	actor, err := s.authz.GetCurrentUser(ctx, actorGuid)
	if err != nil {
		return dto.UserRolesResult{}, err
	}

	// 3. 指派载荷规范化与角色存在性。
	inputs, err := s.normalize(ctx, req)
	if err != nil {
		return dto.UserRolesResult{}, err
	}

	// 4. 超管目标仅可派保护角色（到达此处时 actor 必为超管，
	// 否则步骤 2 已拒绝）。
	if target.IsAdmin {
		roleRows, err := s.roles.FindByGuids(ctx, roleGuidsOf(inputs))
		if err != nil {
			return dto.UserRolesResult{}, fmt.Errorf("userrole: roles: %w", err)
		}
		protectedByGuid := make(map[string]bool, len(roleRows))
		for _, r := range roleRows {
			protectedByGuid[r.Guid] = r.ProtectedAccount
		}
		for _, item := range inputs {
			if !protectedByGuid[item.Assignment.RoleGuid] {
				return dto.UserRolesResult{}, rbaccore.ErrForbidden(rbaccore.MsgSuperAdminRegularRole)
			}
		}
	}

	// 5. scope 包含校验：非超管操作者的组授权范围须覆盖全部
	// device_group 指派的组；非超管不得派 global 指派（提权）。
	if !actor.IsAdmin {
		scope, err := s.authz.GetPermissionScope(ctx, actorGuid, rbaccore.CodeRolesAssign)
		if err != nil {
			return dto.UserRolesResult{}, err
		}
		for _, item := range inputs {
			if item.Assignment.ScopeType == entity.ScopeTypeGlobal {
				return dto.UserRolesResult{}, rbaccore.ErrForbidden(rbaccore.MsgAccessDenied)
			}
			for _, g := range item.DeviceGroupGuids {
				if !scope.InDeviceGroup(g) {
					return dto.UserRolesResult{}, rbaccore.ErrForbidden(rbaccore.MsgTargetGroupOutside)
				}
			}
		}
	}

	// 6. 事务整删整插 + allowed 审计（before/after 快照）。
	before, err := s.result(ctx, userGuid)
	if err != nil {
		return dto.UserRolesResult{}, err
	}
	now := s.now()
	items := make([]repository.AssignmentWithGroups, 0, len(inputs))
	for _, item := range inputs {
		row := item.Assignment
		row.Guid = uuid.NewString()
		row.UserGuid = userGuid
		row.CreatedAt = now
		row.UpdatedAt = now
		items = append(items, repository.AssignmentWithGroups{Assignment: row, DeviceGroupGuids: item.DeviceGroupGuids})
	}
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.assignments.ReplaceAllTx(tx, userGuid, items); err != nil {
			return err
		}
		return s.audits.CreateAuditTx(tx, rbaccore.AuditRecord{
			ActorUserGuid: actorGuid,
			TargetType:    auditTargetUser,
			TargetGuid:    userGuid,
			Action:        auditActionAssign,
			Result:        rbaccore.AuditResultAllowed,
			BeforeState:   rbaccore.RedactJSON(assignmentsPayload(before.Data)),
			AfterState:    rbaccore.RedactJSON(replacePayload(inputs)),
			RequestID:     rbaccore.RequestIDFrom(ctx),
		})
	})
	if err != nil {
		return dto.UserRolesResult{}, fmt.Errorf("userrole: replace: %w", err)
	}
	return s.result(ctx, userGuid)
}

// ==================== 内部辅助 ====================

// normalize 请求载荷规范化：去重、角色存在性 404、scope 形态校验。
// 返回按请求顺序排列的仓储载荷。
func (s *UserRoleService) normalize(ctx context.Context, req dto.ReplaceRolesRequest) ([]repository.AssignmentWithGroups, error) {
	seen := make(map[string]struct{}, len(req.Assignments))
	items := make([]repository.AssignmentWithGroups, 0, len(req.Assignments))
	for _, in := range req.Assignments {
		if _, dup := seen[in.RoleGuid]; dup {
			return nil, rbaccore.ErrBadRequest(msgRoleDupAssignment)
		}
		seen[in.RoleGuid] = struct{}{}
		if _, err := s.roles.FindByID(ctx, in.RoleGuid); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return nil, rbaccore.ErrNotFoundErr(msgRoleNotFound)
			}
			return nil, err
		}
		guids := dedupCodes(in.DeviceGroupGuids)
		switch in.ScopeType {
		case entity.ScopeTypeGlobal:
			if len(guids) > 0 {
				return nil, rbaccore.ErrBadRequest(msgGlobalScopeNoGups)
			}
		case entity.ScopeTypeDeviceGroup:
			if len(guids) == 0 {
				return nil, rbaccore.ErrBadRequest(msgGroupScopeNeeds)
			}
			// device_group 档仅限 device_group scope 档权限码
			// （devices.* + strategies.assign 六码，共享知识 2）。
			codesByRole, err := s.rolePerms.CodesByRoles(ctx, []string{in.RoleGuid})
			if err != nil {
				return nil, fmt.Errorf("userrole: codes: %w", err)
			}
			for _, c := range codesByRole[in.RoleGuid] {
				if !rbaccore.IsDeviceGroupScoped(c) {
					return nil, rbaccore.ErrBadRequest(msgGroupScopeCodes)
				}
			}
			// 组存在性（404）。
			found, err := s.groups.FindByGuids(ctx, guids)
			if err != nil {
				return nil, fmt.Errorf("userrole: groups: %w", err)
			}
			if len(found) != len(guids) {
				return nil, rbaccore.ErrNotFoundErr(msgGroupNotFound)
			}
		}
		items = append(items, repository.AssignmentWithGroups{
			Assignment: entity.UserRoleAssignment{
				RoleGuid:  in.RoleGuid,
				ScopeType: in.ScopeType,
			},
			DeviceGroupGuids: guids,
		})
	}
	return items, nil
}

// requireTargetUser 目标用户存在性（404 "User does not exist"）。
func (s *UserRoleService) requireTargetUser(ctx context.Context, userGuid string) error {
	_, err := s.targetUser(ctx, userGuid)
	return err
}

// targetUser 按公共列加载目标用户；不存在映射 404 固定文案。
func (s *UserRoleService) targetUser(ctx context.Context, userGuid string) (*entity.User, error) {
	u, err := s.users.FindByGuid(ctx, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, rbaccore.ErrNotFoundErr(msgUserNotFound)
		}
		return nil, fmt.Errorf("userrole: target user: %w", err)
	}
	return u, nil
}

// result 组装 {data, effective_scope}（assignment 行 + 角色名 + 组关联）。
func (s *UserRoleService) result(ctx context.Context, userGuid string) (dto.UserRolesResult, error) {
	asgs, err := s.assignments.ListByUser(ctx, userGuid)
	if err != nil {
		return dto.UserRolesResult{}, fmt.Errorf("userrole: assignments: %w", err)
	}
	data := make([]dto.AssignmentDto, 0, len(asgs))
	if len(asgs) > 0 {
		roleGuids := make([]string, 0, len(asgs))
		asgGuids := make([]string, 0, len(asgs))
		for _, a := range asgs {
			roleGuids = append(roleGuids, a.RoleGuid)
			asgGuids = append(asgGuids, a.Guid)
		}
		namesByGuid := map[string]string{}
		roleRows, err := s.roles.FindByGuids(ctx, roleGuids)
		if err != nil {
			return dto.UserRolesResult{}, fmt.Errorf("userrole: role rows: %w", err)
		}
		for _, r := range roleRows {
			namesByGuid[r.Guid] = r.Name
		}
		groupsByAsg, err := s.asgGroups.GroupsByAssignments(ctx, asgGuids)
		if err != nil {
			return dto.UserRolesResult{}, fmt.Errorf("userrole: groups: %w", err)
		}
		for _, a := range asgs {
			data = append(data, dto.AssignmentDto{
				RoleGuid:         a.RoleGuid,
				RoleName:         namesByGuid[a.RoleGuid],
				ScopeType:        a.ScopeType,
				DeviceGroupGuids: nonNil(groupsByAsg[a.Guid]),
			})
		}
	}
	return dto.UserRolesResult{Data: data, EffectiveScope: string(aggregateScope(asgs))}, nil
}

// aggregateScope 指派集 → 聚合 scope（任一 global 即 global）。
func aggregateScope(asgs []entity.UserRoleAssignment) rbaccore.EffectiveScope {
	anyGroup := false
	for _, a := range asgs {
		switch a.ScopeType {
		case entity.ScopeTypeGlobal:
			return rbaccore.EffectiveScopeGlobal
		case entity.ScopeTypeDeviceGroup:
			anyGroup = true
		}
	}
	if anyGroup {
		return rbaccore.EffectiveScopeDeviceGroup
	}
	return rbaccore.EffectiveScopeNone
}

// replacePayload 替换请求的审计载荷（input 形态）。
func replacePayload(items []repository.AssignmentWithGroups) map[string]any {
	rows := make([]map[string]any, 0, len(items))
	for _, item := range items {
		rows = append(rows, map[string]any{
			"role_guid":          item.Assignment.RoleGuid,
			"scope_type":         item.Assignment.ScopeType,
			"device_group_guids": nonNil(item.DeviceGroupGuids),
		})
	}
	return map[string]any{"assignments": rows}
}

// assignmentsPayload 现有指派集的审计载荷（before 形态）。
func assignmentsPayload(rows []dto.AssignmentDto) map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, map[string]any{
			"role_guid":          a.RoleGuid,
			"scope_type":         a.ScopeType,
			"device_group_guids": nonNil(a.DeviceGroupGuids),
		})
	}
	return map[string]any{"assignments": out}
}

// roleGuidsOf 提取去重角色 guid 列表。
func roleGuidsOf(items []repository.AssignmentWithGroups) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		g := item.Assignment.RoleGuid
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}
