// Package dto RBAC 域请求/响应载体（设计 §2 dto/rbac.go）。
//
// 契约红线（共享知识 4）：角色行内 protected_account/created_at/updated_at
// 为 snake_case；assignment 行内 role_guid/role_name/scope_type/
// device_group_guids 为 snake_case；权限目录 system_only 布尔。
// 角色重名冲突为 409 "Role name already exists"（与设备组/策略 400 区分）。
package dto

import (
	"net/url"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// ==================== 权限目录 / 生效权限 ====================

// PermissionsResult GET /api/permissions 响应（{data:[...]} 无 total，
// 共享知识 5）。
type PermissionsResult struct {
	Data []rbac.PermissionDefinition `json:"data"`
}

// EffectivePermissions GET /api/permissions/me 载荷直接复用
// rbac.EffectivePermissions（permissions + scopes{global, device_group}），
// 无独立 DTO（形状在 rbac 包内即为契约）。

// ==================== 角色 ====================

// RoleCreateRequest POST /api/roles 请求体（super administrator）。
// name 必填；permissions 可缺省（=空码集角色）；protected_account 缺省 false。
type RoleCreateRequest struct {
	Name             string   `json:"name" validate:"required"`
	Note             string   `json:"note"`
	ProtectedAccount bool     `json:"protected_account"`
	Permissions      []string `json:"permissions"`
}

// RoleUpdateRequest PATCH /api/roles/{guid} 请求体：全部字段三态——
// 指针 nil/数组 nil = 保持原值；permissions 提供（含空数组）即全量替换。
// 取消保护（true→false）必须同时 confirm_protected_account_change=true。
type RoleUpdateRequest struct {
	Name                          *string  `json:"name"`
	Note                          *string  `json:"note"`
	ProtectedAccount              *bool    `json:"protected_account"`
	Permissions                   []string `json:"permissions"`
	ConfirmProtectedAccountChange bool     `json:"confirm_protected_account_change"`
}

// RoleView 角色行视图（openapi RoleView，6 必需键）。
type RoleView struct {
	Guid             string    `json:"guid"`
	Name             string    `json:"name"`
	Note             string    `json:"note"`
	ProtectedAccount bool      `json:"protected_account"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// RoleDetail 角色详情 = RoleView + permissions 清单（目录顺序）。
type RoleDetail struct {
	Guid             string    `json:"guid"`
	Name             string    `json:"name"`
	Note             string    `json:"note"`
	ProtectedAccount bool      `json:"protected_account"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
	Permissions      []string  `json:"permissions"`
}

// RolePage GET /api/roles 响应。
type RolePage struct {
	Data  []RoleView `json:"data"`
	Total int64      `json:"total"`
}

// ProtectionImpact GET /api/roles/{guid}/protection-impact 响应：
// 挂在该角色上的用户数（不分页，共享知识 5）。
type ProtectionImpact struct {
	AffectedMemberCount int64 `json:"affected_member_count"`
}

// RoleListQuery GET /api/roles 查询参数：name/note LIKE + 分页。
type RoleListQuery struct {
	PaginationQuery
	Name string
	Note string
}

// ParseRoleListQuery 从 query 值构建。
func ParseRoleListQuery(q url.Values) RoleListQuery {
	return RoleListQuery{
		PaginationQuery: paginationQuery(q),
		Name:            q.Get("name"),
		Note:            q.Get("note"),
	}
}

// ==================== 用户角色指派 ====================

// AssignmentDto assignment 行（openapi AssignmentDto，4 必需键；
// device_group_guids 恒非 nil，global 档为空数组）。
type AssignmentDto struct {
	RoleGuid         string   `json:"role_guid"`
	RoleName         string   `json:"role_name"`
	ScopeType        string   `json:"scope_type"`
	DeviceGroupGuids []string `json:"device_group_guids"`
}

// UserRolesResult GET/PUT /api/users/{guid}/roles 响应（{data,
// effective_scope} 无 total）。effective_scope ∈ global|device_group|none。
type UserRolesResult struct {
	Data           []AssignmentDto `json:"data"`
	EffectiveScope string          `json:"effective_scope"`
}

// AssignmentInput ReplaceRolesRequest 的元素（role_guid/scope_type 必填；
// device_group_guids 仅 device_group 档非空）。
type AssignmentInput struct {
	RoleGuid         string   `json:"role_guid" validate:"required"`
	ScopeType        string   `json:"scope_type" validate:"required,oneof=global device_group"`
	DeviceGroupGuids []string `json:"device_group_guids"`
}

// ReplaceRolesRequest PUT /api/users/{guid}/roles 请求体：全量替换语义
// （assignments 即用户最终角色集；空数组 = 清空全部指派）。
type ReplaceRolesRequest struct {
	Assignments []AssignmentInput `json:"assignments" validate:"required"`
}

// EligibilityRow 角色指派资格矩阵行（reason_code 全分支：
// eligible / self_target / target_protected / protected_role /
// super_admin_target）。
type EligibilityRow struct {
	RoleGuid         string `json:"role_guid"`
	RoleName         string `json:"role_name"`
	ProtectedAccount bool   `json:"protected_account"`
	Eligible         bool   `json:"eligible"`
	ReasonCode       string `json:"reason_code"`
}

// EligibilityResult GET /api/users/{guid}/roles/eligibility 响应。
type EligibilityResult struct {
	Data []EligibilityRow `json:"data"`
}
