// Package rbac 实现 M2 RBAC 域：权限目录（编译期常量，杜绝漂移）、
// 生效码过滤、授权决策服务（每次实时查库，不信任 JWT isAdmin）、
// 审计与 HTTP 中间件。
//
// 设计依据：M2 设计 §1.1②（35 码目录 + 双 scope 决策算法）、§1.3（中间件）。
// 固定文案为契约（共享知识 1），逐字节一致，禁止改写。
package rbac

// Scope 常量：权限 scope 两档（共享知识 6）。
const (
	ScopeGlobal      = "global"
	ScopeDeviceGroup = "device_group"
)

// 审计 result 枚举（共享知识 6）。
const (
	AuditResultAllowed = "allowed"
	AuditResultDenied  = "denied"
)

// PermissionDefinition 权限目录条目（对齐参考 permission-catalog.ts，
// 响应字段含 system_only，见共享知识 4）。
type PermissionDefinition struct {
	Code        string   `json:"code"`
	Resource    string   `json:"resource"`
	Action      string   `json:"action"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scope       string   `json:"scope"`
	Assignable  bool     `json:"assignable"`
	SystemOnly  bool     `json:"system_only"`
	Requires    []string `json:"requires"`
}

// 固定错误文案（契约，共享知识 1，逐字节一致）。
const (
	MsgAccessDenied          = "Access denied"
	MsgUnknownPermission     = "Unknown permission"
	MsgSuperAdminRequired    = "Super administrator permission required"
	MsgAdminGuardRequired    = "Access denied: administrator privileges required"
	MsgAccountDisabled       = "Account does not exist or has been disabled"
	MsgDeviceNotInScope      = "Device is not in an authorized device group"
	MsgBatchUnauthorized     = "Batch request contains unauthorized devices"
	MsgAssignUserGlobal      = "Assigning strategies by user requires global permission"
	MsgTargetGroupOutside    = "Target device group is outside the authorized scope"
	MsgProtectedAccount      = "Protected accounts can only be modified by a super administrator"
	MsgSuperAdminRegularRole = "Super administrators cannot be assigned regular roles"
	MsgSelfRoleChange        = "You cannot modify your own roles"
	MsgOwnerAccountImmutable = "The system owner account cannot be disabled or deleted"
	MsgDeviceNotFound        = "Device not found"
)

// 权限码常量（命名 resource.action，共享知识 2）。
const (
	CodeUsersView        = "users.view"
	CodeUsersCreate      = "users.create"
	CodeUsersEdit        = "users.edit"
	CodeUsersStatus      = "users.status"
	CodeUsersDelete      = "users.delete"
	CodeUsersSecurity    = "users.security"
	CodeUsersForceLogout = "users.force_logout"

	CodeUserGroupsView       = "user_groups.view"
	CodeUserGroupsCreate     = "user_groups.create"
	CodeUserGroupsEdit       = "user_groups.edit"
	CodeUserGroupsDelete     = "user_groups.delete"
	CodeUserGroupsMembership = "user_groups.membership"

	CodeDevicesView       = "devices.view"
	CodeDevicesEdit       = "devices.edit"
	CodeDevicesStatus     = "devices.status"
	CodeDevicesDelete     = "devices.delete"
	CodeDevicesDisconnect = "devices.disconnect"

	CodeAddressBooksView  = "address_books.view"
	CodeAddressBooksEdit  = "address_books.edit"
	CodeAddressBooksShare = "address_books.share"

	CodeStrategiesView   = "strategies.view"
	CodeStrategiesCreate = "strategies.create"
	CodeStrategiesEdit   = "strategies.edit"
	CodeStrategiesDelete = "strategies.delete"
	CodeStrategiesAssign = "strategies.assign"

	CodeAuditView = "audit.view"

	CodeRolesView   = "roles.view"
	CodeRolesAssign = "roles.assign"

	CodeServersView       = "servers.view"
	CodeServersControl    = "servers.control"
	CodeServersConfig     = "servers.config"
	CodeServersDisconnect = "servers.disconnect"
	CodeServersBan        = "servers.ban"

	CodeRolesCreate = "roles.create"
	CodeRolesEdit   = "roles.edit"
	CodeRolesDelete = "roles.delete"
)

// catalog 是完整权限目录（设计 §1.1② 清单逐行枚举）：
// 33 个可分配码 + 3 个 system_only 码。M2 使用其中 devices/strategies/
// user_groups/roles 档，其余（users 全档、address_books、audit、servers）
// 为 M3+ 域预留、目录先行收录（与参考目录一致）。
var catalog = []PermissionDefinition{
	// users（requires ⇐ users.view）
	{CodeUsersView, "users", "view", "View users", "View the user list", ScopeGlobal, true, false, nil},
	{CodeUsersCreate, "users", "create", "Create users", "Create new users", ScopeGlobal, true, false, []string{CodeUsersView}},
	{CodeUsersEdit, "users", "edit", "Edit users", "Edit user profiles", ScopeGlobal, true, false, []string{CodeUsersView}},
	{CodeUsersStatus, "users", "status", "Toggle user status", "Enable or disable users", ScopeGlobal, true, false, []string{CodeUsersView}},
	{CodeUsersDelete, "users", "delete", "Delete users", "Delete users", ScopeGlobal, true, false, []string{CodeUsersView}},
	{CodeUsersSecurity, "users", "security", "Manage user security", "Manage 2FA, passkeys and sessions of users", ScopeGlobal, true, false, []string{CodeUsersView}},
	{CodeUsersForceLogout, "users", "force_logout", "Force logout", "Force logout users", ScopeGlobal, true, false, []string{CodeUsersView}},

	// user_groups（requires ⇐ user_groups.view）
	{CodeUserGroupsView, "user_groups", "view", "View user groups", "View user groups", ScopeGlobal, true, false, nil},
	{CodeUserGroupsCreate, "user_groups", "create", "Create user groups", "Create user groups", ScopeGlobal, true, false, []string{CodeUserGroupsView}},
	{CodeUserGroupsEdit, "user_groups", "edit", "Edit user groups", "Edit user groups", ScopeGlobal, true, false, []string{CodeUserGroupsView}},
	{CodeUserGroupsDelete, "user_groups", "delete", "Delete user groups", "Delete user groups", ScopeGlobal, true, false, []string{CodeUserGroupsView}},
	{CodeUserGroupsMembership, "user_groups", "membership", "Manage user group membership", "Move users between user groups", ScopeGlobal, true, false, []string{CodeUserGroupsView}},

	// devices（scope=device_group 档，requires ⇐ devices.view）
	{CodeDevicesView, "devices", "view", "View devices", "View devices", ScopeDeviceGroup, true, false, nil},
	{CodeDevicesEdit, "devices", "edit", "Edit devices", "Edit devices", ScopeDeviceGroup, true, false, []string{CodeDevicesView}},
	{CodeDevicesStatus, "devices", "status", "Toggle device status", "Enable or disable devices", ScopeDeviceGroup, true, false, []string{CodeDevicesView}},
	{CodeDevicesDelete, "devices", "delete", "Delete devices", "Delete devices", ScopeDeviceGroup, true, false, []string{CodeDevicesView}},
	{CodeDevicesDisconnect, "devices", "disconnect", "Disconnect devices", "Disconnect device sessions", ScopeDeviceGroup, true, false, []string{CodeDevicesView}},

	// address_books（requires ⇐ address_books.view）
	{CodeAddressBooksView, "address_books", "view", "View address books", "View address books", ScopeGlobal, true, false, nil},
	{CodeAddressBooksEdit, "address_books", "edit", "Edit address books", "Edit address books", ScopeGlobal, true, false, []string{CodeAddressBooksView}},
	{CodeAddressBooksShare, "address_books", "share", "Share address books", "Share address books", ScopeGlobal, true, false, []string{CodeAddressBooksView}},

	// strategies（assign 的 scope=device_group 档，其余 requires ⇐ strategies.view）
	{CodeStrategiesView, "strategies", "view", "View strategies", "View strategies", ScopeGlobal, true, false, nil},
	{CodeStrategiesCreate, "strategies", "create", "Create strategies", "Create strategies", ScopeGlobal, true, false, []string{CodeStrategiesView}},
	{CodeStrategiesEdit, "strategies", "edit", "Edit strategies", "Edit strategies", ScopeGlobal, true, false, []string{CodeStrategiesView}},
	{CodeStrategiesDelete, "strategies", "delete", "Delete strategies", "Delete strategies", ScopeGlobal, true, false, []string{CodeStrategiesView}},
	{CodeStrategiesAssign, "strategies", "assign", "Assign strategies", "Assign strategies to devices, users and device groups", ScopeDeviceGroup, true, false, []string{CodeStrategiesView, CodeUsersView}},

	// audit
	{CodeAuditView, "audit", "view", "View audit logs", "View console audit logs", ScopeGlobal, true, false, nil},

	// roles（roles.create/edit/delete 为 system_only，不可存储到角色）
	{CodeRolesView, "roles", "view", "View roles", "View roles", ScopeGlobal, true, false, nil},
	{CodeRolesAssign, "roles", "assign", "Assign roles", "Assign roles to users", ScopeGlobal, true, false, []string{CodeRolesView, CodeUsersView}},
	{CodeRolesCreate, "roles", "create", "Create roles", "Create roles", ScopeGlobal, false, true, nil},
	{CodeRolesEdit, "roles", "edit", "Edit roles", "Edit roles", ScopeGlobal, false, true, nil},
	{CodeRolesDelete, "roles", "delete", "Delete roles", "Delete roles", ScopeGlobal, false, true, nil},

	// servers（M3 server-management 用，M2 仅目录收录）
	{CodeServersView, "servers", "view", "View servers", "View relay servers", ScopeGlobal, true, false, nil},
	{CodeServersControl, "servers", "control", "Control servers", "Start or stop relay servers", ScopeGlobal, true, false, []string{CodeServersView}},
	{CodeServersConfig, "servers", "config", "Configure servers", "Configure relay servers", ScopeGlobal, true, false, []string{CodeServersView}},
	{CodeServersDisconnect, "servers", "disconnect", "Disconnect servers", "Disconnect server sessions", ScopeGlobal, true, false, []string{CodeServersView}},
	{CodeServersBan, "servers", "ban", "Ban servers", "Ban relay servers", ScopeGlobal, true, false, []string{CodeServersView}},
}

// Catalog 返回完整权限目录（GET /api/permissions 直接序列化，
// 顺序稳定 = 定义顺序）。
func Catalog() []PermissionDefinition {
	out := make([]PermissionDefinition, len(catalog))
	copy(out, catalog)
	return out
}

// catalogIndex 码 → 目录下标（包初始化构建）。
var catalogIndex = func() map[string]PermissionDefinition {
	m := make(map[string]PermissionDefinition, len(catalog))
	for _, d := range catalog {
		m[d.Code] = d
	}
	return m
}()

// FindDefinition 按码查目录条目。
func FindDefinition(code string) (PermissionDefinition, bool) {
	d, ok := catalogIndex[code]
	return d, ok
}

// IsAssignable 报告码是否可存储到角色（system_only 码 false）。
// 未知码同样不可分配。
func IsAssignable(code string) bool {
	d, ok := catalogIndex[code]
	return ok && d.Assignable
}

// IsDeviceGroupScoped 报告码是否属于 device_group 档
// （仅 devices.view/edit/status/delete/disconnect + strategies.assign 六码）。
func IsDeviceGroupScoped(code string) bool {
	d, ok := catalogIndex[code]
	return ok && d.Scope == ScopeDeviceGroup
}
