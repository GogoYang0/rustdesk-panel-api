package rbac

import (
	"context"
	"errors"
	"net/http"
	"sort"
)

// StatusError 携带 HTTP 状态码与固定文案的业务错误（共享知识 1）。
// 中间件与服务层以它统一映射错误包络 {statusCode, message, error}。
type StatusError struct {
	Status  int
	Message string
}

// Error 实现 error。
func (e *StatusError) Error() string { return e.Message }

// ErrBadRequest 构造 400 业务错误。
func ErrBadRequest(msg string) *StatusError {
	return &StatusError{Status: http.StatusBadRequest, Message: msg}
}

// ErrForbidden 构造 403 业务错误。
func ErrForbidden(msg string) *StatusError {
	return &StatusError{Status: http.StatusForbidden, Message: msg}
}

// ErrNotFoundErr 构造 404 业务错误。
func ErrNotFoundErr(msg string) *StatusError {
	return &StatusError{Status: http.StatusNotFound, Message: msg}
}

// ErrUnauthorizedMsg 构造 401 业务错误（如被禁用户固定文案）。
func ErrUnauthorizedMsg(msg string) *StatusError {
	return &StatusError{Status: http.StatusUnauthorized, Message: msg}
}

// 仓储端口约定的哨兵错误：适配器必须把"记录不存在"映射为它们，
// 其余错误原样透传（由中间件转 500）。
var (
	// ErrUserNotFound 用户不存在（GetCurrentUser 转 401 固定文案）。
	ErrUserNotFound = errors.New("rbac: user not found")
	// ErrDeviceNotFound 设备不存在（Assert 转 404 Device not found）。
	ErrDeviceNotFound = errors.New("rbac: device not found")
)

// StatusActive users.status 的 ACTIVE 值（1；0=停用，共享知识 6）。
const StatusActive = 1

// UserRef 授权上下文中的用户最小视图（避免 rbac 反向依赖具体实体全列）。
type UserRef struct {
	Guid    string
	Status  int
	IsAdmin bool
}

// DeviceRef 设备最小视图。
type DeviceRef struct {
	UUID            string
	DeviceGroupGuid *string
}

// RoleRef 角色最小视图。
type RoleRef struct {
	Guid             string
	ProtectedAccount bool
}

// DeviceGroupRef 设备组最小视图。
type DeviceGroupRef struct {
	Guid string
	Name string
}

// AssignmentRef 角色指派最小视图（scope_type ∈ global|device_group）。
type AssignmentRef struct {
	Guid      string
	RoleGuid  string
	ScopeType string
}

// UserReader 用户读取端口。
type UserReader interface {
	// FindAuthUser 按 guid 查用户；未找到必须返回 ErrUserNotFound。
	FindAuthUser(ctx context.Context, guid string) (*UserRef, error)
	// FindAuthUsers 批量按 guid 查用户；未找到的 guid 不出现在结果中。
	FindAuthUsers(ctx context.Context, guids []string) (map[string]*UserRef, error)
}

// RoleReader 角色读取端口。
type RoleReader interface {
	// FindRolesByGuids 批量查角色；未找到的 guid 不出现在结果中。
	FindRolesByGuids(ctx context.Context, guids []string) (map[string]*RoleRef, error)
}

// RolePermissionReader 角色-权限码读取端口。
type RolePermissionReader interface {
	// CodesByRoles 返回 roleGuid → 权限码列表。
	CodesByRoles(ctx context.Context, roleGuids []string) (map[string][]string, error)
}

// AssignmentReader 角色指派读取端口。
type AssignmentReader interface {
	// ListAssignmentsByUser 用户全部指派。
	ListAssignmentsByUser(ctx context.Context, userGuid string) ([]AssignmentRef, error)
	// ListAssignmentsByUsers 批量用户指派（保护账号判定）。
	ListAssignmentsByUsers(ctx context.Context, userGuids []string) (map[string][]AssignmentRef, error)
}

// AssignmentGroupReader 指派-设备组关联读取端口。
type AssignmentGroupReader interface {
	// GroupsByAssignments 返回 assignmentGuid → 设备组 guid 列表。
	GroupsByAssignments(ctx context.Context, assignmentGuids []string) (map[string][]string, error)
}

// PeerReader 设备读取端口。
type PeerReader interface {
	// FindAuthDevice 按 uuid 查设备；未找到必须返回 ErrDeviceNotFound。
	FindAuthDevice(ctx context.Context, uuid string) (*DeviceRef, error)
	// FindAuthDevices 批量按 uuid 查设备；未找到的 uuid 不出现在结果中。
	FindAuthDevices(ctx context.Context, uuids []string) (map[string]*DeviceRef, error)
}

// DeviceGroupReader 设备组读取端口。
type DeviceGroupReader interface {
	// FindDeviceGroupsByGuids 批量查设备组；未找到的 guid 不出现在结果中。
	FindDeviceGroupsByGuids(ctx context.Context, guids []string) (map[string]*DeviceGroupRef, error)
}

// Stores 授权服务的仓储端口集合（T02 由真实仓储适配接入；
// 任一端口缺失时决策方法 panic 属开发期装配错误）。
type Stores struct {
	Users            UserReader
	Roles            RoleReader
	RolePerms        RolePermissionReader
	Assignments      AssignmentReader
	AssignmentGroups AssignmentGroupReader
	Peers            PeerReader
	DeviceGroups     DeviceGroupReader
}

// PermissionScope 授权范围（决策算法产出）：
// Global=true 表示无边界；否则 DeviceGroupGuids 为授权设备组并集。
type PermissionScope struct {
	Global           bool
	DeviceGroupGuids map[string]struct{}
}

// InDeviceGroup 报告 guid 是否在 scope 设备组集内。
func (s PermissionScope) InDeviceGroup(guid string) bool {
	if s.Global {
		return true
	}
	if s.DeviceGroupGuids == nil {
		return false
	}
	_, ok := s.DeviceGroupGuids[guid]
	return ok
}

// EffectiveScope 用户全部指派的聚合 scope（users/{guid}/roles 响应）。
type EffectiveScope string

// EffectiveScope 取值。
const (
	EffectiveScopeNone        EffectiveScope = "none"
	EffectiveScopeGlobal      EffectiveScope = "global"
	EffectiveScopeDeviceGroup EffectiveScope = "device_group"
)

// EffectiveScopes GET /api/permissions/me 的 scopes 字段：
// global 为 global scope 下的生效码并集；device_group 为
// 设备组 guid → 该组 scope 下生效码。
type EffectiveScopes struct {
	Global      []string            `json:"global"`
	DeviceGroup map[string][]string `json:"device_group"`
}

// EffectivePermissions GET /api/permissions/me 载荷（共享知识 4 响应混排）。
type EffectivePermissions struct {
	Permissions []string        `json:"permissions"`
	Scopes      EffectiveScopes `json:"scopes"`
}

// AuthorizationService RBAC 授权决策服务。
//
// 红线（共享知识 3）：授权决策一律实时查库，不信任 JWT 中的 isAdmin；
// 被禁用户在受 RBAC 路由上得 401 而非 403。
type AuthorizationService struct {
	stores Stores
	audit  *AuditService
}

// NewAuthorizationService 构建授权服务。
func NewAuthorizationService(stores Stores, audit *AuditService) *AuthorizationService {
	return &AuthorizationService{stores: stores, audit: audit}
}

// GetCurrentUser 按 guid 实时查用户：不存在或 status != ACTIVE →
// 401 "Account does not exist or has been disabled"。
func (s *AuthorizationService) GetCurrentUser(ctx context.Context, userGuid string) (*UserRef, error) {
	user, err := s.stores.Users.FindAuthUser(ctx, userGuid)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrUnauthorizedMsg(MsgAccountDisabled)
		}
		return nil, err
	}
	if user.Status != StatusActive {
		return nil, ErrUnauthorizedMsg(MsgAccountDisabled)
	}
	return user, nil
}

// RequireSuperAdmin 超管校验：非超管 → 403 "Super administrator permission required"
// （roles CRUD 路线文案）+ denied 审计。
func (s *AuthorizationService) RequireSuperAdmin(ctx context.Context, userGuid string) (*UserRef, error) {
	user, err := s.GetCurrentUser(ctx, userGuid)
	if err != nil {
		return nil, err
	}
	if !user.IsAdmin {
		s.denied(ctx, userGuid, "route", "", "super_admin", MsgSuperAdminRequired)
		return nil, ErrForbidden(MsgSuperAdminRequired)
	}
	return user, nil
}

// RequireAdminGuard AdminGuard 语义校验（device-groups CRUD 路线）：
// 非超管 → 403 "Access denied: administrator privileges required" + denied 审计。
func (s *AuthorizationService) RequireAdminGuard(ctx context.Context, userGuid string) (*UserRef, error) {
	user, err := s.GetCurrentUser(ctx, userGuid)
	if err != nil {
		return nil, err
	}
	if !user.IsAdmin {
		s.denied(ctx, userGuid, "route", "", "admin_guard", MsgAdminGuardRequired)
		return nil, ErrForbidden(MsgAdminGuardRequired)
	}
	return user, nil
}

// RequirePermission 权限决策（中间件入口）：
//  1. GetCurrentUser（401）；
//  2. 码不可分配 → 403 "Unknown permission"；
//  3. scope 为空 → 403 "Access denied"（均记 denied 审计）；
//  4. 放行并返回 scope。
func (s *AuthorizationService) RequirePermission(ctx context.Context, userGuid, code string) (PermissionScope, error) {
	user, err := s.GetCurrentUser(ctx, userGuid)
	if err != nil {
		return PermissionScope{}, err
	}
	if !IsAssignable(code) {
		s.denied(ctx, userGuid, "route", "", code, MsgUnknownPermission)
		return PermissionScope{}, ErrForbidden(MsgUnknownPermission)
	}
	scope, err := s.computeScope(ctx, user, code)
	if err != nil {
		return PermissionScope{}, err
	}
	if scope.Global || len(scope.DeviceGroupGuids) > 0 {
		return scope, nil
	}
	s.denied(ctx, userGuid, "route", "", code, MsgAccessDenied)
	return PermissionScope{}, ErrForbidden(MsgAccessDenied)
}

// GetPermissionScope 供 handler 复取 scope（与 RequirePermission 同语义，
// 但不写 denied 审计——中间件已决策过；scope 为空同样返回 403）。
func (s *AuthorizationService) GetPermissionScope(ctx context.Context, userGuid, code string) (PermissionScope, error) {
	user, err := s.GetCurrentUser(ctx, userGuid)
	if err != nil {
		return PermissionScope{}, err
	}
	if !IsAssignable(code) {
		return PermissionScope{}, ErrForbidden(MsgUnknownPermission)
	}
	scope, err := s.computeScope(ctx, user, code)
	if err != nil {
		return PermissionScope{}, err
	}
	if scope.Global || len(scope.DeviceGroupGuids) > 0 {
		return scope, nil
	}
	return PermissionScope{}, ErrForbidden(MsgAccessDenied)
}

// computeScope 决策内核：isAdmin → global；否则加载全部
// user_role_assignments × role_permissions，经生效码过滤后：
// 任一 global-scope assignment 含该码 → global；否则收集全部
// device_group-scope assignment 的设备组并集。
func (s *AuthorizationService) computeScope(ctx context.Context, user *UserRef, code string) (PermissionScope, error) {
	scope := PermissionScope{DeviceGroupGuids: map[string]struct{}{}}
	if user.IsAdmin {
		scope.Global = true
		return scope, nil
	}
	assignments, err := s.stores.Assignments.ListAssignmentsByUser(ctx, user.Guid)
	if err != nil {
		return PermissionScope{}, err
	}
	if len(assignments) == 0 {
		return scope, nil
	}
	roleGuids := uniqueStrings(func() []string {
		out := make([]string, 0, len(assignments))
		for _, a := range assignments {
			out = append(out, a.RoleGuid)
		}
		return out
	}())
	codesByRole, err := s.stores.RolePerms.CodesByRoles(ctx, roleGuids)
	if err != nil {
		return PermissionScope{}, err
	}
	// 仅 device_group scope 的 assignment 需要展开组关联。
	groupAssignmentGuids := make([]string, 0)
	for _, a := range assignments {
		if a.ScopeType == ScopeDeviceGroup {
			groupAssignmentGuids = append(groupAssignmentGuids, a.Guid)
		}
	}
	groupsByAssignment := map[string][]string{}
	if len(groupAssignmentGuids) > 0 {
		groupsByAssignment, err = s.stores.AssignmentGroups.GroupsByAssignments(ctx, groupAssignmentGuids)
		if err != nil {
			return PermissionScope{}, err
		}
	}
	for _, a := range assignments {
		effective := FilterEffective(codesByRole[a.RoleGuid])
		has := false
		for _, c := range effective {
			if c == code {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		switch a.ScopeType {
		case ScopeGlobal:
			scope.Global = true
		case ScopeDeviceGroup:
			for _, g := range groupsByAssignment[a.Guid] {
				scope.DeviceGroupGuids[g] = struct{}{}
			}
		}
	}
	if scope.Global {
		// global 无边界；组集无意义，清空避免误读。
		scope.DeviceGroupGuids = map[string]struct{}{}
	}
	return scope, nil
}

// GetEffectivePermissions 计算 GET /api/permissions/me 载荷：
// 生效码并集（目录顺序）+ scopes（global 码并集 / 设备组 → 码）。
func (s *AuthorizationService) GetEffectivePermissions(ctx context.Context, userGuid string) (EffectivePermissions, error) {
	user, err := s.GetCurrentUser(ctx, userGuid)
	if err != nil {
		return EffectivePermissions{}, err
	}
	if user.IsAdmin {
		global := make([]string, 0, len(catalog))
		for _, d := range catalog {
			if d.Assignable {
				global = append(global, d.Code)
			}
		}
		return EffectivePermissions{
			Permissions: global,
			Scopes:      EffectiveScopes{Global: global, DeviceGroup: map[string][]string{}},
		}, nil
	}
	assignments, err := s.stores.Assignments.ListAssignmentsByUser(ctx, user.Guid)
	if err != nil {
		return EffectivePermissions{}, err
	}
	permSet := map[string]struct{}{}
	globalSet := map[string]struct{}{}
	groupCodes := map[string]map[string]struct{}{}
	if len(assignments) > 0 {
		roleGuids := uniqueStrings(func() []string {
			out := make([]string, 0, len(assignments))
			for _, a := range assignments {
				out = append(out, a.RoleGuid)
			}
			return out
		}())
		codesByRole, err := s.stores.RolePerms.CodesByRoles(ctx, roleGuids)
		if err != nil {
			return EffectivePermissions{}, err
		}
		groupAssignmentGuids := make([]string, 0)
		for _, a := range assignments {
			if a.ScopeType == ScopeDeviceGroup {
				groupAssignmentGuids = append(groupAssignmentGuids, a.Guid)
			}
		}
		groupsByAssignment := map[string][]string{}
		if len(groupAssignmentGuids) > 0 {
			groupsByAssignment, err = s.stores.AssignmentGroups.GroupsByAssignments(ctx, groupAssignmentGuids)
			if err != nil {
				return EffectivePermissions{}, err
			}
		}
		for _, a := range assignments {
			effective := FilterEffective(codesByRole[a.RoleGuid])
			for _, c := range effective {
				permSet[c] = struct{}{}
			}
			switch a.ScopeType {
			case ScopeGlobal:
				for _, c := range effective {
					globalSet[c] = struct{}{}
				}
			case ScopeDeviceGroup:
				for _, g := range groupsByAssignment[a.Guid] {
					if groupCodes[g] == nil {
						groupCodes[g] = map[string]struct{}{}
					}
					for _, c := range effective {
						groupCodes[g][c] = struct{}{}
					}
				}
			}
		}
	}
	// 输出按目录顺序稳定排列。
	permissions := make([]string, 0, len(permSet))
	for _, d := range catalog {
		if _, ok := permSet[d.Code]; ok {
			permissions = append(permissions, d.Code)
		}
	}
	global := make([]string, 0, len(globalSet))
	for _, d := range catalog {
		if _, ok := globalSet[d.Code]; ok {
			global = append(global, d.Code)
		}
	}
	devices := make(map[string][]string, len(groupCodes))
	for g, set := range groupCodes {
		codes := make([]string, 0, len(set))
		for c := range set {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		devices[g] = codes
	}
	return EffectivePermissions{
		Permissions: permissions,
		Scopes:      EffectiveScopes{Global: global, DeviceGroup: devices},
	}, nil
}

// ComputeScopeFor 计算 scope 而不做空 scope 拒绝（无权限码端点使用：
// scope 为空时由调用方回退显式授权源，而非 403）。码不可分配时返回
// 空 scope（该端点未声明权限语义，不做 Unknown permission 拒绝）。
func (s *AuthorizationService) ComputeScopeFor(ctx context.Context, userGuid, code string) (PermissionScope, error) {
	user, err := s.GetCurrentUser(ctx, userGuid)
	if err != nil {
		return PermissionScope{}, err
	}
	if !IsAssignable(code) {
		return PermissionScope{DeviceGroupGuids: map[string]struct{}{}}, nil
	}
	return s.computeScope(ctx, user, code)
}

// AssertDeviceAccess 资源级复核：设备必须存在且落在 scope 边界内。
// 未分组设备对 scoped 操作者一律拒绝（设计 §1.1② 决策算法 4）。
func (s *AuthorizationService) AssertDeviceAccess(ctx context.Context, actorGuid, code, uuid string) (*DeviceRef, PermissionScope, error) {
	user, err := s.GetCurrentUser(ctx, actorGuid)
	if err != nil {
		return nil, PermissionScope{}, err
	}
	scope, err := s.computeScope(ctx, user, code)
	if err != nil {
		return nil, PermissionScope{}, err
	}
	if !scope.Global && len(scope.DeviceGroupGuids) == 0 {
		s.denied(ctx, actorGuid, "device", uuid, code, MsgAccessDenied)
		return nil, PermissionScope{}, ErrForbidden(MsgAccessDenied)
	}
	device, err := s.stores.Peers.FindAuthDevice(ctx, uuid)
	if err != nil {
		if errors.Is(err, ErrDeviceNotFound) {
			return nil, PermissionScope{}, ErrNotFoundErr(MsgDeviceNotFound)
		}
		return nil, PermissionScope{}, err
	}
	if !scope.Global && !scope.InDeviceGroup(deref(device.DeviceGroupGuid)) {
		s.denied(ctx, actorGuid, "device", uuid, code, MsgDeviceNotInScope)
		return nil, PermissionScope{}, ErrForbidden(MsgDeviceNotInScope)
	}
	return device, scope, nil
}

// AssertDevicesAccess 批量资源级复核：任一设备不存在 → 404
// "Device not found"；任一设备越出 scope → 403
// "Batch request contains unauthorized devices"。
func (s *AuthorizationService) AssertDevicesAccess(ctx context.Context, actorGuid, code string, uuids []string) ([]DeviceRef, PermissionScope, error) {
	user, err := s.GetCurrentUser(ctx, actorGuid)
	if err != nil {
		return nil, PermissionScope{}, err
	}
	scope, err := s.computeScope(ctx, user, code)
	if err != nil {
		return nil, PermissionScope{}, err
	}
	if !scope.Global && len(scope.DeviceGroupGuids) == 0 {
		s.denied(ctx, actorGuid, "device", "", code, MsgAccessDenied)
		return nil, PermissionScope{}, ErrForbidden(MsgAccessDenied)
	}
	devices, err := s.stores.Peers.FindAuthDevices(ctx, uuids)
	if err != nil {
		return nil, PermissionScope{}, err
	}
	out := make([]DeviceRef, 0, len(uuids))
	for _, u := range uuids {
		d, ok := devices[u]
		if !ok {
			return nil, PermissionScope{}, ErrNotFoundErr(MsgDeviceNotFound)
		}
		out = append(out, *d)
	}
	if scope.Global {
		return out, scope, nil
	}
	for _, d := range out {
		if !scope.InDeviceGroup(deref(d.DeviceGroupGuid)) {
			s.denied(ctx, actorGuid, "device", d.UUID, code, MsgBatchUnauthorized)
			return nil, PermissionScope{}, ErrForbidden(MsgBatchUnauthorized)
		}
	}
	return out, scope, nil
}

// AssertStrategyTargets 策略指派目标复核（决策算法 5）：
//   - target_type=user 必须 global scope（403
//     "Assigning strategies by user requires global permission"），
//     且保护账号目标需 super admin；
//   - device_group/device 目标逐一比对 scope；
//   - 目标不存在不在此报错（由服务层记入 errors 数组）。
func (s *AuthorizationService) AssertStrategyTargets(ctx context.Context, actorGuid, targetType string, guids []string) (PermissionScope, error) {
	user, err := s.GetCurrentUser(ctx, actorGuid)
	if err != nil {
		return PermissionScope{}, err
	}
	scope, err := s.computeScope(ctx, user, CodeStrategiesAssign)
	if err != nil {
		return PermissionScope{}, err
	}
	if !scope.Global && len(scope.DeviceGroupGuids) == 0 {
		s.denied(ctx, actorGuid, "strategy", "", CodeStrategiesAssign, MsgAccessDenied)
		return PermissionScope{}, ErrForbidden(MsgAccessDenied)
	}
	switch targetType {
	case "user":
		if !scope.Global {
			s.denied(ctx, actorGuid, "user", "", CodeStrategiesAssign, MsgAssignUserGlobal)
			return PermissionScope{}, ErrForbidden(MsgAssignUserGlobal)
		}
		users, err := s.stores.Users.FindAuthUsers(ctx, guids)
		if err != nil {
			return PermissionScope{}, err
		}
		existing := make([]string, 0, len(users))
		for g := range users {
			existing = append(existing, g)
		}
		protected, err := s.GetEffectiveProtectionMap(ctx, existing)
		if err != nil {
			return PermissionScope{}, err
		}
		for g, isProtected := range protected {
			if isProtected && !user.IsAdmin {
				s.denied(ctx, actorGuid, "user", g, CodeStrategiesAssign, MsgProtectedAccount)
				return PermissionScope{}, ErrForbidden(MsgProtectedAccount)
			}
		}
	case "device_group":
		if scope.Global {
			return scope, nil
		}
		groups, err := s.stores.DeviceGroups.FindDeviceGroupsByGuids(ctx, guids)
		if err != nil {
			return PermissionScope{}, err
		}
		for g := range groups {
			if !scope.InDeviceGroup(g) {
				s.denied(ctx, actorGuid, "device_group", g, CodeStrategiesAssign, MsgTargetGroupOutside)
				return PermissionScope{}, ErrForbidden(MsgTargetGroupOutside)
			}
		}
	case "device":
		if scope.Global {
			return scope, nil
		}
		devices, err := s.stores.Peers.FindAuthDevices(ctx, guids)
		if err != nil {
			return PermissionScope{}, err
		}
		for _, d := range devices {
			if !scope.InDeviceGroup(deref(d.DeviceGroupGuid)) {
				s.denied(ctx, actorGuid, "device", d.UUID, CodeStrategiesAssign, MsgDeviceNotInScope)
				return PermissionScope{}, ErrForbidden(MsgDeviceNotInScope)
			}
		}
	default:
		return PermissionScope{}, ErrBadRequest("Invalid target_type")
	}
	return scope, nil
}

// AssertUserMutation 单用户变更复核（决策算法 6）：
// 目标是保护账号（isAdmin 或挂 protectedAccount 角色）时要求
// super admin，失败记审计后 403
// "Protected accounts can only be modified by a super administrator"。
// 注：系统所有者不可禁用/删除的文案（MsgOwnerAccountImmutable）由 M3
// users.status/delete 服务在对应动作上触发，成员移动不适用。
func (s *AuthorizationService) AssertUserMutation(ctx context.Context, actorGuid, targetGuid, code string) error {
	return s.assertUsersMutation(ctx, actorGuid, []string{targetGuid}, code, true)
}

// AssertUsersMutation 批量用户变更复核：任一目标不存在 → 404
// "One or more users do not exist"；任一目标为保护账号且操作者非超管 →
// 403（同上文案）。
func (s *AuthorizationService) AssertUsersMutation(ctx context.Context, actorGuid string, targetGuids []string, code string) error {
	return s.assertUsersMutation(ctx, actorGuid, targetGuids, code, false)
}

// assertUsersMutation 公共实现；single=true 时缺失目标返回 404
// "User does not exist"（单数文案）。
func (s *AuthorizationService) assertUsersMutation(ctx context.Context, actorGuid string, targetGuids []string, code string, single bool) error {
	actor, err := s.GetCurrentUser(ctx, actorGuid)
	if err != nil {
		return err
	}
	users, err := s.stores.Users.FindAuthUsers(ctx, targetGuids)
	if err != nil {
		return err
	}
	for _, g := range targetGuids {
		if _, ok := users[g]; !ok {
			if single {
				return ErrNotFoundErr("User does not exist")
			}
			return ErrNotFoundErr("One or more users do not exist")
		}
	}
	protected, err := s.GetEffectiveProtectionMap(ctx, targetGuids)
	if err != nil {
		return err
	}
	for _, g := range targetGuids {
		if protected[g] && !actor.IsAdmin {
			s.denied(ctx, actorGuid, "user", g, code, MsgProtectedAccount)
			return ErrForbidden(MsgProtectedAccount)
		}
	}
	return nil
}

// IsProtectedUser 报告用户是否保护账号：isAdmin 或存在 protectedAccount
// 角色的指派。用户不存在返回 ErrUserNotFound。
func (s *AuthorizationService) IsProtectedUser(ctx context.Context, userGuid string) (bool, error) {
	user, err := s.stores.Users.FindAuthUser(ctx, userGuid)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return false, ErrUserNotFound
		}
		return false, err
	}
	if user.IsAdmin {
		return true, nil
	}
	protected, err := s.GetEffectiveProtectionMap(ctx, []string{userGuid})
	if err != nil {
		return false, err
	}
	return protected[userGuid], nil
}

// GetEffectiveProtectionMap 批量判定保护账号：
// isAdmin || 存在 protectedAccount 角色的指派（经生效语义，
// 保护角色本身不受依赖过滤影响——protectedAccount 是角色属性）。
// 不存在的 guid 映射为 false。
func (s *AuthorizationService) GetEffectiveProtectionMap(ctx context.Context, guids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(guids))
	if len(guids) == 0 {
		return out, nil
	}
	users, err := s.stores.Users.FindAuthUsers(ctx, guids)
	if err != nil {
		return nil, err
	}
	for g, u := range users {
		out[g] = u.IsAdmin
	}
	assignmentsByUser, err := s.stores.Assignments.ListAssignmentsByUsers(ctx, guids)
	if err != nil {
		return nil, err
	}
	roleGuids := make([]string, 0)
	for _, list := range assignmentsByUser {
		for _, a := range list {
			roleGuids = append(roleGuids, a.RoleGuid)
		}
	}
	rolesByGuid := map[string]*RoleRef{}
	if len(roleGuids) > 0 {
		rolesByGuid, err = s.stores.Roles.FindRolesByGuids(ctx, uniqueStrings(roleGuids))
		if err != nil {
			return nil, err
		}
	}
	for g, list := range assignmentsByUser {
		for _, a := range list {
			if role, ok := rolesByGuid[a.RoleGuid]; ok && role.ProtectedAccount {
				out[g] = true
			}
		}
	}
	return out, nil
}

// denied 写拒绝审计（targetType=route|device|user|device_group|strategy）。
func (s *AuthorizationService) denied(ctx context.Context, actorGuid, targetType, targetGuid, code, reason string) {
	if s.audit == nil {
		return
	}
	s.audit.RecordDenied(ctx, AuditRecord{
		ActorUserGuid: actorGuid,
		TargetType:    targetType,
		TargetGuid:    targetGuid,
		Action:        code,
		Reason:        reason,
		RequestID:     RequestIDFrom(ctx),
	})
}

// deref 空安全指针解引用。
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// uniqueStrings 去重（保持首次出现顺序）。
func uniqueStrings(in []string) []string {
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
