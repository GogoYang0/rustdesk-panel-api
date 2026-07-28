package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// ============ 内存桩仓储（T01 单测专用；T02 由真实仓储适配接入） ============

type stubUsers struct {
	byGuid map[string]*UserRef
}

func (s *stubUsers) FindAuthUser(_ context.Context, guid string) (*UserRef, error) {
	u, ok := s.byGuid[guid]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (s *stubUsers) FindAuthUsers(_ context.Context, guids []string) (map[string]*UserRef, error) {
	out := map[string]*UserRef{}
	for _, g := range guids {
		if u, ok := s.byGuid[g]; ok {
			out[g] = u
		}
	}
	return out, nil
}

type stubRoles struct {
	byGuid map[string]*RoleRef
}

func (s *stubRoles) FindRolesByGuids(_ context.Context, guids []string) (map[string]*RoleRef, error) {
	out := map[string]*RoleRef{}
	for _, g := range guids {
		if r, ok := s.byGuid[g]; ok {
			out[g] = r
		}
	}
	return out, nil
}

type stubRolePerms struct {
	codes map[string][]string
}

func (s *stubRolePerms) CodesByRoles(_ context.Context, roleGuids []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, g := range roleGuids {
		out[g] = s.codes[g]
	}
	return out, nil
}

type stubAssignments struct {
	byUser map[string][]AssignmentRef
}

func (s *stubAssignments) ListAssignmentsByUser(_ context.Context, userGuid string) ([]AssignmentRef, error) {
	return s.byUser[userGuid], nil
}

func (s *stubAssignments) ListAssignmentsByUsers(_ context.Context, userGuids []string) (map[string][]AssignmentRef, error) {
	out := map[string][]AssignmentRef{}
	for _, g := range userGuids {
		out[g] = s.byUser[g]
	}
	return out, nil
}

type stubAssignmentGroups struct {
	groups map[string][]string
}

func (s *stubAssignmentGroups) GroupsByAssignments(_ context.Context, assignmentGuids []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, g := range assignmentGuids {
		out[g] = s.groups[g]
	}
	return out, nil
}

type stubPeers struct {
	byUUID map[string]*DeviceRef
}

func (s *stubPeers) FindAuthDevice(_ context.Context, uuid string) (*DeviceRef, error) {
	d, ok := s.byUUID[uuid]
	if !ok {
		return nil, ErrDeviceNotFound
	}
	return d, nil
}

func (s *stubPeers) FindAuthDevices(_ context.Context, uuids []string) (map[string]*DeviceRef, error) {
	out := map[string]*DeviceRef{}
	for _, u := range uuids {
		if d, ok := s.byUUID[u]; ok {
			out[u] = d
		}
	}
	return out, nil
}

type stubDeviceGroups struct {
	byGuid map[string]*DeviceGroupRef
}

func (s *stubDeviceGroups) FindDeviceGroupsByGuids(_ context.Context, guids []string) (map[string]*DeviceGroupRef, error) {
	out := map[string]*DeviceGroupRef{}
	for _, g := range guids {
		if d, ok := s.byGuid[g]; ok {
			out[g] = d
		}
	}
	return out, nil
}

// stubStores 装配一组桩。
func stubStores() (Stores, *stubUsers, *stubAssignments, *stubPeers) {
	users := &stubUsers{byGuid: map[string]*UserRef{
		"admin":    {Guid: "admin", Status: StatusActive, IsAdmin: true},
		"scoped":   {Guid: "scoped", Status: StatusActive, IsAdmin: false},
		"global":   {Guid: "global", Status: StatusActive, IsAdmin: false},
		"disabled": {Guid: "disabled", Status: 0, IsAdmin: false},
		"target":   {Guid: "target", Status: StatusActive, IsAdmin: false},
	}}
	roles := &stubRoles{byGuid: map[string]*RoleRef{
		"r-dev":   {Guid: "r-dev", ProtectedAccount: false},
		"r-prot":  {Guid: "r-prot", ProtectedAccount: true},
		"r-strat": {Guid: "r-strat", ProtectedAccount: false},
	}}
	rolePerms := &stubRolePerms{codes: map[string][]string{
		"r-dev":   {"devices.view", "devices.disconnect"},
		"r-prot":  {"devices.view"},
		"r-strat": {"strategies.view", "strategies.assign", "users.view"},
	}}
	assignments := &stubAssignments{byUser: map[string][]AssignmentRef{
		"scoped": { // device_group scope：仅组 dg1
			{Guid: "a1", RoleGuid: "r-dev", ScopeType: ScopeDeviceGroup},
			{Guid: "a4", RoleGuid: "r-strat", ScopeType: ScopeDeviceGroup},
		},
		"global": {
			{Guid: "a2", RoleGuid: "r-dev", ScopeType: ScopeGlobal},
			{Guid: "a5", RoleGuid: "r-strat", ScopeType: ScopeGlobal},
		},
		"target": { // 挂保护角色 → 保护账号
			{Guid: "a3", RoleGuid: "r-prot", ScopeType: ScopeGlobal},
		},
	}}
	assignmentGroups := &stubAssignmentGroups{groups: map[string][]string{
		"a1": {"dg1"},
		"a4": {"dg1"},
	}}
	peers := &stubPeers{byUUID: map[string]*DeviceRef{
		"dev-in-dg1":    {UUID: "dev-in-dg1", DeviceGroupGuid: strPtr("dg1")},
		"dev-in-dg2":    {UUID: "dev-in-dg2", DeviceGroupGuid: strPtr("dg2")},
		"dev-ungrouped": {UUID: "dev-ungrouped", DeviceGroupGuid: nil},
	}}
	deviceGroups := &stubDeviceGroups{byGuid: map[string]*DeviceGroupRef{
		"dg1": {Guid: "dg1", Name: "Group One"},
		"dg2": {Guid: "dg2", Name: "Group Two"},
	}}
	stores := Stores{
		Users:            users,
		Roles:            roles,
		RolePerms:        rolePerms,
		Assignments:      assignments,
		AssignmentGroups: assignmentGroups,
		Peers:            peers,
		DeviceGroups:     deviceGroups,
	}
	return stores, users, assignments, peers
}

func strPtr(s string) *string { return &s }

func newTestAuthz(t *testing.T) *AuthorizationService {
	t.Helper()
	stores, _, _, _ := stubStores()
	return NewAuthorizationService(stores, NewAuditService(nil, nil))
}

// TestGetCurrentUser 覆盖 401 固定文案（被禁用户在 RBAC 路由得 401）。
func TestGetCurrentUser(t *testing.T) {
	svc := newTestAuthz(t)
	ctx := context.Background()

	u, err := svc.GetCurrentUser(ctx, "admin")
	if err != nil || u.Guid != "admin" {
		t.Fatalf("GetCurrentUser(admin) = %v, %v", u, err)
	}

	var se *StatusError
	_, err = svc.GetCurrentUser(ctx, "disabled")
	if !errors.As(err, &se) || se.Status != 401 {
		t.Fatalf("disabled user err = %v, want 401", err)
	}
	if se.Message != "Account does not exist or has been disabled" {
		t.Errorf("message = %q", se.Message)
	}

	_, err = svc.GetCurrentUser(ctx, "ghost")
	if !errors.As(err, &se) || se.Status != 401 {
		t.Fatalf("unknown user err = %v, want 401", err)
	}
}

// TestRequirePermissionDecisions 覆盖 admin/global/device_group/无 scope 决策。
func TestRequirePermissionDecisions(t *testing.T) {
	ctx := context.Background()

	t.Run("admin is always global", func(t *testing.T) {
		svc := newTestAuthz(t)
		scope, err := svc.RequirePermission(ctx, "admin", CodeDevicesDisconnect)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !scope.Global {
			t.Error("admin scope must be global")
		}
	})

	t.Run("global assignment grants global", func(t *testing.T) {
		svc := newTestAuthz(t)
		scope, err := svc.RequirePermission(ctx, "global", CodeDevicesDisconnect)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !scope.Global {
			t.Error("global assignment must yield global scope")
		}
	})

	t.Run("device_group assignment yields group scope", func(t *testing.T) {
		svc := newTestAuthz(t)
		scope, err := svc.RequirePermission(ctx, "scoped", CodeDevicesDisconnect)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if scope.Global {
			t.Error("device_group assignment must not be global")
		}
		if !scope.InDeviceGroup("dg1") || scope.InDeviceGroup("dg2") {
			t.Errorf("scope groups = %v, want only dg1", scope.DeviceGroupGuids)
		}
	})

	t.Run("no assignment denied", func(t *testing.T) {
		svc := newTestAuthz(t)
		// disabled 用户 401 优先。
		var se *StatusError
		_, err := svc.RequirePermission(ctx, "disabled", CodeDevicesView)
		if !errors.As(err, &se) || se.Status != 401 {
			t.Fatalf("disabled user err = %v, want 401", err)
		}
		// ghost 用户（存在但无 assignment 的场景用 target）：先给 target 无码角色。
		_, err = svc.RequirePermission(ctx, "target", CodeStrategiesAssign)
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("target err = %v, want 403", err)
		}
		if se.Message != MsgAccessDenied {
			t.Errorf("message = %q, want %q", se.Message, MsgAccessDenied)
		}
	})

	t.Run("unknown permission rejected", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, err := svc.RequirePermission(ctx, "admin", "made.up.code")
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != MsgUnknownPermission {
			t.Errorf("message = %q, want %q", se.Message, MsgUnknownPermission)
		}
	})

	t.Run("system_only code rejected even for admin", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, err := svc.RequirePermission(ctx, "admin", CodeRolesCreate)
		if !errors.As(err, &se) || se.Status != 403 || se.Message != MsgUnknownPermission {
			t.Fatalf("err = %v, want 403 Unknown permission", err)
		}
	})

	t.Run("dependency filtered code denied", func(t *testing.T) {
		// r-dev 只有 devices.view+disconnect；给某用户挂 roles.view 角色时
		// roles.assign 因缺 users.view 被过滤 → 拒绝。
		stores, _, _, _ := stubStores()
		// target 换成 roles.assign 试验场：新增用户。
		users := stores.Users.(*stubUsers)
		users.byGuid["delegator"] = &UserRef{Guid: "delegator", Status: StatusActive, IsAdmin: false}
		asg := stores.Assignments.(*stubAssignments)
		asg.byUser["delegator"] = []AssignmentRef{{Guid: "a9", RoleGuid: "r-viewonly", ScopeType: ScopeGlobal}}
		rp := stores.RolePerms.(*stubRolePerms)
		rp.codes["r-viewonly"] = []string{"roles.view"} // roles.assign 缺 users.view 不在场
		svc := NewAuthorizationService(stores, NewAuditService(nil, nil))
		var se *StatusError
		_, err := svc.RequirePermission(ctx, "delegator", CodeRolesAssign)
		if !errors.As(err, &se) || se.Status != 403 || se.Message != MsgAccessDenied {
			t.Fatalf("err = %v, want 403 Access denied", err)
		}
	})
}

// TestSuperAdminSemantics 双文案区分。
func TestSuperAdminSemantics(t *testing.T) {
	ctx := context.Background()
	svc := newTestAuthz(t)

	t.Run("roles route wording", func(t *testing.T) {
		var se *StatusError
		_, err := svc.RequireSuperAdmin(ctx, "scoped")
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != "Super administrator permission required" {
			t.Errorf("message = %q", se.Message)
		}
		_, err = svc.RequireSuperAdmin(ctx, "admin")
		if err != nil {
			t.Fatalf("admin should pass: %v", err)
		}
	})

	t.Run("admin guard wording", func(t *testing.T) {
		var se *StatusError
		_, err := svc.RequireAdminGuard(ctx, "global")
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != "Access denied: administrator privileges required" {
			t.Errorf("message = %q", se.Message)
		}
	})
}

// TestAssertDeviceAccess 覆盖未分组设备拒绝与 404。
func TestAssertDeviceAccess(t *testing.T) {
	ctx := context.Background()

	t.Run("scoped operator on unauthorized device", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, _, err := svc.AssertDeviceAccess(ctx, "scoped", CodeDevicesDisconnect, "dev-in-dg2")
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != "Device is not in an authorized device group" {
			t.Errorf("message = %q", se.Message)
		}
	})

	t.Run("scoped operator on ungrouped device rejected", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, _, err := svc.AssertDeviceAccess(ctx, "scoped", CodeDevicesDisconnect, "dev-ungrouped")
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
	})

	t.Run("scoped operator on authorized device passes", func(t *testing.T) {
		svc := newTestAuthz(t)
		device, _, err := svc.AssertDeviceAccess(ctx, "scoped", CodeDevicesDisconnect, "dev-in-dg1")
		if err != nil || device.UUID != "dev-in-dg1" {
			t.Fatalf("device = %v, err = %v", device, err)
		}
	})

	t.Run("device not found", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, _, err := svc.AssertDeviceAccess(ctx, "admin", CodeDevicesDisconnect, "ghost")
		if !errors.As(err, &se) || se.Status != 404 {
			t.Fatalf("err = %v, want 404", err)
		}
		if se.Message != "Device not found" {
			t.Errorf("message = %q", se.Message)
		}
	})

	t.Run("batch contains unauthorized devices", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, _, err := svc.AssertDevicesAccess(ctx, "scoped", CodeDevicesDisconnect, []string{"dev-in-dg1", "dev-in-dg2"})
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != "Batch request contains unauthorized devices" {
			t.Errorf("message = %q", se.Message)
		}
	})

	t.Run("batch missing device is 404", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, _, err := svc.AssertDevicesAccess(ctx, "admin", CodeDevicesDisconnect, []string{"dev-in-dg1", "ghost"})
		if !errors.As(err, &se) || se.Status != 404 {
			t.Fatalf("err = %v, want 404", err)
		}
	})
}

// TestAssertStrategyTargets 覆盖 user 目标 global 门槛与保护账号。
func TestAssertStrategyTargets(t *testing.T) {
	ctx := context.Background()

	t.Run("user target requires global", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, err := svc.AssertStrategyTargets(ctx, "scoped", "user", []string{"target"})
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != "Assigning strategies by user requires global permission" {
			t.Errorf("message = %q", se.Message)
		}
	})

	t.Run("user target protected account needs super admin", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		// global 权限但非超管；target 挂保护角色。
		_, err := svc.AssertStrategyTargets(ctx, "global", "user", []string{"target"})
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != "Protected accounts can only be modified by a super administrator" {
			t.Errorf("message = %q", se.Message)
		}
	})

	t.Run("admin may target protected user", func(t *testing.T) {
		svc := newTestAuthz(t)
		if _, err := svc.AssertStrategyTargets(ctx, "admin", "user", []string{"target"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("device_group target outside scope", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, err := svc.AssertStrategyTargets(ctx, "scoped", "device_group", []string{"dg2"})
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != "Target device group is outside the authorized scope" {
			t.Errorf("message = %q", se.Message)
		}
		if _, err := svc.AssertStrategyTargets(ctx, "scoped", "device_group", []string{"dg1"}); err != nil {
			t.Fatalf("dg1 should pass: %v", err)
		}
	})

	t.Run("device target outside scope", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		_, err := svc.AssertStrategyTargets(ctx, "scoped", "device", []string{"dev-in-dg2"})
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
	})
}

// TestProtectedAccountSemantics 覆盖保护账号判定与批量变更复核。
func TestProtectedAccountSemantics(t *testing.T) {
	ctx := context.Background()

	t.Run("is protected user", func(t *testing.T) {
		svc := newTestAuthz(t)
		if got, err := svc.IsProtectedUser(ctx, "target"); err != nil || !got {
			t.Fatalf("IsProtectedUser(target) = %v, %v", got, err)
		}
		if got, err := svc.IsProtectedUser(ctx, "scoped"); err != nil || got {
			t.Fatalf("IsProtectedUser(scoped) = %v, %v", got, err)
		}
		if got, _ := svc.IsProtectedUser(ctx, "admin"); !got {
			t.Error("admin must be protected")
		}
	})

	t.Run("assert user mutation", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		err := svc.AssertUserMutation(ctx, "scoped", "target", CodeUserGroupsMembership)
		if !errors.As(err, &se) || se.Status != 403 {
			t.Fatalf("err = %v, want 403", err)
		}
		if se.Message != "Protected accounts can only be modified by a super administrator" {
			t.Errorf("message = %q", se.Message)
		}
		if err := svc.AssertUserMutation(ctx, "admin", "target", CodeUserGroupsMembership); err != nil {
			t.Fatalf("admin should pass: %v", err)
		}
	})

	t.Run("assert users mutation batch missing", func(t *testing.T) {
		svc := newTestAuthz(t)
		var se *StatusError
		err := svc.AssertUsersMutation(ctx, "admin", []string{"scoped", "ghost"}, CodeUserGroupsMembership)
		if !errors.As(err, &se) || se.Status != 404 {
			t.Fatalf("err = %v, want 404", err)
		}
		if se.Message != "One or more users do not exist" {
			t.Errorf("message = %q", se.Message)
		}
	})
}

// TestGetEffectivePermissions 覆盖 /permissions/me 载荷。
func TestGetEffectivePermissions(t *testing.T) {
	ctx := context.Background()

	t.Run("admin gets all assignable codes", func(t *testing.T) {
		svc := newTestAuthz(t)
		eff, err := svc.GetEffectivePermissions(ctx, "admin")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(eff.Permissions) != 33 {
			t.Errorf("admin permissions = %d, want 33", len(eff.Permissions))
		}
		if len(eff.Scopes.Global) != 33 {
			t.Errorf("admin global scope = %d codes, want 33", len(eff.Scopes.Global))
		}
	})

	t.Run("scoped user gets group mapping", func(t *testing.T) {
		svc := newTestAuthz(t)
		eff, err := svc.GetEffectivePermissions(ctx, "scoped")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(eff.Permissions) != 5 {
			t.Errorf("permissions = %v, want 5 codes (r-dev + r-strat)", eff.Permissions)
		}
		codes, ok := eff.Scopes.DeviceGroup["dg1"]
		if !ok || len(codes) != 5 {
			t.Errorf("device_group[dg1] = %v, want 5 codes", codes)
		}
		if len(eff.Scopes.Global) != 0 {
			t.Errorf("global scope = %v, want empty (all assignments device_group)", eff.Scopes.Global)
		}
	})
}

// TestDeniedAuditRecorded 覆盖拒绝审计（stub store 记录）。
func TestDeniedAuditRecorded(t *testing.T) {
	stores, _, _, _ := stubStores()
	recorder := &memAuditStore{}
	svc := NewAuthorizationService(stores, NewAuditService(recorder, nil))
	ctx := context.Background()

	_, _ = svc.RequirePermission(ctx, "target", CodeStrategiesAssign)
	if len(recorder.records) != 1 {
		t.Fatalf("denied records = %d, want 1", len(recorder.records))
	}
	rec := recorder.records[0]
	if rec.Result != AuditResultDenied || rec.Reason != MsgAccessDenied {
		t.Errorf("record = %+v", rec)
	}
	if !strings.EqualFold(rec.Action, CodeStrategiesAssign) {
		t.Errorf("action = %q", rec.Action)
	}
}

// memAuditStore 内存审计存储。
type memAuditStore struct {
	records []AuditRecord
}

func (m *memAuditStore) CreateAudit(_ context.Context, rec AuditRecord) error {
	m.records = append(m.records, rec)
	return nil
}
