// Package server RBAC 适配层测试：真实仓储 + SeedM2 fixture 驱动
// rbac.AuthorizationService 决策链（global/scoped/被禁/超管/保护账号），
// 并验证 denied 审计经 ConsoleAuditRepo 落 console_audits。
package server

import (
	"context"
	"errors"
	"testing"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// openRBAC 迁移+种子就绪的库、决策服务与审计仓储。
func openRBAC(t *testing.T) (context.Context, *gorm.DB, *testutil.SeedM2Data, *rbac.AuthorizationService, *repository.ConsoleAuditRepo) {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	data := testutil.SeedM2(t, db)
	auditRepo := repository.NewConsoleAuditRepo(db)
	auditSvc := rbac.NewAuditService(auditRepo, testutil.TestLogger())
	authz := rbac.NewAuthorizationService(NewRBACStores(db), auditSvc)
	return context.Background(), db, data, authz, auditRepo
}

// countAudits 读取审计行数。
func countAudits(t *testing.T, db *gorm.DB) []entity.ConsoleAudit {
	t.Helper()
	rows := make([]entity.ConsoleAudit, 0)
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("read audits: %v", err)
	}
	return rows
}

// TestRBACStoresAdminGlobal 超管（isAdmin）→ global scope。
func TestRBACStoresAdminGlobal(t *testing.T) {
	ctx, _, data, authz, _ := openRBAC(t)

	user, err := authz.GetCurrentUser(ctx, data.Admin.Guid)
	if err != nil {
		t.Fatalf("GetCurrentUser: %v", err)
	}
	if !user.IsAdmin || user.Status != rbac.StatusActive {
		t.Fatalf("admin ref = %+v", user)
	}
	scope, err := authz.GetPermissionScope(ctx, data.Admin.Guid, "devices.view")
	if err != nil {
		t.Fatalf("GetPermissionScope: %v", err)
	}
	if !scope.Global {
		t.Errorf("admin scope = %+v, want global", scope)
	}
}

// TestRBACStoresScopedPermission scoped 用户：授权码得组集、未授权码 403
// （文案逐字节）+ denied 审计落库。
func TestRBACStoresScopedPermission(t *testing.T) {
	ctx, db, data, authz, _ := openRBAC(t)

	scope, err := authz.GetPermissionScope(ctx, data.Scoped.Guid, "devices.view")
	if err != nil {
		t.Fatalf("GetPermissionScope: %v", err)
	}
	if scope.Global || len(scope.DeviceGroupGuids) != 1 {
		t.Fatalf("scoped scope = %+v, want {DG1}", scope)
	}
	if !scope.InDeviceGroup(data.DG1.Guid) || scope.InDeviceGroup(data.DG2.Guid) {
		t.Errorf("scope membership wrong: %+v", scope)
	}

	// devices.status 不在角色码内 → 403 Access denied + denied 审计。
	_, err = authz.RequirePermission(ctx, data.Scoped.Guid, "devices.status")
	var st *rbac.StatusError
	if !errors.As(err, &st) || st.Status != 403 || st.Message != "Access denied" {
		t.Fatalf("RequirePermission err = %v, want 403 Access denied", err)
	}
	rows := countAudits(t, db)
	if len(rows) != 1 || rows[0].Result != rbac.AuditResultDenied ||
		rows[0].Action != "devices.status" || rows[0].ActorUserGuid == nil ||
		*rows[0].ActorUserGuid != data.Scoped.Guid {
		t.Fatalf("denied audit rows = %+v", rows)
	}
}

// TestRBACStoresDisabledUser401 被禁用户在 RBAC 路由得 401 固定文案
// （共享知识 3：授权一律查库，不信任 JWT）。
func TestRBACStoresDisabledUser401(t *testing.T) {
	ctx, _, data, authz, _ := openRBAC(t)

	_, err := authz.RequirePermission(ctx, data.Disabled.Guid, "devices.view")
	var st *rbac.StatusError
	if !errors.As(err, &st) || st.Status != 401 || st.Message != "Account does not exist or has been disabled" {
		t.Fatalf("disabled user err = %v, want 401 fixed message", err)
	}
}

// TestRBACStoresSuperAdminGuard 双超管文案路线：RequireSuperAdmin 与
// RequireAdminGuard 文案逐字节不同。
func TestRBACStoresSuperAdminGuard(t *testing.T) {
	ctx, _, data, authz, _ := openRBAC(t)

	_, err := authz.RequireSuperAdmin(ctx, data.Scoped.Guid)
	var st *rbac.StatusError
	if !errors.As(err, &st) || st.Status != 403 || st.Message != "Super administrator permission required" {
		t.Fatalf("RequireSuperAdmin err = %v", err)
	}
	_, err = authz.RequireAdminGuard(ctx, data.Scoped.Guid)
	if !errors.As(err, &st) || st.Status != 403 || st.Message != "Access denied: administrator privileges required" {
		t.Fatalf("RequireAdminGuard err = %v", err)
	}
	// 超管放行。
	if _, err := authz.RequireSuperAdmin(ctx, data.Admin.Guid); err != nil {
		t.Errorf("admin RequireSuperAdmin: %v", err)
	}
	if _, err := authz.RequireAdminGuard(ctx, data.Admin.Guid); err != nil {
		t.Errorf("admin RequireAdminGuard: %v", err)
	}
}

// TestRBACStoresProtectedUser 保护账号判定走 assignments ⨝ roles 查库。
func TestRBACStoresProtectedUser(t *testing.T) {
	ctx, _, data, authz, _ := openRBAC(t)

	protected, err := authz.IsProtectedUser(ctx, data.Owner.Guid)
	if err != nil {
		t.Fatalf("IsProtectedUser(owner): %v", err)
	}
	if !protected {
		t.Error("owner should be protected via RoleProt")
	}
	plain, err := authz.IsProtectedUser(ctx, data.Scoped.Guid)
	if err != nil {
		t.Fatalf("IsProtectedUser(scoped): %v", err)
	}
	if plain {
		t.Error("scoped should not be protected")
	}
	// 批量保护映射。
	m, err := authz.GetEffectiveProtectionMap(ctx, []string{data.Owner.Guid, data.Scoped.Guid, data.Admin.Guid})
	if err != nil {
		t.Fatalf("GetEffectiveProtectionMap: %v", err)
	}
	if !m[data.Owner.Guid] || m[data.Scoped.Guid] || !m[data.Admin.Guid] {
		t.Errorf("protection map = %v, want owner+admin protected, scoped not", m)
	}
}

// TestRBACStoresAssertDeviceAccess 设备断言：scope 内放行、scope 外
// 403 Device is not in an authorized device group、未知设备 404 Device not found。
func TestRBACStoresAssertDeviceAccess(t *testing.T) {
	ctx, _, data, authz, _ := openRBAC(t)

	p, scope, err := authz.AssertDeviceAccess(ctx, data.Scoped.Guid, "devices.disconnect", data.PeerA.UUID)
	if err != nil {
		t.Fatalf("AssertDeviceAccess in-scope: %v", err)
	}
	if p.UUID != data.PeerA.UUID || scope.Global {
		t.Fatalf("assert result = %+v %+v", p, scope)
	}

	_, _, err = authz.AssertDeviceAccess(ctx, data.Scoped.Guid, "devices.disconnect", data.PeerC.UUID)
	var st *rbac.StatusError
	if !errors.As(err, &st) || st.Status != 403 || st.Message != "Device is not in an authorized device group" {
		t.Fatalf("out-of-scope err = %v", err)
	}

	_, _, err = authz.AssertDeviceAccess(ctx, data.Admin.Guid, "devices.disconnect", "uuid-not-exist")
	if !errors.As(err, &st) || st.Status != 404 || st.Message != "Device not found" {
		t.Fatalf("unknown device err = %v", err)
	}
}
