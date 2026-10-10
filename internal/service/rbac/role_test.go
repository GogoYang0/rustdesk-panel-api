// role_test.go 角色域服务单测（T05 验收锁定项）：取消保护 confirm 门槛
// 与角色删除全量快照审计内容（beforeState 含 assignments+groups、
// afterState=null、级联删净）。
package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	rbaccore "github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// newRoleService 构建角色服务 + 全套仓储（Delete/Update 路径不触
// authz，可传 nil）。
func newRoleService(t *testing.T) (*RoleService, *gorm.DB) {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	testutil.MigrateUpForTest(t, db)
	svc := NewRoleService(nil, db,
		repository.NewRoleRepo(db),
		repository.NewRolePermissionRepo(db),
		repository.NewAssignmentRepo(db),
		repository.NewAssignmentGroupRepo(db),
		repository.NewConsoleAuditRepo(db))
	return svc, db
}

// TestUpdateUnprotectRequiresConfirm 取消保护（true→false）须显式
// confirm_protected_account_change=true；未确认时 400 且角色不变。
func TestUpdateUnprotectRequiresConfirm(t *testing.T) {
	ctx := context.Background()
	svc, db := newRoleService(t)
	now := time.Now()
	role := &entity.Role{Guid: uuid.NewString(), Name: "protected", ProtectedAccount: true, CreatedAt: now, UpdatedAt: now}
	if err := db.Create(role).Error; err != nil {
		t.Fatalf("seed role: %v", err)
	}
	fetch := func() entity.Role {
		var got entity.Role
		if err := db.Where("guid = ?", role.Guid).First(&got).Error; err != nil {
			t.Fatalf("reload: %v", err)
		}
		return got
	}

	// 未 confirm：400 + 角色保持保护。
	f := false
	_, err := svc.Update(ctx, "actor", role.Guid, dto.RoleUpdateRequest{ProtectedAccount: &f})
	if err == nil {
		t.Fatal("unprotect without confirm must fail")
	}
	var se *rbaccore.StatusError
	if !errors.As(err, &se) || se.Status != 400 {
		t.Fatalf("err = %v, want 400 StatusError", err)
	}
	if se.Message != msgConfirmUnprotect {
		t.Errorf("message = %q, want %q", se.Message, msgConfirmUnprotect)
	}
	if got := fetch(); !got.ProtectedAccount {
		t.Error("role must stay protected after rejected update")
	}

	// 带 confirm：成功取消保护。
	if _, err := svc.Update(ctx, "actor", role.Guid, dto.RoleUpdateRequest{ProtectedAccount: &f, ConfirmProtectedAccountChange: true}); err != nil {
		t.Fatalf("unprotect with confirm: %v", err)
	}
	if got := fetch(); got.ProtectedAccount {
		t.Error("role must be unprotected after confirmed update")
	}

	// 升保护（false→true）不需要 confirm。
	tr := true
	if _, err := svc.Update(ctx, "actor", role.Guid, dto.RoleUpdateRequest{ProtectedAccount: &tr}); err != nil {
		t.Fatalf("protect without confirm: %v", err)
	}
	if got := fetch(); !got.ProtectedAccount {
		t.Error("role must be protected after promote update")
	}
}

// TestDeleteSnapshotAudit 删除角色：beforeState 全量快照（含角色、
// permissions、assignments、device_group_guids）、afterState=null、
// result=allowed；级联删净三张关联表。
func TestDeleteSnapshotAudit(t *testing.T) {
	ctx := context.Background()
	svc, db := newRoleService(t)
	now := time.Now()

	role := &entity.Role{Guid: uuid.NewString(), Name: "doomed", Note: "n", CreatedAt: now, UpdatedAt: now}
	perm1 := &entity.RolePermission{RoleGuid: role.Guid, PermissionCode: "devices.view"}
	perm2 := &entity.RolePermission{RoleGuid: role.Guid, PermissionCode: "devices.disconnect"}
	holder := &entity.User{Guid: "user-1", Username: "holder", Email: "holder@example.com", Status: 1, CreatedAt: now, UpdatedAt: now}
	group := &entity.DeviceGroup{Guid: "dg-1", Name: "dg", CreatedAt: now, UpdatedAt: now}
	asg := &entity.UserRoleAssignment{Guid: "asg-1", UserGuid: holder.Guid, RoleGuid: role.Guid, ScopeType: entity.ScopeTypeDeviceGroup, CreatedAt: now, UpdatedAt: now}
	link := &entity.UserRoleAssignmentDeviceGroup{AssignmentGuid: asg.Guid, DeviceGroupGuid: group.Guid}
	for _, row := range []any{role, perm1, perm2, holder, group, asg, link} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	if err := svc.Delete(ctx, "actor-1", role.Guid); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// 角色与关联行全部删净（各表按自身键过滤）。
	count := func(table, col, val string) int64 {
		t.Helper()
		var n int64
		if err := db.Table(table).Where(col+" = ?", val).Count(&n).Error; err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n
	}
	for _, tc := range []struct{ table, col, val string }{
		{"roles", "guid", role.Guid},
		{"role_permissions", "roleGuid", role.Guid},
		{"user_role_assignments", "roleGuid", role.Guid},
		{"user_role_assignment_device_groups", "assignmentGuid", asg.Guid},
	} {
		if n := count(tc.table, tc.col, tc.val); n != 0 {
			t.Errorf("%s residual rows = %d, want 0", tc.table, n)
		}
	}

	// 审计行：allowed + before/after 快照。
	var rec entity.ConsoleAudit
	if err := db.Where("targetType = ? AND targetGuid = ?", "role", role.Guid).
		Order("createdAt DESC").First(&rec).Error; err != nil {
		t.Fatalf("audit row missing: %v", err)
	}
	if rec.Result != "allowed" || rec.Action != auditActionDelete {
		t.Errorf("audit = %s/%s, want allowed/%s", rec.Result, rec.Action, auditActionDelete)
	}
	if rec.ActorUserGuid == nil || *rec.ActorUserGuid != "actor-1" {
		t.Errorf("actor = %v, want actor-1", rec.ActorUserGuid)
	}
	if rec.AfterState != stateNull {
		t.Errorf("afterState = %q, want %q", rec.AfterState, stateNull)
	}

	var before struct {
		Role struct {
			Guid             string   `json:"guid"`
			Permissions      []string `json:"permissions"`
			ProtectedAccount bool     `json:"protected_account"`
		} `json:"role"`
		Assignments []struct {
			UserGuid         string   `json:"user_guid"`
			ScopeType        string   `json:"scope_type"`
			DeviceGroupGuids []string `json:"device_group_guids"`
		} `json:"assignments"`
	}
	if err := json.Unmarshal([]byte(rec.BeforeState), &before); err != nil {
		t.Fatalf("beforeState not json: %v (%s)", err, rec.BeforeState)
	}
	if before.Role.Guid != role.Guid || len(before.Role.Permissions) != 2 {
		t.Errorf("before.role = %+v", before.Role)
	}
	if len(before.Assignments) != 1 {
		t.Fatalf("before.assignments = %+v, want 1 row", before.Assignments)
	}
	asm := before.Assignments[0]
	if asm.UserGuid != holder.Guid || asm.ScopeType != entity.ScopeTypeDeviceGroup ||
		len(asm.DeviceGroupGuids) != 1 || asm.DeviceGroupGuids[0] != group.Guid {
		t.Errorf("assignment snapshot = %+v", asm)
	}
	if !strings.Contains(rec.BeforeState, "device_group_guids") {
		t.Error("beforeState must contain device_group_guids key")
	}
}
