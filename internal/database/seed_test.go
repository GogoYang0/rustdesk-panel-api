package database

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/migration"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// TestSeedIdempotent 幂等种子：跑两次结果一致；管理员密码可 bcrypt 校验。
func TestSeedIdempotent(t *testing.T) {
	db := testutil.NewMemoryDB(t)
	m, err := migration.New(db, "sqlite")
	if err != nil {
		t.Fatalf("migration.New: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("migration.Up: %v", err)
	}
	ctx := context.Background()

	if err := Seed(ctx, db, "databk", "databk@github.com", "databk"); err != nil {
		t.Fatalf("Seed 1: %v", err)
	}
	if err := Seed(ctx, db, "databk", "databk@github.com", "databk"); err != nil {
		t.Fatalf("Seed 2 (idempotent): %v", err)
	}

	var groups []entity.UserGroup
	if err := db.Find(&groups).Error; err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(groups) != 1 || groups[0].NormalizedName != "default" || !groups[0].IsDefault {
		t.Fatalf("groups = %+v", groups)
	}

	var admins []entity.User
	if err := db.Where("isAdmin = ?", true).Find(&admins).Error; err != nil {
		t.Fatalf("list admins: %v", err)
	}
	if len(admins) != 1 {
		t.Fatalf("admin count = %d, want 1 (UQ_users_single_owner semantics)", len(admins))
	}
	admin := admins[0]
	if admin.Username != "databk" || admin.Email != "databk@github.com" || admin.Status != 1 {
		t.Errorf("admin = %+v", admin)
	}
	if admin.UserGroupGuid == nil || *admin.UserGroupGuid != groups[0].Guid {
		t.Errorf("admin group binding = %v, want %q", admin.UserGroupGuid, groups[0].Guid)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte("databk")); err != nil {
		t.Errorf("bcrypt verify failed: %v", err)
	}

	exists, err := SeedAdminExists(ctx, db)
	if err != nil || !exists {
		t.Errorf("SeedAdminExists = %v, %v", exists, err)
	}
}

// TestSeedEnvOverride 管理员账号可通过参数覆盖（批复事项 #5）。
func TestSeedEnvOverride(t *testing.T) {
	db := testutil.NewMemoryDB(t)
	m, _ := migration.New(db, "sqlite")
	if err := m.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if err := Seed(context.Background(), db, "boss", "boss@x.io", "boss-secret"); err != nil {
		t.Fatalf("Seed: %v", err)
	}
	var admin entity.User
	if err := db.Where("isAdmin = ?", true).First(&admin).Error; err != nil {
		t.Fatalf("query admin: %v", err)
	}
	if admin.Username != "boss" || admin.Email != "boss@x.io" {
		t.Errorf("admin = %+v", admin)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte("boss-secret")); err != nil {
		t.Errorf("bcrypt verify: %v", err)
	}
}
