package migration

import (
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// openMigrated 构建内存库与迁移运行器（不自动执行 Up）。
func openMigrated(t *testing.T) (*Migrator, *gorm.DB) {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	m, err := New(db, "sqlite")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m, db
}

// TestMigrateUpShowDown SQLite 迁移幂等往返（up → show → down → up）。
func TestMigrateUpShowDown(t *testing.T) {
	m, _ := openMigrated(t)

	if err := m.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}
	v, dirty, err := m.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v != 1 || dirty {
		t.Errorf("version = %d dirty = %v, want 1 false", v, dirty)
	}

	// 幂等：重复 Up 无错（ErrNoChange 视为成功）。
	if err := m.Up(); err != nil {
		t.Fatalf("second Up should be no-op: %v", err)
	}

	infos, err := m.Show()
	if err != nil {
		t.Fatalf("Show: %v", err)
	}
	if len(infos) != 1 || infos[0].Version != 1 || !infos[0].Applied || infos[0].Name != "m1_baseline" {
		t.Errorf("Show = %+v", infos)
	}

	// Down 全部回退：users 表应不存在。
	if err := m.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	v, _, err = m.Version()
	if err != nil {
		t.Fatalf("Version after down: %v", err)
	}
	if v != 0 {
		t.Errorf("version after down = %d, want 0", v)
	}
	if hasTable(t, m.dbForTest(), "users") {
		t.Error("users table should not exist after Down")
	}

	// 再 Up 恢复。
	if err := m.Up(); err != nil {
		t.Fatalf("re-Up: %v", err)
	}
	if !hasTable(t, m.dbForTest(), "users") {
		t.Error("users table should exist after re-Up")
	}
}

// TestMigrateColumnContract 逐表断言：迁移 SQL 实际列 == 实体 GORM tag 列
// （共享知识 11：实体 GORM tag 与迁移 SQL 逐列一致，附录 B 契约锚定）。
func TestMigrateColumnContract(t *testing.T) {
	m, db := openMigrated(t)
	if err := m.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	cases := map[string]any{
		"users":               entity.User{},
		"user_tokens":         entity.UserToken{},
		"login_sessions":      entity.LoginSession{},
		"passkey_credentials": entity.PasskeyCredential{},
		"user_groups":         entity.UserGroup{},
		"oidc_providers":      entity.OidcProvider{},
		"oidc_auth_states":    entity.OidcAuthState{},
	}
	for table, ent := range cases {
		t.Run(table, func(t *testing.T) {
			dbCols := actualColumns(t, db, table)
			entityCols := entityColumns(reflect.TypeOf(ent))
			for _, c := range entityCols {
				if !containsStr(dbCols, c) {
					t.Errorf("column %q in entity but not in migration SQL (db=%v)", c, dbCols)
				}
			}
			for _, c := range dbCols {
				if !containsStr(entityCols, c) {
					t.Errorf("column %q in migration SQL but not in entity (entity=%v)", c, entityCols)
				}
			}
		})
	}

	// 方言专属：owner_flag 生成列仅存在于 MySQL 方言，SQLite 不得出现。
	if containsStr(actualColumns(t, db, "users"), "owner_flag") {
		t.Error("owner_flag should only exist in mysql dialect")
	}
}

// TestMigrateSingleOwnerIndex SQLite partial unique index 生效性：
// 插入第二个管理员必须失败（UQ_users_single_owner）。
func TestMigrateSingleOwnerIndex(t *testing.T) {
	m, db := openMigrated(t)
	if err := m.Up(); err != nil {
		t.Fatalf("Up: %v", err)
	}

	insertAdmin := func(guid string) error {
		return db.Exec(`INSERT INTO users (guid, username, status, isAdmin) VALUES (?, ?, 1, 1)`, guid, "admin-"+guid).Error
	}
	if err := insertAdmin("00000000-0000-4000-8000-00000000a001"); err != nil {
		t.Fatalf("first admin insert: %v", err)
	}
	if err := insertAdmin("00000000-0000-4000-8000-00000000a002"); err == nil {
		t.Fatal("second admin insert should violate UQ_users_single_owner")
	}
	// 普通用户不受限。
	if err := db.Exec(`INSERT INTO users (guid, username, status, isAdmin) VALUES (?, ?, 1, 0)`,
		"00000000-0000-4000-8000-00000000a003", "normal").Error; err != nil {
		t.Fatalf("non-admin insert: %v", err)
	}
}

// dbForTest 暴露内部连接（仅测试）。
func (m *Migrator) dbForTest() *gorm.DB { return m.db }

// hasTable 检查表是否存在。
func hasTable(t *testing.T, db *gorm.DB, table string) bool {
	t.Helper()
	var count int64
	err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count).Error
	if err != nil {
		t.Fatalf("hasTable: %v", err)
	}
	return count > 0
}

// actualColumns 从 sqlite pragma 读取实际列名。
func actualColumns(t *testing.T, db *gorm.DB, table string) []string {
	t.Helper()
	var names []string
	if err := db.Raw("SELECT name FROM pragma_table_info(?)", table).Scan(&names).Error; err != nil {
		t.Fatalf("pragma_table_info(%s): %v", table, err)
	}
	return names
}

// entityColumns 反射实体 GORM tag 的 column:xxx（与迁移 SQL 比对）。
func entityColumns(t reflect.Type) []string {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	cols := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("gorm")
		for _, part := range strings.Split(tag, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "column:") {
				cols = append(cols, strings.TrimPrefix(part, "column:"))
			}
		}
	}
	return cols
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
