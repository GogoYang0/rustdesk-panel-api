// Package migration 是 golang-migrate 运行器：embed SQL 基线，
// 提供 Up / Down / Version / Show（对齐参考 db:migrate / db:show 语义）。
//
// 方言布局：migrations/{mysql,sqlite}/000001_m1_baseline.{up,down}.sql，
// 因 UQ_users_single_owner 的双方言实现（MySQL 生成列 vs SQLite partial
// unique index）无法用单文件表达，采用 golang-migrate 官方多方言目录。
package migration

import (
	"embed"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	mysqldriver "github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"gorm.io/gorm"
)

//go:embed migrations/mysql/*.sql migrations/sqlite/*.sql
var migrationsFS embed.FS

// ErrNoMigrations 无任何已执行迁移（Version 查询时）。
var ErrNoMigrations = errors.New("migration: no migrations applied")

// Migrator 迁移运行器（与 GORM 共享连接池）。
type Migrator struct {
	db     *gorm.DB
	driver string
}

// New 构建运行器；driver 为 mysql | sqlite。
func New(db *gorm.DB, driver string) (*Migrator, error) {
	if driver != "mysql" && driver != "sqlite" {
		return nil, fmt.Errorf("migration: unsupported driver %q", driver)
	}
	return &Migrator{db: db, driver: driver}, nil
}

// core 组装 golang-migrate 实例（source = embed iofs，database = 当前连接）。
func (m *Migrator) core() (*migrate.Migrate, error) {
	sqlDB, err := m.db.DB()
	if err != nil {
		return nil, fmt.Errorf("migration: unwrap sql.DB: %w", err)
	}
	switch m.driver {
	case "mysql":
		drv, err := mysqldriver.WithInstance(sqlDB, &mysqldriver.Config{})
		if err != nil {
			return nil, fmt.Errorf("migration: mysql driver: %w", err)
		}
		src, err := iofs.New(migrationsFS, "migrations/mysql")
		if err != nil {
			return nil, fmt.Errorf("migration: mysql source: %w", err)
		}
		return migrate.NewWithInstance("iofs", src, "mysql", drv)
	case "sqlite":
		// 绑定 glebarez 连接的自研适配层（避免 modernc "sqlite" 驱动重复注册，
		// 见 sqlitedriver.go 头注）。
		drv, err := newSqliteDriver(sqlDB, "")
		if err != nil {
			return nil, err
		}
		src, err := iofs.New(migrationsFS, "migrations/sqlite")
		if err != nil {
			return nil, fmt.Errorf("migration: sqlite source: %w", err)
		}
		return migrate.NewWithInstance("iofs", src, "sqlite", drv)
	default:
		return nil, fmt.Errorf("migration: unsupported driver %q", m.driver)
	}
}

// Up 执行全部待执行迁移（幂等：已在最新版时返回 ErrNoChange 视为成功）。
func (m *Migrator) Up() error {
	mig, err := m.core()
	if err != nil {
		return err
	}
	if err := mig.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migration: up: %w", err)
	}
	return nil
}

// Down 回退全部迁移（golang-migrate Down 语义 = migrate all the way down）。
func (m *Migrator) Down() error {
	mig, err := m.core()
	if err != nil {
		return err
	}
	if err := mig.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migration: down: %w", err)
	}
	return nil
}

// MigrationInfo 迁移状态条目。
type MigrationInfo struct {
	Version uint
	Name    string
	Applied bool
	Dirty   bool
}

// Version 返回当前版本；无迁移时返回 (0, false, nil)。
func (m *Migrator) Version() (uint, bool, error) {
	mig, err := m.core()
	if err != nil {
		return 0, false, err
	}
	v, dirty, err := mig.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("migration: version: %w", err)
	}
	return v, dirty, nil
}

// Show 列出全部迁移与其应用状态（对齐参考 db:show）。
func (m *Migrator) Show() ([]MigrationInfo, error) {
	current, _, err := m.Version()
	if err != nil {
		return nil, err
	}
	dir := "migrations/" + m.driver
	entries, err := migrationsFS.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("migration: read dir: %w", err)
	}
	out := make([]MigrationInfo, 0)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		base := strings.TrimSuffix(name, ".up.sql") // 如 000001_m1_baseline
		parts := strings.SplitN(base, "_", 2)
		v, pErr := strconv.ParseUint(parts[0], 10, 32)
		if pErr != nil {
			return nil, fmt.Errorf("migration: parse version from %q: %w", name, pErr)
		}
		display := ""
		if len(parts) > 1 {
			display = parts[1]
		}
		out = append(out, MigrationInfo{Version: uint(v), Name: display, Applied: uint(v) <= current})
	}
	return out, nil
}
