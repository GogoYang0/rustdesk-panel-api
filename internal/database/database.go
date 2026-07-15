// Package database 负责 GORM 双驱动连接（mysql / glebarez sqlite）。
// 纯 Go SQLite 驱动保证 CGO_ENABLED=0 静态编译。
package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Open 按 driver（mysql | sqlite）与 DSN 建立 GORM 连接并设置连接池参数。
// MySQL DSN 建议携带 parseTime=true&loc=Local（对齐 TypeORM 语义，
// 见 docker-compose.yml 示例）。
func Open(driver, dsn string) (*gorm.DB, error) {
	var dialector gorm.Dialector
	switch driver {
	case "mysql":
		dialector = gormmysql.Open(dsn)
	case "sqlite":
		dialector = sqlite.Open(dsn)
	default:
		return nil, fmt.Errorf("database: unsupported driver %q", driver)
	}
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("database: open %s failed: %w", driver, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("database: unwrap sql.DB failed: %w", err)
	}
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(time.Hour)
	// 内存库（testutil / 开发回退）多连接各自独立，必须收敛为单连接。
	if driver == "sqlite" && isMemoryDSN(dsn) {
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	}
	return db, nil
}

// isMemoryDSN 判断是否 sqlite 内存库 DSN。
func isMemoryDSN(dsn string) bool {
	return strings.Contains(dsn, ":memory:") || strings.Contains(dsn, "mode=memory")
}

// Ping 健康探测。
func Ping(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}
