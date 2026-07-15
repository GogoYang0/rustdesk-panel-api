// Package testutil 提供测试基建：sqlite 内存库、测试配置、
// 迁移与 HTTP 测试服务器构建器（T03/T04 按域扩展）。
package testutil

import (
	"fmt"
	"log/slog"
	"testing"
	"uuid"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// NewMemoryDB 创建唯一命名的 sqlite 内存库（cache=shared 使多连接可见同一库），
// 并注册 t.Cleanup 关闭。
func NewMemoryDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:rp_%s?mode=memory&cache=shared", uuid.New().String())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		// 测试静默 GORM 日志，失败仍由断言暴露。
		Logger: gormlogger.Discard,
	})
	if err != nil {
		t.Fatalf("testutil: open memory sqlite failed: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("testutil: unwrap sql.DB failed: %v", err)
	}
	// 内存库必须单连接，避免多连接各见空库。
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// TestLogger 返回 discard 级别测试日志器（避免污染测试输出）。
func TestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

// discardWriter 丢弃全部写入。
type discardWriter struct{}

func (*discardWriter) Write(p []byte) (int, error) { return len(p), nil }
