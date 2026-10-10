// Package apptest 提供全栈 HTTP 测试服务器（集成/契约测试共用基建）。
//
// 独立子包原因：AppServer 组装完整路由需依赖 internal/server，若置于
// testutil 根包，会使依赖 testutil 的各域内部测试（repository/migration/
// database）经由 server 反向依赖形成 import cycle。
package apptest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/database"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/migration"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// AppServer 全栈测试服务器：内存库 + 迁移种子 + 完整路由 +
// 真实 TokenService（集成/契约测试共用基建）。
type AppServer struct {
	DB     *gorm.DB
	TS     *httptest.Server
	Config config.Config
	Router *server.Router
}

// NewAppServer 构建并启动全栈服务器。
//
// 监听地址固定 127.0.0.1 随机端口（WebAuthn origins 依此推导）；
// mutate 可在装配前调整配置（JWT 有效期、限流开关等）。
func NewAppServer(t *testing.T, mutate func(*config.Config)) *AppServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("apptest: listen failed: %v", err)
	}
	cfg := config.Config{
		HTTPAddr:      l.Addr().String(),
		DBDriver:      "sqlite",
		JWTSecret:     "test-secret-key",
		JWTExpiryDays: 30,
		DataDir:       t.TempDir(),
		// go-webauthn 校验 RPID 必须为域名（拒绝 IP）；
		// 测试用假域名即可，rpIdHash 由 SoftAuthenticator 以同一 RPID 计算。
		WebAuthnRPID:     "panel.test",
		WebAuthnOrigins:  []string{"http://" + l.Addr().String()},
		AdminUsername:    "databk",
		AdminEmail:       "databk@github.com",
		AdminPassword:    "databk",
		RateLimitEnabled: true,
		LogLevel:         "error",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	db := testutil.NewMemoryDB(t)
	m, err := migration.New(db, "sqlite")
	if err != nil {
		t.Fatalf("apptest: build migrator failed: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("apptest: migrate up failed: %v", err)
	}
	if err := database.Seed(context.Background(), db, cfg.AdminUsername, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		t.Fatalf("apptest: seed failed: %v", err)
	}
	rt := server.NewRouter(server.RouterDeps{
		Logger:           testutil.TestLogger(),
		RateLimitEnabled: cfg.RateLimitEnabled,
		DB:               db,
		Config:           cfg,
	})
	// 手工构造 httptest.Server 以接管已监听的端口，Config 必须显式初始化。
	ts := &httptest.Server{Listener: l, Config: &http.Server{ReadHeaderTimeout: 10 * time.Second}}
	ts.Config.Handler = rt.Handler()
	ts.Start()
	t.Cleanup(ts.Close)
	return &AppServer{DB: db, TS: ts, Config: cfg, Router: rt}
}
