// dashboard_contract_test.go 仪表盘域契约用例（M3 T04）：overview
// 聚合口径（设计 §1.1⑥）与 trends 逐日序列（§10-9 批复：空日补 0）；
// 双端点 SuperAdmin 档（401/403）。时间敏感口径以"测试内直插今日
// 锚定行"规避 SeedM3 相对时刻跨午夜脆弱（下界断言锚定直插行）。
package contract

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// newDashboardContractServer 全栈契约服务器：真实路由 + 内存库 +
// SeedM3（内含 SeedM2 基座）；禁限流（本域端点无限流档）。
func newDashboardContractServer(t *testing.T) (*contractServer, *apptest.AppServer, *testutil.SeedM3Data) {
	t.Helper()
	as := apptest.NewAppServer(t, nil)
	seed := testutil.SeedM3(t, as.DB)
	cs := newContractServerWith(t, func() *server.Router {
		return server.NewRouter(server.RouterDeps{
			Logger:           testutil.TestLogger(),
			RateLimitEnabled: false,
			DB:               as.DB,
			Config:           as.Config,
		})
	})
	return cs, as, seed
}

// TestContractDashboardOverview overview 聚合口径（验收项⑤）：
// users/admin、devices(total/online=60s 窗口)、connections success/
// failure/today 下界、files 下界、counts（roles/strategies/addressBooks
// 精确 + groups=user_groups+device_groups 合并公式）、systemStatus 形状。
func TestContractDashboardOverview(t *testing.T) {
	cs, as, seed := newDashboardContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scoped := bearer(m2Token(t, as, seed.Scoped))

	// 403：SuperAdmin 档；401：匿名。
	cs.get(t, "/api/dashboard", scoped, http.StatusForbidden)
	cs.get(t, "/api/dashboard", nil, http.StatusUnauthorized)

	// 直插今日锚定行（success/failure 口径各一，规避跨午夜脆弱）。
	now := time.Now()
	est := now
	closed := now
	cid1 := "dash-c1"
	uidA := seed.PeerA.UUID
	if err := as.DB.Create(&entity.ConnectionAudit{
		DeviceId: "dash-ct", DeviceUuid: &uidA, ConnId: &cid1,
		Action:      entity.ConnActionEstablished,
		RequestedAt: now, EstablishedAt: &est, ClosedAt: &closed,
	}).Error; err != nil {
		t.Fatalf("seed success row: %v", err)
	}
	cid2 := "dash-c2"
	uidB := seed.PeerB.UUID
	if err := as.DB.Create(&entity.ConnectionAudit{
		DeviceId: "dash-ct", DeviceUuid: &uidB, ConnId: &cid2,
		Action: entity.ConnActionNew, RequestedAt: now, ClosedAt: &closed,
	}).Error; err != nil {
		t.Fatalf("seed failure row: %v", err)
	}

	raw := cs.get(t, "/api/dashboard", admin, http.StatusOK)
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("overview body not json: %v (%s)", err, raw)
	}

	// users：全栈场景 SeedM2 复用 databk 超管（UQ 单管理员索引）；
	// 用户 = databk + scoped/global/disabled/owner + pending = 6。
	users := resp["users"].(map[string]any)
	if users["admin"] != float64(1) {
		t.Errorf("users.admin = %v, want 1", users["admin"])
	}
	if users["total"] != float64(6) {
		t.Errorf("users.total = %v, want 6", users["total"])
	}

	// devices：PeerA/PeerB/PeerC；online=60s 窗口内心跳 + status=1
	//（PeerA/PeerB -10s 在线，PeerC -24h 离线）。
	devices := resp["devices"].(map[string]any)
	if devices["total"] != float64(3) {
		t.Errorf("devices.total = %v, want 3", devices["total"])
	}
	if devices["online"] != float64(2) {
		t.Errorf("devices.online = %v, want 2", devices["online"])
	}

	// connections：直插锚定行保证下界（success=双非空、failure=
	// closedAt 非空且 establishedAt 空、today=requestedAt 当日）。
	conns := resp["connections"].(map[string]any)
	if v, _ := conns["success"].(float64); v < 1 {
		t.Errorf("connections.success = %v, want >= 1", conns["success"])
	}
	if v, _ := conns["failure"].(float64); v < 1 {
		t.Errorf("connections.failure = %v, want >= 1", conns["failure"])
	}
	if v, _ := conns["today"].(float64); v < 2 {
		t.Errorf("connections.today = %v, want >= 2", conns["today"])
	}

	// files：SeedM3 FileA1（当日、type=0 upload）保证下界。
	files := resp["files"].(map[string]any)
	if v, _ := files["today"].(float64); v < 1 {
		t.Errorf("files.today = %v, want >= 1", files["today"])
	}
	if v, _ := files["upload"].(float64); v < 1 {
		t.Errorf("files.upload = %v, want >= 1", files["upload"])
	}

	// counts：种子精确值 + groups 合并公式（user_groups+device_groups）。
	counts := resp["counts"].(map[string]any)
	if counts["roles"] != float64(3) {
		t.Errorf("counts.roles = %v, want 3", counts["roles"])
	}
	if counts["strategies"] != float64(1) {
		t.Errorf("counts.strategies = %v, want 1", counts["strategies"])
	}
	if counts["addressBooks"] != float64(3) {
		t.Errorf("counts.addressBooks = %v, want 3", counts["addressBooks"])
	}
	var userGroupCount, deviceGroupCount int64
	if err := as.DB.Model(&entity.UserGroup{}).Count(&userGroupCount).Error; err != nil {
		t.Fatalf("count user_groups: %v", err)
	}
	if err := as.DB.Model(&entity.DeviceGroup{}).Count(&deviceGroupCount).Error; err != nil {
		t.Fatalf("count device_groups: %v", err)
	}
	if counts["groups"] != float64(userGroupCount+deviceGroupCount) {
		t.Errorf("counts.groups = %v, want %d (user_groups+device_groups)",
			counts["groups"], userGroupCount+deviceGroupCount)
	}

	// systemStatus：四键存在、百分比 ∈ [0,100]、uptime ≥ 0。
	ss := resp["systemStatus"].(map[string]any)
	for _, key := range []string{"cpu", "memory", "disk"} {
		v, ok := ss[key].(float64)
		if !ok || v < 0 || v > 100 {
			t.Errorf("systemStatus.%s = %v, want number in [0,100]", key, ss[key])
		}
	}
	if up, ok := ss["uptime"].(float64); !ok || up < 0 {
		t.Errorf("systemStatus.uptime = %v, want >= 0", ss["uptime"])
	}
}

// TestContractDashboardTrends trends 逐日序列：缺省 7d、range 档长度、
// 末项为今日且锚定行命中、非法 range 双防线 400。
func TestContractDashboardTrends(t *testing.T) {
	cs, as, seed := newDashboardContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scoped := bearer(m2Token(t, as, seed.Scoped))

	cs.get(t, "/api/dashboard/trends", scoped, http.StatusForbidden)
	cs.get(t, "/api/dashboard/trends", nil, http.StatusUnauthorized)

	// 直插今日锚定行（conn/alarm 各一；newUsers 由种子用户当日
	// createdAt 保证——SeedM2/SeedM3 用户 CreatedAt=now）。
	now := time.Now()
	today := now.Format("2006-01-02")
	uidTrend := "uuid-trend-conn"
	if err := as.DB.Create(&entity.ConnectionAudit{
		DeviceId: "trend-ct", DeviceUuid: &uidTrend, RequestedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed trend conn: %v", err)
	}
	if err := as.DB.Create(&entity.AlarmAudit{
		DeviceId: "trend-ct", DeviceUuid: "uuid-trend", Typ: 2, CreatedAt: now,
	}).Error; err != nil {
		t.Fatalf("seed trend alarm: %v", err)
	}

	raw := cs.get(t, "/api/dashboard/trends", admin, http.StatusOK)
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("trends body not json: %v (%s)", err, raw)
	}
	connTrend, _ := resp["connectionTrend"].([]any)
	userTrend, _ := resp["newUserTrend"].([]any)
	alarmTrend, _ := resp["alarmTrend"].([]any)
	if len(connTrend) != 7 || len(userTrend) != 7 || len(alarmTrend) != 7 {
		t.Fatalf("trend lengths = %d/%d/%d, want 7/7/7",
			len(connTrend), len(userTrend), len(alarmTrend))
	}

	// 逐项 date 为合法日期串；末项为今日且 count 命中锚定行。
	for i, item := range connTrend {
		d, _ := item.(map[string]any)["date"].(string)
		if _, err := time.Parse("2006-01-02", d); err != nil {
			t.Errorf("connectionTrend[%d].date = %q not YYYY-MM-DD", i, d)
		}
	}
	last := connTrend[len(connTrend)-1].(map[string]any)
	if last["date"] != today {
		t.Errorf("connectionTrend last date = %v, want %s", last["date"], today)
	}
	if v, _ := last["count"].(float64); v < 1 {
		t.Errorf("connectionTrend today count = %v, want >= 1", last["count"])
	}
	alarmLast := alarmTrend[len(alarmTrend)-1].(map[string]any)
	if v, _ := alarmLast["count"].(float64); v < 1 {
		t.Errorf("alarmTrend today count = %v, want >= 1", alarmLast["count"])
	}
	userLast := userTrend[len(userTrend)-1].(map[string]any)
	if v, _ := userLast["newUsers"].(float64); v < 1 {
		t.Errorf("newUserTrend today = %v, want >= 1", userLast["newUsers"])
	}

	// range 档长度。
	raw = cs.get(t, "/api/dashboard/trends?range=30d", admin, http.StatusOK)
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("trends(30d) body not json: %v", err)
	}
	connTrend, _ = resp["connectionTrend"].([]any)
	if len(connTrend) != 30 {
		t.Errorf("30d connectionTrend length = %d, want 30", len(connTrend))
	}
	raw = cs.get(t, "/api/dashboard/trends?range=90d", admin, http.StatusOK)
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("trends(90d) body not json: %v", err)
	}
	connTrend, _ = resp["connectionTrend"].([]any)
	if len(connTrend) != 90 {
		t.Errorf("90d connectionTrend length = %d, want 90", len(connTrend))
	}

	// 非法 range：spec enum 违规 + 服务端 400 双防线。
	cs.invalid(t, http.MethodGet, "/api/dashboard/trends?range=365d", nil, admin, http.StatusBadRequest)
}
