// audit_contract_test.go 审计域契约用例（M3 T04 退出标准 ★）：上报
// 三端（Public + per-IP 50/min 档在路由声明）与查询六端以 openapi.yaml
// 为准绳做请求/响应双向校验（kin-openapi openapi3filter）。锁定：
//   - conn upsert action 迁移三态（'new' 首报 → 'open' → 'established'+
//     establishedAt，设计 §4.2）；
//   - note-only 模式定位改备注与 404 格式串；
//   - file/alarm UNIQUE(deviceId,nonce) 幂等重放；
//   - active 端 scope 过滤 + 行内 can_disconnect（设计事实②）；
//   - PATCH note 403（SuperAdmin 档）/ 404 / 400；
//   - console 查询（M2 console_audits 表查询端）过滤与行形状。
package contract

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// newAuditContractServer 全栈契约服务器：真实路由 + 内存库 + SeedM3
// （内含 SeedM2 基座）；禁 per-IP 限流避免上报用例挤兑 50/min 配额
// （限流档位由三方一致性声明锁定，行为由 qa 专项覆盖）。
func newAuditContractServer(t *testing.T) (*contractServer, *apptest.AppServer, *testutil.SeedM3Data) {
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

// auditList 解析审计分页响应 {data, total}。
func auditList(t *testing.T, raw []byte) ([]map[string]any, int) {
	t.Helper()
	var page struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatalf("page body not json: %v (%s)", err, raw)
	}
	return page.Data, page.Total
}

// auditRowBy 在 data 中按键值取行（未命中 Fatal）。
func auditRowBy(t *testing.T, rows []map[string]any, key, val string) map[string]any {
	t.Helper()
	for _, row := range rows {
		if fmt.Sprint(row[key]) == val {
			return row
		}
	}
	t.Fatalf("row %s=%s not found in %d rows", key, val, len(rows))
	return nil
}

// respMessage 取 MessageResponse.message。
func respMessage(t *testing.T, raw []byte) string {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("body not json: %v (%s)", err, raw)
	}
	msg, _ := resp["message"].(string)
	return msg
}

// TestContractAuditReportConnStateMachines conn upsert action 迁移三态
// 锁定（验收项②）：首报恒落 'new'（不采信报文值）→ 再报 'new' 迁移
// 'open' → 再报缺省 action（”）迁移 'established' + establishedAt。
func TestContractAuditReportConnStateMachines(t *testing.T) {
	cs, as, seed := newAuditContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	report := func(action any) {
		t.Helper()
		body := map[string]any{
			"id": "dev-ct", "uuid": "uuid-ct", "conn_id": 11,
			"ip": "10.1.1.9", "peer": []string{"900001", "alpha"}, "type": 1,
		}
		if action != nil {
			body["action"] = action
		}
		raw := cs.post(t, "/api/audit/conn", body, nil, http.StatusOK)
		if msg := respMessage(t, raw); msg != "Connection audit recorded successfully" {
			t.Errorf("message = %q", msg)
		}
	}
	connRow := func() map[string]any {
		t.Helper()
		rows, total := auditList(t, cs.get(t, "/api/audits/conn?uuid=uuid-ct&conn_id=11", admin, http.StatusOK))
		if total != 1 {
			t.Fatalf("rows total = %d, want 1", total)
		}
		return rows[0]
	}

	// ① 首报：INSERT，action 恒落 'new'（报文 action='new' 语义一致）。
	report("new")
	row := connRow()
	if row["action"] != "new" {
		t.Errorf("first action = %v, want new", row["action"])
	}
	if peer, ok := row["peer"].([]any); !ok || len(peer) != 2 || peer[0] != "900001" || peer[1] != "alpha" {
		t.Errorf("peer = %v, want [900001 alpha]", row["peer"])
	}

	// ② 再报 'new'：行迁移 'open'。
	report("new")
	if row = connRow(); row["action"] != "open" {
		t.Errorf("second action = %v, want open", row["action"])
	}

	// ③ 再报缺省 action（''）：迁移 'established' + establishedAt。
	report(nil)
	if row = connRow(); row["action"] != "established" {
		t.Errorf("third action = %v, want established", row["action"])
	}
	if row["established_at"] == nil {
		t.Error("established_at not set on '' transition")
	}
}

// TestContractAuditReportConnNoteOnly note-only 模式：无 uuid、有
// session_id+note → 定位既有行仅改备注；找不到 → 404 参考格式串。
func TestContractAuditReportConnNoteOnly(t *testing.T) {
	cs, as, seed := newAuditContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	// 常规上报带 session_id（该报文 action 缺省 → 行 established）。
	cs.post(t, "/api/audit/conn", map[string]any{
		"id": "dev-note", "uuid": "uuid-note", "conn_id": 12, "session_id": "sess-n1",
	}, nil, http.StatusOK)

	// note-only 上报：200 固定文案。
	raw := cs.post(t, "/api/audit/conn", map[string]any{
		"id": "dev-note", "session_id": "sess-n1", "note": "reviewed",
	}, nil, http.StatusOK)
	if msg := respMessage(t, raw); msg != "Connection audit recorded successfully" {
		t.Errorf("message = %q", msg)
	}

	// 行内 note 更新。
	rows, _ := auditList(t, cs.get(t, "/api/audits/conn?uuid=uuid-note", admin, http.StatusOK))
	row := auditRowBy(t, rows, "conn_id", "12")
	if row["note"] != "reviewed" {
		t.Errorf("note = %v, want reviewed", row["note"])
	}

	// note-only 找不到目标行 → 404（纯文本 message，参考格式串）。
	raw = cs.post(t, "/api/audit/conn", map[string]any{
		"id": "dev-none", "session_id": "sess-404", "note": "x",
	}, nil, http.StatusNotFound)
	if msg := respMessage(t, raw); msg != "Connection audit not found for deviceId=dev-none, sessionId=sess-404" {
		t.Errorf("404 message = %q", msg)
	}
}

// TestContractAuditReportFileNonceReplay file 上报：info JSON 解析
// （ip/name/num/files）与 UNIQUE(deviceId,nonce) 幂等重放。
func TestContractAuditReportFileNonceReplay(t *testing.T) {
	cs, as, seed := newAuditContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	body := func(num int, files string) map[string]any {
		return map[string]any{
			"id": "dev-fx", "uuid": "uuid-fx", "peer_id": "900001",
			"type": 0, "is_file": true, "path": "C:/tmp",
			"info":  fmt.Sprintf(`{"ip":"10.2.3.4","name":"win11","num":%d,"files":%s}`, num, files),
			"nonce": "nonce-fx-1", "conn_id": 13,
		}
	}

	raw := cs.post(t, "/api/audit/file", body(2, `["a.txt","b.txt"]`), nil, http.StatusOK)
	if msg := respMessage(t, raw); msg != "File audit recorded successfully" {
		t.Errorf("message = %q", msg)
	}

	rows, total := auditList(t, cs.get(t, "/api/audits/file?uuid=uuid-fx", admin, http.StatusOK))
	if total != 1 {
		t.Fatalf("file rows total = %d, want 1", total)
	}
	row := rows[0]
	if row["file_count"] != float64(2) {
		t.Errorf("file_count = %v, want 2", row["file_count"])
	}
	if row["client_ip"] != "10.2.3.4" || row["client_name"] != "win11" {
		t.Errorf("client = %v/%v, want 10.2.3.4/win11", row["client_ip"], row["client_name"])
	}
	// info 为解析后的 files 数组 JSON 文本。
	infoStr, ok := row["info"].(string)
	if !ok {
		t.Fatalf("info not string: %T", row["info"])
	}
	var files []any
	if err := json.Unmarshal([]byte(infoStr), &files); err != nil || len(files) != 2 {
		t.Errorf("files = %q (%v), want 2 items", infoStr, err)
	}

	// nonce 重放（同 deviceId+nonce、载荷不同）：幂等返回既有行。
	cs.post(t, "/api/audit/file", body(99, `[]`), nil, http.StatusOK)
	rows2, total2 := auditList(t, cs.get(t, "/api/audits/file?uuid=uuid-fx", admin, http.StatusOK))
	if total2 != 1 {
		t.Fatalf("replay rows total = %d, want 1 (idempotent)", total2)
	}
	if rows2[0]["file_count"] != float64(2) {
		t.Errorf("replay file_count = %v, want original 2", rows2[0]["file_count"])
	}
}

// TestContractAuditReportAlarmNonceReplay alarm 上报：info 解析
// （{id,ip,name} → 三列，查询时重建）与 nonce 幂等重放。
func TestContractAuditReportAlarmNonceReplay(t *testing.T) {
	cs, as, seed := newAuditContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))

	body := func(typ int) map[string]any {
		return map[string]any{
			"id": "dev-ax", "uuid": "uuid-ax", "typ": typ,
			"info":  `{"id":"ALM-1","ip":"10.2.3.5","name":"cpu spike"}`,
			"nonce": "nonce-ax-1", "conn_id": 14,
		}
	}

	raw := cs.post(t, "/api/audit/alarm", body(1), nil, http.StatusOK)
	if msg := respMessage(t, raw); msg != "Alarm audit recorded successfully" {
		t.Errorf("message = %q", msg)
	}

	rows, total := auditList(t, cs.get(t, "/api/audits/alarm?typ=1", admin, http.StatusOK))
	row := auditRowBy(t, rows, "nonce", "nonce-ax-1")
	var info map[string]any
	if err := json.Unmarshal([]byte(fmt.Sprint(row["info"])), &info); err != nil {
		t.Fatalf("alarm info not json: %v", err)
	}
	if info["id"] != "ALM-1" || info["ip"] != "10.2.3.5" || info["name"] != "cpu spike" {
		t.Errorf("alarm info = %v", info)
	}

	// 重放（同 nonce、typ 不同）：幂等返回既有行，typ 仍为 1。
	cs.post(t, "/api/audit/alarm", body(2), nil, http.StatusOK)
	_, total2 := auditList(t, cs.get(t, "/api/audits/alarm?typ=1", admin, http.StatusOK))
	if total2 != total {
		t.Errorf("replay total = %d, want %d (idempotent)", total2, total)
	}
}

// TestContractAuditQueryAuthAndConsole 查询端档位（401/403）与过滤、
// console 查询（M2 表查询端）行形状与 result/user_guid 过滤。
func TestContractAuditQueryAuthAndConsole(t *testing.T) {
	cs, as, seed := newAuditContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scoped := bearer(m2Token(t, as, seed.Scoped))

	// 401：无 token；403：Scoped 无 audit.view。
	cs.get(t, "/api/audits/conn", nil, http.StatusUnauthorized)
	cs.get(t, "/api/audits/conn", scoped, http.StatusForbidden)

	// SeedM3 五态行可见（Admin）。
	rows, total := auditList(t, cs.get(t, "/api/audits/conn", admin, http.StatusOK))
	if total < 5 {
		t.Fatalf("conn total = %d, want >= 5 (SeedM3 five states)", total)
	}
	auditRowBy(t, rows, "conn_id", "seed-c3")

	// uuid 过滤：SeedM3 连接行全部挂 PeerA。
	rows, _ = auditList(t, cs.get(t, "/api/audits/conn?uuid=seed-peer-a", admin, http.StatusOK))
	if len(rows) != 5 {
		t.Errorf("uuid filter rows = %d, want 5", len(rows))
	}

	// start/end 闭区间（UTC RFC3339 锚点）：[now-60min, now-45min]
	// 命中 connNew(-60min)/connFailed(-55min)/connOpen(-50min)，排除
	// connActive(-31min) 与 connClosed(-125min)。
	start := seed.Now.Add(-60 * time.Minute).UTC().Format(time.RFC3339)
	end := seed.Now.Add(-45 * time.Minute).UTC().Format(time.RFC3339)
	rows, _ = auditList(t, cs.get(t,
		"/api/audits/conn?uuid=seed-peer-a&start="+start+"&end="+end, admin, http.StatusOK))
	want := map[string]bool{"seed-c1": true, "seed-c5": true, "seed-c2": true}
	if len(rows) != len(want) {
		t.Errorf("time window rows = %v, want 3 rows", connIDs(rows))
	}
	for _, r := range rows {
		if !want[fmt.Sprint(r["conn_id"])] {
			t.Errorf("time window unexpected row %v", r["conn_id"])
		}
	}

	// 非法分页参数：spec integer 违规 + 服务端 400 双防线。
	cs.invalid(t, http.MethodGet, "/api/audits/conn?current=abc", nil, admin, http.StatusBadRequest)

	// ---- console 查询（M2 表）：直插样本锁定行形状 ----
	actor := seed.Scoped.Guid
	ca := &entity.ConsoleAudit{
		Guid: "seed-ca-ct", ActorUserGuid: &actor,
		TargetType: "role", TargetGuid: "seed-role-dev", Action: "role.update",
		Result: entity.AuditResultAllowed, Reason: "contract sample",
		BeforeState: `{"name":"a"}`, AfterState: `{"name":"b"}`, RequestID: "req-ct-1",
		CreatedAt: seed.Now,
	}
	if err := as.DB.Create(ca).Error; err != nil {
		t.Fatalf("seed console audit: %v", err)
	}

	rows, _ = auditList(t, cs.get(t, "/api/audits/console?result=allowed", admin, http.StatusOK))
	row := auditRowBy(t, rows, "guid", "seed-ca-ct")
	if row["result"] != "allowed" || row["target_type"] != "role" || row["action"] != "role.update" {
		t.Errorf("console row = %v", row)
	}
	if row["actor_user_guid"] != seed.Scoped.Guid || row["actor_user_name"] != seed.Scoped.Username {
		t.Errorf("actor = %v/%v, want %s/%s (LEFT JOIN username)",
			row["actor_user_guid"], row["actor_user_name"], seed.Scoped.Guid, seed.Scoped.Username)
	}
	before, ok := row["before_state"].(map[string]any)
	if !ok || before["name"] != "a" {
		t.Errorf("before_state = %v, want raw JSON object", row["before_state"])
	}

	// user_guid 过滤（测试期间 Scoped 的 403 决策亦落 denied 审计行，
	// 断言改为"包含直插样本"而非精确计数）。
	rows, _ = auditList(t, cs.get(t, "/api/audits/console?user_guid="+seed.Scoped.Guid, admin, http.StatusOK))
	found := false
	for _, r := range rows {
		if r["guid"] == "seed-ca-ct" {
			found = true
		}
	}
	if !found {
		t.Errorf("user_guid filter missing seeded row in %d rows", len(rows))
	}

	// result=denied 不含 allowed 行。
	rows, _ = auditList(t, cs.get(t, "/api/audits/console?result=denied", admin, http.StatusOK))
	for _, r := range rows {
		if r["guid"] == "seed-ca-ct" {
			t.Error("denied filter returned allowed row")
		}
	}
}

// connIDs 提取行集 conn_id 列表（断言输出用）。
func connIDs(rows []map[string]any) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, fmt.Sprint(row["conn_id"]))
	}
	return out
}

// TestContractAuditActiveScope active 端 scope 过滤与 can_disconnect
// （验收项③）：global 全见且恒可断连；组集 scope 仅见组内设备行。
func TestContractAuditActiveScope(t *testing.T) {
	cs, as, seed := newAuditContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scoped := bearer(m2Token(t, as, seed.Scoped))
	globalUser := bearer(m2Token(t, as, seed.Global))

	// 直插 scope 外活跃行：PeerC（DG2）与 PeerB（未分组）。
	now := seed.Now
	cidC := "c-out-c"
	uidC := seed.PeerC.UUID
	if err := as.DB.Create(&entity.ConnectionAudit{
		DeviceId: seed.PeerC.ID, DeviceUuid: &uidC, ConnId: &cidC,
		Action: entity.ConnActionEstablished, RequestedAt: now, EstablishedAt: &now,
	}).Error; err != nil {
		t.Fatalf("seed peerC active: %v", err)
	}
	cidB := "c-out-b"
	uidB := seed.PeerB.UUID
	if err := as.DB.Create(&entity.ConnectionAudit{
		DeviceId: seed.PeerB.ID, DeviceUuid: &uidB, ConnId: &cidB,
		Action: entity.ConnActionEstablished, RequestedAt: now, EstablishedAt: &now,
	}).Error; err != nil {
		t.Fatalf("seed peerB active: %v", err)
	}

	// Admin（global scope）：未关闭行全见（SeedM3 connNew/connOpen/
	// connActive + 直插 2 行）且 can_disconnect 恒 true。
	rows, _ := auditList(t, cs.get(t, "/api/audits/conn/active", admin, http.StatusOK))
	if len(rows) != 5 {
		t.Fatalf("admin active rows = %d, want 5", len(rows))
	}
	for _, row := range rows {
		if row["can_disconnect"] != true {
			t.Errorf("admin row %v can_disconnect = %v, want true", row["conn_id"], row["can_disconnect"])
		}
	}

	// Scoped（devices.disconnect @ DG1）：仅 PeerA 未关闭行
	// （connNew/connOpen/connActive）可见，行内可断连。
	rows, _ = auditList(t, cs.get(t, "/api/audits/conn/active", scoped, http.StatusOK))
	if len(rows) != 3 {
		t.Fatalf("scoped active rows = %v, want 3 (PeerA only)", connIDs(rows))
	}
	for _, row := range rows {
		if row["can_disconnect"] != true {
			t.Errorf("scoped row %v can_disconnect = %v, want true (in scope)", row["conn_id"], row["can_disconnect"])
		}
	}

	// Global 用户（仅 devices.view，无 disconnect）→ 403。
	cs.get(t, "/api/audits/conn/active", globalUser, http.StatusForbidden)
}

// TestContractAuditPatchNote PATCH /api/audits/conn/{id}（验收项④）：
// SuperAdmin 档 403、更新成功文案、404/400 错误路径。
func TestContractAuditPatchNote(t *testing.T) {
	cs, as, seed := newAuditContractServer(t)
	admin := bearer(m2Token(t, as, seed.Admin))
	scoped := bearer(m2Token(t, as, seed.Scoped))

	path := fmt.Sprintf("/api/audits/conn/%d", seed.ConnNew.Id)

	// 403：SuperAdmin 档（Scoped）。
	cs.patch(t, path, map[string]any{"note": "x"}, scoped, http.StatusForbidden)

	// 200：更新成功 + note 落库。
	raw := cs.patch(t, path, map[string]any{"note": "ops note"}, admin, http.StatusOK)
	if msg := respMessage(t, raw); msg != "Connection audit updated successfully" {
		t.Errorf("message = %q", msg)
	}
	var row entity.ConnectionAudit
	if err := as.DB.Where("id = ?", seed.ConnNew.Id).First(&row).Error; err != nil {
		t.Fatalf("reload conn row: %v", err)
	}
	if row.Note == nil || *row.Note != "ops note" {
		t.Errorf("note = %v, want ops note", row.Note)
	}

	// 404：不存在行（参考格式串）。
	raw = cs.patch(t, "/api/audits/conn/99999", map[string]any{"note": "x"}, admin, http.StatusNotFound)
	if msg := respMessage(t, raw); msg != "Connection audit not found for id=99999" {
		t.Errorf("404 message = %q", msg)
	}

	// 400：id=0（契约整数合法，服务端业务校验拒绝）。
	cs.patch(t, "/api/audits/conn/0", map[string]any{"note": "x"}, admin, http.StatusBadRequest)
}
