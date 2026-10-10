// Package qa 本文件：M3 T05 兼容怪癖三件套字节级快照（设计 §8.17）。
//
// 字节级锁定对象（RustDesk 客户端硬依赖，逐字节不可偏差）：
//  1. GET /api/ab 空数据 → 裸 JSON null（4 字节，无引号、无换行）；
//  2. POST /api/ab 失败 → {error:msg} 且 HTTP 仍 200（仅此端点 try/catch）；
//  3. POST /api/ab/settings → {max_peer_one_ab:0}；
//  4. GET /api/ab 非空 → 双重 JSON 编码（data 为字符串内嵌 JSON，其内
//     tag_colors 再嵌一层 JSON 串，三重编码）。
//
// 这些断言与 internal/contract/addressbook_contract_test.go 的 schema
// 校验互补：契约测"形状"，本文件测"字节"。
package qa

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestM3CompatLegacyNull GET /api/ab 空数据返回裸 JSON null 字节
// （兼容怪癖第一件，§8.17-1，字节级锁定：不得是带引号的 "null" 字符串）。
func TestM3CompatLegacyNull(t *testing.T) {
	ts := newQAServer(t)
	token := mustLogin(t, ts, "databk", "databk")

	status, _, raw := doJSON(t, ts.TS.Client(), http.MethodGet, ts.TS.URL+"/api/ab", nil, authHeader(token))
	if status != http.StatusOK {
		t.Fatalf("GET /api/ab status = %d (body %s)", status, raw)
	}
	// 字节级锁定：body 必须恰好是裸 null（4 字节，无引号、无换行、无空白）。
	if string(raw) != "null" {
		t.Fatalf("GET /api/ab 空数据字节级不匹配: got %q, want %q", string(raw), "null")
	}
}

// TestM3CompatLegacyPostError200 POST /api/ab 失败返回 {error:msg} 且
// HTTP 仍 200（兼容怪癖第二件，§8.17-2，仅此端点 try/catch 语义）。
func TestM3CompatLegacyPostError200(t *testing.T) {
	ts := newQAServer(t)
	token := mustLogin(t, ts, "databk", "databk")

	// data 为非法 JSON 串 → 服务层返回 Invalid JSON data → handler 包装
	// 为 {error} 且 HTTP 200（非标准 400 包络）。
	body := map[string]string{"data": "this-is-not-json"}
	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/ab", body, authHeader(token))
	if status != http.StatusOK {
		t.Fatalf("POST /api/ab 失败态应恒 200, got %d (body %s)", status, raw)
	}
	// 字节级锁定：{error:"Invalid JSON data"}（WriteJSON 尾部含 \n）。
	got := strings.TrimRight(string(raw), "\n")
	want := `{"error":"Invalid JSON data"}`
	if got != want {
		t.Fatalf("POST /api/ab 失败包络字节级不匹配: got %q, want %q", got, want)
	}
	if msg, _ := parsed["error"].(string); msg != "Invalid JSON data" {
		t.Fatalf("POST /api/ab error 字段 = %v, want %q", parsed["error"], "Invalid JSON data")
	}
}

// TestM3CompatSettings POST /api/ab/settings 恒返回 {max_peer_one_ab:0}
// （兼容怪癖第三件，§8.17-3）。
func TestM3CompatSettings(t *testing.T) {
	ts := newQAServer(t)
	token := mustLogin(t, ts, "databk", "databk")

	status, parsed, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/ab/settings", nil, authHeader(token))
	if status != http.StatusOK {
		t.Fatalf("POST /api/ab/settings status = %d (body %s)", status, raw)
	}
	// 字节级锁定：{"max_peer_one_ab":0}（WriteJSON 尾部含 \n）。
	got := strings.TrimRight(string(raw), "\n")
	want := `{"max_peer_one_ab":0}`
	if got != want {
		t.Fatalf("POST /api/ab/settings 字节级不匹配: got %q, want %q", got, want)
	}
	if v, _ := parsed["max_peer_one_ab"].(float64); int(v) != 0 {
		t.Fatalf("max_peer_one_ab = %v, want 0", parsed["max_peer_one_ab"])
	}
}

// TestM3CompatDoubleJSON GET /api/ab 非空返回
// {licensed_devices:100, data:"<双重 JSON 编码>"}（data 内 tag_colors
// 又是一层 JSON 串，§8.17-1 双重/三重 JSON 字节级锁定）。
func TestM3CompatDoubleJSON(t *testing.T) {
	ts := newQAServer(t)
	token := mustLogin(t, ts, "databk", "databk")

	// 构造 legacy data 内层（data 本身是 JSON 串；tag_colors 再嵌一层
	// JSON 串，形成三重编码）。
	inner := map[string]any{
		"tags":       []string{"work"},
		"peers":      []any{},
		"tag_colors": `{"work":16711680}`,
	}
	innerBytes, err := json.Marshal(inner)
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	saveBody := map[string]string{"data": string(innerBytes)}
	status, _, raw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/ab", saveBody, authHeader(token))
	if status != http.StatusOK {
		t.Fatalf("POST /api/ab 保存 status = %d (body %s)", status, raw)
	}

	// 回读：GET /api/ab 应返回双重编码载荷。
	gstatus, parsed, graw := doJSON(t, ts.TS.Client(), http.MethodGet, ts.TS.URL+"/api/ab", nil, authHeader(token))
	if gstatus != http.StatusOK {
		t.Fatalf("GET /api/ab status = %d (body %s)", gstatus, graw)
	}

	// 第一层：licensed_devices 恒 100。
	if ld, _ := parsed["licensed_devices"].(float64); int(ld) != 100 {
		t.Fatalf("licensed_devices = %v, want 100", parsed["licensed_devices"])
	}

	// 第二层：data 必须是字符串（而非对象）——证明双重 JSON 编码。
	dataStr, ok := parsed["data"].(string)
	if !ok {
		t.Fatalf("data 字节级类型应为 string（双重编码），got %T: %v", parsed["data"], parsed["data"])
	}

	// 第三层：data 字符串内是 JSON 对象，含 tags/peers/tag_colors。
	var inner2 map[string]any
	if err := json.Unmarshal([]byte(dataStr), &inner2); err != nil {
		t.Fatalf("data 内层非合法 JSON（双重编码断裂）: %v (raw %s)", err, dataStr)
	}
	tags, _ := inner2["tags"].([]any)
	if len(tags) != 1 || tags[0] != "work" {
		t.Fatalf("inner tags = %v, want [work]", inner2["tags"])
	}
	if _, ok := inner2["peers"].([]any); !ok {
		t.Fatalf("inner peers 缺失或非数组: %v", inner2["peers"])
	}

	// 第四层：tag_colors 又是字符串内嵌 JSON（三重编码）——证明字节级
	// 嵌套 JSON 串未被展平。
	colorsStr, ok := inner2["tag_colors"].(string)
	if !ok {
		t.Fatalf("tag_colors 字节级类型应为 string（三重编码），got %T", inner2["tag_colors"])
	}
	var colors map[string]any
	if err := json.Unmarshal([]byte(colorsStr), &colors); err != nil {
		t.Fatalf("tag_colors 内层非合法 JSON（三重编码断裂）: %v (raw %s)", err, colorsStr)
	}
	if c, _ := colors["work"].(float64); int(c) != 16711680 {
		t.Fatalf("tag_colors.work = %v, want 16711680", colors["work"])
	}
}
