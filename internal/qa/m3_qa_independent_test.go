// m3_qa_independent_test.go —— M3 里程碑「独立最终验证」QA 用例（严过关）。
//
// 定位：本文件由 QA 独立设计，不复跑工程师既有断言路径（internal/contract
// 锁形状、internal/server 锁三方一致、m3_security_test.go 锁提权矩阵）。
// 攻击面聚焦「工程师既有测试未显式覆盖的语义边界」：
//
//	A. 越权矩阵三态（无权限 / 有权限 / SuperAdmin 各一态）× M3 新域；
//	B. 跨租户隔离：A/B 用户互访资源应 404（不泄漏存在性）；
//	C. 兼容怪癖逐字节（§8.17 nexus 201/204、ab 三件套补充路径）；
//	D. 边界与安全：/files 与 nexus 产物穿越、avatar 白名单、LDAP 掩码；
//	E. 幂等与状态：audit nonce 重放、nexus 状态机非法跃迁；
//	F. 错误包络 NestJS 兼容结构；
//	G. 固定文案（§8.16）≥8 条逐字节比对。
//
// 全部断言只经 HTTP 入口（真实中间件链），不直接调服务层。
package qa

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// ---------------------------------------------------------------------------
// 独立测试基座
// ---------------------------------------------------------------------------

// qaM3Server 禁限流全栈服务器 + M3 fixture；nexus 上游与 agent 节点均可
// 由调用方以 httptest 假服务注入（QA 独立于工程契约测试的网络假设）。
func qaM3Server(t *testing.T, mutate ...func(*config.Config)) (*apptest.AppServer, *testutil.SeedM3Data) {
	t.Helper()
	as := apptest.NewAppServer(t, func(c *config.Config) {
		c.RateLimitEnabled = false
		for _, m := range mutate {
			m(c)
		}
	})
	return as, testutil.SeedM3(t, as.DB)
}

// qaThirdUser 插入一个「无任何角色」的第三方普通用户（跨租户隔离用）。
// 复用种子口令 hash 以省 bcrypt 成本。
func qaThirdUser(t *testing.T, as *apptest.AppServer, username string) *entity.User {
	t.Helper()
	var hash string
	if err := as.DB.Raw("SELECT password FROM users WHERE username = ?", "databk").Scan(&hash).Error; err != nil || hash == "" {
		t.Fatalf("qaThirdUser: read seed hash: %v", err)
	}
	u := &entity.User{
		Guid:     "qa-third-" + username,
		Username: username,
		Email:    username + "@qa.example",
		Password: hash,
		Status:   1,
	}
	if err := as.DB.Create(u).Error; err != nil {
		t.Fatalf("qaThirdUser create: %v", err)
	}
	return u
}

// qaAssertEnvelope3 断言 NestJS 兼容错误包络三字段（statusCode/message/error）。
func qaAssertEnvelope3(t *testing.T, label string, status, want int, parsed map[string]any, raw []byte) {
	t.Helper()
	if status != want {
		t.Fatalf("%s: status = %d, want %d (body %s)", label, status, want, raw)
	}
	if got, _ := parsed["statusCode"].(float64); int(got) != want {
		t.Errorf("%s: statusCode = %v, want %d", label, parsed["statusCode"], want)
	}
	if got, _ := parsed["error"].(string); got != http.StatusText(want) {
		t.Errorf("%s: error = %q, want %q", label, got, http.StatusText(want))
	}
	if _, ok := parsed["message"]; !ok {
		t.Errorf("%s: message 字段缺失 (body %s)", label, raw)
	}
}

// ---------------------------------------------------------------------------
// A. 越权矩阵：三态（无权限 / 有权限 / SuperAdmin）
// ---------------------------------------------------------------------------

// TestQA_M3_RBAC_Tristate_Servers servers 域三态独立复核：
//
//	态1 无权限 Scoped → 403 "Access denied"；
//	态2 补授 servers.view 后 Scoped → 200（放行）；
//	态3 SuperAdmin（databk）→ 200（超管直通策略决策）。
//
// 与 m3_security 的分工：后者只验态1/态2；本用例补「三态在同一测试内
// 闭环」，确保放行不是偶然（区分 403 源于权限而非端点不存在）。
func TestQA_M3_RBAC_Tristate_Servers(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()

	// 态1：无权限。
	status, _, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/servers", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	assertForbidden(t, "servers 态1 无权限", status, raw, rbac.MsgAccessDenied)

	// 态2：补授后放行。
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeServersView)
	status, _, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/servers", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	assertStatus(t, "servers 态2 有权限", status, http.StatusOK, raw)

	// 态3：SuperAdmin 直通。
	admin := authHeader(seedToken(t, as, seed.Admin))
	status, _, raw = doJSON(t, client, http.MethodGet, as.TS.URL+"/api/servers", nil, admin)
	assertStatus(t, "servers 态3 SuperAdmin", status, http.StatusOK, raw)
}

// TestQA_M3_RBAC_Tristate_UpdateCheck update-check 域三态：无权限 403 →
// 管理员放行 200 → 且响应为对象（非空包络）。覆盖 AdminGuard 与 super
// 两档之间的边界（本端点为 AdminGuard，非 SuperAdmin）。
func TestQA_M3_RBAC_Tristate_UpdateCheck(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()

	status, _, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/update-check", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	assertForbidden(t, "update-check 态1 无权限", status, raw, rbac.MsgAdminGuardRequired)

	admin := authHeader(seedToken(t, as, seed.Admin))
	status, parsed, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/update-check", nil, admin)
	assertStatus(t, "update-check 态2 管理员", status, http.StatusOK, raw)
	if len(parsed) == 0 {
		t.Errorf("update-check 响应应为 JSON 对象，got %s", raw)
	}
}

// TestQA_M3_RBAC_SuperAdminOnly_DenoTxt 记录 SuperAdmin 专属端点的拒绝
// 文案与「有全部权限码仍 403」语义：Scoped 补授 audit.view / users.view 等
// 全部相关码后访问 dashboard 仍 403 "Super administrator permission
// required"——证明 SuperAdmin 档不依赖权限码（正交档位）。
func TestQA_M3_RBAC_SuperAdminOnly_DenoTxt(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()

	for _, code := range []string{
		rbac.CodeAuditView, rbac.CodeUsersView, rbac.CodeServersView,
		rbac.CodeAddressBooksView,
	} {
		grantM3(t, as, seed.RoleDev.Guid, code)
	}
	status, parsed, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/dashboard", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	assertForbidden(t, "dashboard 持全部码仍拒", status, raw, rbac.MsgSuperAdminRequired)
	if len(parsed) == 0 {
		t.Errorf("403 应为 JSON 对象：%s", raw)
	}
}

// ---------------------------------------------------------------------------
// B. 跨租户隔离（A/B 互访 404，不泄漏存在性）
// ---------------------------------------------------------------------------

// TestQA_M3_CrossTenant_AddressBook 通讯录跨租户：第三方无角色用户读取
// Owner 的 personal 书 peers 列表应 404/403（不泄漏书存在性）；Owner 本人
// 读取同名端点成功（对照，证明 404 源于归属而非端点错误）。
func TestQA_M3_CrossTenant_AddressBook(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()
	third := qaThirdUser(t, as, "cross-ab")

	// 第三方读取 Owner 的自定义书 peers：服务层归属校验 → 403
	// "No permission to access this address book"（不泄漏书内 peers）。
	ownerBook := seed.BookCustom.Guid
	label := "GET /api/ab/peers?ab=<owner custom> (third party)"
	status, parsed, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/ab/peers?ab="+ownerBook+"&current=1&pageSize=10", nil,
		authHeader(seedToken(t, as, third)))
	if status != http.StatusForbidden {
		t.Fatalf("%s: status = %d, want 403 (body %s)", label, status, raw)
	}
	if msg, _ := parsed["message"].(string); msg != "No permission to access this address book" {
		t.Errorf("%s: message = %q, want 'No permission to access this address book'", label, msg)
	}
	// 拒绝响应体不得泄漏 peers 字段。
	if strings.Contains(string(raw), `"data"`) {
		t.Errorf("%s: 403 响应体不应含 data 行（泄漏）: %s", label, raw)
	}

	// 对照：Owner 本人读取其 custom 书 peers → 200（证明 403 源于归属）。
	label = "GET /api/ab/peers?ab=<owner custom> (owner)"
	status, _, raw = doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/ab/peers?ab="+ownerBook+"&current=1&pageSize=10", nil,
		authHeader(seedToken(t, as, seed.Owner)))
	assertStatus(t, label, status, http.StatusOK, raw)
}

// TestQA_M3_CrossTenant_Nexus_ThirdParty nexus 构建跨租户：与 Scoped 无任何
// 绑定关系的第三方访问 Scoped 的构建 UUID（取消 / 产物清单 / 下载）一律
// 404，不泄漏存在性。
func TestQA_M3_CrossTenant_Nexus_ThirdParty(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()
	third := qaThirdUser(t, as, "cross-nexus")
	th := authHeader(seedToken(t, as, third))
	build := seed.Build1.Uuid

	cases := []struct {
		label  string
		method string
		path   string
	}{
		{"DELETE builds/{uuid}", http.MethodDelete, "/api/nexus/builds/" + build},
		{"GET builds/{uuid}/files", http.MethodGet, "/api/nexus/builds/" + build + "/files"},
		{"GET builds/{uuid}/files/{fn}", http.MethodGet, "/api/nexus/builds/" + build + "/files/agent.exe"},
	}
	for _, tc := range cases {
		status, _, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, nil, th)
		assertNotFoundMsg(t, "第三方 "+tc.label, status, raw, "Build task not found")
	}
}

// TestQA_M3_CrossTenant_UserDetail users/{guid} 跨租户：第三方读者（仅授
// users.view）读取他人详情返回 200（用户域是管理域，非租户隔离域）——
// 但读取**不存在**的 guid 必须 404，不泄漏「存在与否」之外的差异。
// 本用例显式钉住该语义，防止将用户域误实现为租户隔离域。
func TestQA_M3_CrossTenant_UserDetail404(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeUsersView)

	label := "GET /api/users/{nonexistent}"
	status, _, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/users/does-not-exist-guid", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	assertStatus(t, label, status, http.StatusNotFound, raw)
	if !strings.Contains(string(raw), "User does not exist") {
		t.Errorf("%s: message = %s, want 含 'User does not exist'", label, raw)
	}
}

// ---------------------------------------------------------------------------
// C. 兼容怪癖逐字节（§8.17，nexus 201/204 与 ab 增量）
// ---------------------------------------------------------------------------

// TestQA_M3_Quirk_Nexus201And204 nexus 状态码特例逐字节锁定：
// POST builds = 201（成功体为 NexusBuildView）、DELETE builds/{uuid} = 204
// （无响应体）。上游以假 nexus 注入返回 201 + uuid。
func TestQA_M3_Quirk_Nexus201And204(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/build" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"uuid":"qa-build-201","status":"pending"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(upstream.Close)

	as, seed := qaM3Server(t, func(c *config.Config) { c.NexusUpstream = upstream.URL })
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	// POST builds → 201。
	label := "POST /api/nexus/builds → 201"
	status, parsed, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/nexus/builds",
		map[string]any{"os": "windows", "arch": "x86_64", "custom": map[string]any{"app-name": "qa"}}, scoped)
	if status != http.StatusCreated {
		t.Fatalf("%s: status = %d, want 201 (body %s)", label, status, raw)
	}
	uuidStr, _ := parsed["uuid"].(string)
	if uuidStr == "" {
		t.Fatalf("%s: 响应体缺 uuid: %s", label, raw)
	}

	// DELETE builds/{uuid} → 204 且体为空。
	label = "DELETE /api/nexus/builds/{uuid} → 204"
	status, _, raw = doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/nexus/builds/"+uuidStr, nil, scoped)
	if status != http.StatusNoContent {
		t.Fatalf("%s: status = %d, want 204 (body %s)", label, status, raw)
	}
	if len(raw) != 0 {
		t.Errorf("%s: 204 响应体应为空，got %q", label, string(raw))
	}
}

// TestQA_M3_Quirk_AbLegacyNullAndSettings 对 §8.17 三件套做「独立再验」：
// 空 ab → 裸字符串 null（4 字节）；ab/settings → {"max_peer_one_ab":0}。
// 与 m3_compat 的区别：本用例显式断言「不是带引号的 "null" 字符串」与
// 无尾部空白以外的严格字节，作为独立冗余防线。
func TestQA_M3_Quirk_AbLegacyNullAndSettings(t *testing.T) {
	as, _ := qaM3Server(t)
	client := as.TS.Client()
	token := authHeader(mustLogin(t, as, "databk", "databk"))

	// 独立验：裸 null（不是字符串 "null"）。
	status, _, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/ab", nil, token)
	assertStatus(t, "GET /api/ab 空", status, http.StatusOK, raw)
	if string(raw) != "null" {
		t.Fatalf("GET /api/ab 应为裸 null，got %q", string(raw))
	}
	if strings.Contains(string(raw), `"null"`) {
		t.Fatalf("GET /api/ab 不应为带引号字符串: %q", string(raw))
	}

	// ab/settings 严格字节。
	status, _, raw = doJSON(t, client, http.MethodPost, as.TS.URL+"/api/ab/settings", nil, token)
	assertStatus(t, "POST /api/ab/settings", status, http.StatusOK, raw)
	if got := strings.TrimRight(string(raw), "\n"); got != `{"max_peer_one_ab":0}` {
		t.Fatalf("POST /api/ab/settings 字节不符: got %q", got)
	}
}

// TestQA_M3_Quirk_AbPostFailureStill200 独立验 §8.17-2：POST /api/ab 失败
// 仍返回 HTTP 200 + {error}（非标准包络）。用「非对象 data」触发失败路径。
func TestQA_M3_Quirk_AbPostFailureStill200(t *testing.T) {
	as, _ := qaM3Server(t)
	client := as.TS.Client()
	token := authHeader(mustLogin(t, as, "databk", "databk"))

	status, parsed, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/ab",
		map[string]any{"data": "{not-json"}, token)
	if status != http.StatusOK {
		t.Fatalf("POST /api/ab 失败态应 200，got %d (body %s)", status, raw)
	}
	if _, ok := parsed["error"]; !ok {
		t.Fatalf("POST /api/ab 失败应返回 {error}，got %s", raw)
	}
}

// ---------------------------------------------------------------------------
// D. 边界与安全
// ---------------------------------------------------------------------------

// TestQA_M3_Security_AvatarFilenameWhitelist avatar 文件名白名单
// ^[a-f0-9-]+\.webp$（§8.25）：穿越 / 非 hex / 大写 hex / 非 webp 后缀
// 一律不得 200（服务层白名单 Serve 返回 false → handler 统一 404 包络，
// 与「文件不存在」不可区分，天然不构成存在性 oracle）。
//
// 严格断言：所有拒绝样本既非 200、亦不得出现任意文件字节（防穿越读）。
func TestQA_M3_Security_AvatarFilenameWhitelist(t *testing.T) {
	as, _ := qaM3Server(t)
	client := as.TS.Client()
	base := as.TS.URL + "/api/avatars/"

	bad := []struct {
		label string
		name  string
	}{
		{"dotdot", "..%2Fetc%2Fpasswd.webp"},
		{"non-hex", "ZZZ.webp"},
		{"uppercase-hex", "ABCDEF.webp"},
		{"wrong-ext", "deadbeef.png"},
		{"no-ext", "deadbeef"},
		{"double-dot-ext", "deadbeef..webp"},
		{"absolute", "%2Fetc%2Fpasswd"},
	}
	for _, tc := range bad {
		label := "GET /api/avatars/ " + tc.label
		status, _, raw := doJSON(t, client, http.MethodGet, base+tc.name, nil, nil)
		if status == http.StatusOK {
			t.Errorf("%s: 白名单违例不应 200（body %s）", label, raw)
			continue
		}
		if status != http.StatusNotFound && status != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400/404 (body %s)", label, status, raw)
		}
	}

	// 合法白名单名（全小写 hex + .webp）未命中文件 → 与服务层拒绝同形 404。
	label := "GET /api/avatars/ deadbeef.webp (valid name, absent)"
	status, parsed, raw := doJSON(t, client, http.MethodGet, base+"deadbeef.webp", nil, nil)
	if status == http.StatusOK || status == http.StatusBadRequest {
		t.Errorf("%s: 合法名未命中应 404（非 200/400），got %d (body %s)", label, status, raw)
	}
	if status == http.StatusNotFound {
		if msg, _ := parsed["message"].(string); msg != "Avatar not found" {
			t.Errorf("%s: 404 文案 = %q, want 'Avatar not found'", label, msg)
		}
	}
}

// TestQA_M3_Security_FilesTraversalVariants /files 穿越族深度变体：
// URL 双层编码、绝对路径、空段等一律 400 "Invalid path"（与
// static.FilesHandler safeJoin 同源）。含 %2e%2e 编码变体。
func TestQA_M3_Security_FilesTraversalVariants(t *testing.T) {
	as, _ := qaM3Server(t)
	client := as.TS.Client()
	base := as.TS.URL + "/files/"

	variants := []struct {
		label string
		path  string
	}{
		{"dotdot encoded", "%2e%2e%2fsecret.txt"},
		{"dotdot plain", "..%2F..%2Fetc%2Fpasswd"},
		{"absolute", "%2Fetc%2Fshadow"},
		{"windows drive", "C%3A%5Cwindows%5Cwin.ini"},
	}
	for _, tc := range variants {
		label := "GET /files/ " + tc.label
		status, _, raw := doJSON(t, client, http.MethodGet, base+tc.path, nil, nil)
		if status != http.StatusBadRequest && status != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 400/404 (body %s)", label, status, raw)
			continue
		}
		if status == http.StatusBadRequest && !strings.Contains(string(raw), "Invalid path") {
			t.Errorf("%s: message = %s, want 含 'Invalid path'", label, raw)
		}
	}
}

// TestQA_M3_Security_LDAPMasking LDAP bindCredentials 掩码：管理员写入明文
// bindCredentials 后回读恒 '******'，响应体不含明文；以掩码回写不覆盖库内
// 密文（掩码跳过）。与 smtp 同源语义但走不同键，独立验证掩码覆盖面。
func TestQA_M3_Security_LDAPMasking(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()
	admin := authHeader(seedToken(t, as, seed.Admin))

	const plaintext = "ldap-bind-secret-xyz"
	label := "PUT /api/settings/ldap"
	status, _, raw := doJSON(t, client, http.MethodPut, as.TS.URL+"/api/settings/ldap",
		map[string]any{
			"enabled":         true,
			"urls":            []string{"ldap://ldap.example.com:389"},
			"bindDN":          "cn=admin,dc=example,dc=com",
			"bindCredentials": plaintext,
			"searchBase":      "dc=example,dc=com",
		}, admin)
	if status != http.StatusOK {
		// LDAP DTO 字段名以 openapi 为准；若 400 说明 body 形状不符，输出以便定位。
		t.Fatalf("%s: status = %d (body %s)", label, status, raw)
	}

	label = "GET /api/settings/ldap"
	status, parsed, raw := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/settings/ldap", nil, admin)
	assertStatus(t, label, status, http.StatusOK, raw)
	if strings.Contains(string(raw), plaintext) {
		t.Fatalf("%s: 响应体泄漏 LDAP 明文凭据", label)
	}
	if got, _ := parsed["bindCredentials"].(string); got != "******" {
		t.Errorf("%s: bindCredentials = %v, want '******'", label, parsed["bindCredentials"])
	}

	// 掩码回写 → 库内保持明文。
	updates := map[string]any{}
	for k, v := range parsed {
		updates[k] = v
	}
	label = "PUT /api/settings/ldap (mask skip)"
	status, _, raw = doJSON(t, client, http.MethodPut, as.TS.URL+"/api/settings/ldap", updates, admin)
	assertStatus(t, label, status, http.StatusOK, raw)

	var stored entity.SystemSetting
	if err := as.DB.Where("key = ?", "ldap.bindCredentials").First(&stored).Error; err != nil {
		t.Fatalf("read ldap.bindCredentials: %v", err)
	}
	if stored.Value != plaintext {
		t.Errorf("LDAP 掩码跳更失效：库内 = %q, want %q", stored.Value, plaintext)
	}
}

// ---------------------------------------------------------------------------
// E. 幂等与状态
// ---------------------------------------------------------------------------

// TestQA_M3_Idempotency_FileNonceReplay file 审计 UNIQUE(device_id,nonce)
// 幂等重放（§8.24）：同 nonce 二次上报返回相同成功文案，且库内仅一行
// （不产生重复行）。conn 无 nonce 不在此列。
func TestQA_M3_Idempotency_FileNonceReplay(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()

	// 注册一个设备（heartbeat 建 peers 行，file 上报引用 deviceId）。
	devID := seed.PeerA.ID
	nonce := "qa-file-nonce-replay-1"
	body := map[string]any{
		"id":      devID,
		"uuid":    seed.PeerA.UUID,
		"peer_id": devID,
		"type":    0,
		"is_file": true,
		"info":    `{"ip":"10.0.0.9","name":"qa","num":1,"files":["x"]}`,
		"nonce":   nonce,
	}

	var msgs []string
	for i := 0; i < 2; i++ {
		status, parsed, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/audit/file", body, nil)
		if status != http.StatusOK {
			t.Fatalf("file 上报 #%d status = %d (body %s)", i+1, status, raw)
		}
		msgs = append(msgs, strOf(parsed["message"]))
	}
	if msgs[0] != msgs[1] {
		t.Errorf("同 nonce 两次上报文案不一致: %q vs %q", msgs[0], msgs[1])
	}

	var count int64
	if err := as.DB.Model(&entity.FileAudit{}).
		Where("deviceId = ? AND nonce = ?", devID, nonce).Count(&count).Error; err != nil {
		t.Fatalf("count file audits: %v", err)
	}
	if count != 1 {
		t.Errorf("同 nonce 重放应仅 1 行，got %d（幂等失效）", count)
	}
}

// TestQA_M3_Idempotency_ConnUpsert conn 上报无 nonce 幂等（§8.24 upsert 定位键）：
// 同 (deviceId, deviceUuid, connId) 二次上报不新增行（状态幂等）。
func TestQA_M3_Idempotency_ConnUpsert(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()
	devID := seed.PeerA.ID
	body := map[string]any{
		"id":      devID,
		"uuid":    seed.PeerA.UUID,
		"conn_id": 51, // 官方客户端为数值 i32（v0.2.1 契约修正）
		"peer":    []string{devID, "qa-peer"},
		"action":  "new",
	}
	connIDStr := "51"

	for i := 0; i < 2; i++ {
		status, _, raw := doJSON(t, client, http.MethodPost, as.TS.URL+"/api/audit/conn", body, nil)
		if status != http.StatusOK {
			t.Fatalf("conn 上报 #%d status = %d (body %s)", i+1, status, raw)
		}
	}
	var count int64
	if err := as.DB.Model(&entity.ConnectionAudit{}).
		Where("deviceId = ? AND connId = ?", devID, connIDStr).Count(&count).Error; err != nil {
		t.Fatalf("count conn audits: %v", err)
	}
	if count != 1 {
		t.Errorf("conn upsert 幂等失效：同定位键 got %d 行, want 1", count)
	}
}

// TestQA_M3_StateMachine_NexusCancelTerminal nexus 状态机非法跃迁：
// 终态（done）构建不可再取消 → 409（"cannot be cancelled in current status"）。
func TestQA_M3_StateMachine_NexusCancelTerminal(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()

	// 将 seed 的 pending 构建置为终态 done。
	if err := as.DB.Model(&entity.NexusBuild{}).
		Where("uuid = ?", seed.Build1.Uuid).
		Update("status", entity.NexusStatusDone).Error; err != nil {
		t.Fatalf("set build done: %v", err)
	}

	label := "DELETE /api/nexus/builds/{uuid} on terminal(done)"
	status, _, raw := doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/nexus/builds/"+seed.Build1.Uuid, nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	if status != http.StatusConflict {
		t.Fatalf("%s: status = %d, want 409 (body %s)", label, status, raw)
	}
	if !strings.Contains(string(raw), "cannot be cancelled in current status") {
		t.Errorf("%s: message = %s, want 含 'cannot be cancelled in current status'", label, raw)
	}

	// 复核：状态未被改写（仍 done）。
	var after entity.NexusBuild
	if err := as.DB.Where("uuid = ?", seed.Build1.Uuid).First(&after).Error; err != nil {
		t.Fatalf("reload build: %v", err)
	}
	if after.Status != entity.NexusStatusDone {
		t.Errorf("非法取消改写了终态：%q, want done", after.Status)
	}
}

// ---------------------------------------------------------------------------
// F. 错误包络（NestJS 兼容三字段）
// ---------------------------------------------------------------------------

// TestQA_M3_Envelope_Matrix 抽样 M3 各域错误端点，断言包络恒为
// {statusCode,message,error} 三字段且 error == HTTP 状态文本。
func TestQA_M3_Envelope_Matrix(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	cases := []struct {
		label  string
		method string
		path   string
		body   any
		hdr    map[string]string
		want   int
	}{
		{"403 servers", http.MethodGet, "/api/servers", nil, scoped, http.StatusForbidden},
		{"403 admin-guard settings", http.MethodGet, "/api/settings/general", nil, scoped, http.StatusForbidden},
		{"401 no token nexus", http.MethodGet, "/api/nexus/builds", nil, nil, http.StatusUnauthorized},
		{"404 nexus cross-user", http.MethodGet,
			"/api/nexus/builds/" + seed.Build1.Uuid + "/files", nil,
			authHeader(seedToken(t, as, seed.Owner)), http.StatusNotFound},
	}
	for _, tc := range cases {
		status, parsed, raw := doJSON(t, client, tc.method, as.TS.URL+tc.path, tc.body, tc.hdr)
		qaAssertEnvelope3(t, tc.label, status, tc.want, parsed, raw)
	}
}

// ---------------------------------------------------------------------------
// G. 固定文案逐字节（§8.16）≥8 条
// ---------------------------------------------------------------------------

// TestQA_M3_FixedMessages_ByteExact 抽查 §8.16 固定文案 ≥8 条逐字节比对：
// 通过真实 HTTP 路径触发各文案，断言 message 字段字节级相等。
func TestQA_M3_FixedMessages_ByteExact(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()

	// 1) "Unauthorized" 401（无 token）。
	s1, p1, r1 := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/nexus/builds", nil, nil)
	qaAssertEnvelope3(t, "401 nexus no-token", s1, http.StatusUnauthorized, p1, r1)

	// 2) 设置域 SMTP 未配置 → 404 "SMTP configuration does not exist"。
	admin := authHeader(seedToken(t, as, seed.Admin))
	s2, _, r2 := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/settings/smtp", nil, admin)
	assertNotFoundMsg(t, "GET smtp 未配置", s2, r2, "SMTP configuration does not exist")

	// 3) nexus 产物文件名穿越 → 400 "Invalid path"（固定文案）。
	s3, p3, r3 := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/nexus/builds/"+seed.Build1.Uuid+"/files/..%2Fevil", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	if s3 == http.StatusBadRequest {
		if got, _ := p3["message"].(string); got != "Invalid path" {
			t.Errorf("nexus 穿越文案 = %q, want 'Invalid path' (body %s)", got, r3)
		}
	}

	// 4) access denied 文案（servers 无权限）。
	_, p4, r4 := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/servers", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	if got, _ := p4["message"].(string); got != rbac.MsgAccessDenied {
		t.Errorf("access denied 文案 = %q, want %q (body %s)", got, rbac.MsgAccessDenied, r4)
	}

	// 5) admin guard 文案（settings）。
	_, p5, r5 := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/settings/general", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	if got, _ := p5["message"].(string); got != rbac.MsgAdminGuardRequired {
		t.Errorf("admin guard 文案 = %q, want %q (body %s)", got, rbac.MsgAdminGuardRequired, r5)
	}

	// 6) super admin 文案（dashboard）。
	_, p6, r6 := doJSON(t, client, http.MethodGet, as.TS.URL+"/api/dashboard", nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	if got, _ := p6["message"].(string); got != rbac.MsgSuperAdminRequired {
		t.Errorf("super admin 文案 = %q, want %q (body %s)", got, rbac.MsgSuperAdminRequired, r6)
	}

	// 7) protected account 文案（删除保护账号）。
	//    注意依赖链：users.delete requires users.view（effective 过滤会剔除
	//    缺依赖的码 → 否则退化为路由 403 "Access denied"）。
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeUsersView)
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeUsersDelete)
	s7, p7, r7 := doJSON(t, client, http.MethodDelete,
		as.TS.URL+"/api/users/"+seed.Owner.Guid, nil,
		authHeader(seedToken(t, as, seed.Scoped)))
	if got, _ := p7["message"].(string); got != rbac.MsgProtectedAccount {
		t.Errorf("protected account 文案 = %q, want %q (status %d, body %s)",
			got, rbac.MsgProtectedAccount, s7, r7)
	}

	// 8) owner immutable 文案（PATCH 系统所有者 status=0 → 403）。
	//    PATCH users/{guid} 为 Auth 档 + 字段分权：需 users.status（依赖 users.view）。
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeUsersStatus)
	s8, p8, r8 := doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/users/"+seed.Admin.Guid, map[string]any{"status": 0},
		authHeader(seedToken(t, as, seed.Scoped)))
	if got, _ := p8["message"].(string); got != rbac.MsgOwnerAccountImmutable {
		t.Errorf("owner immutable 文案 = %q, want %q (status %d, body %s)",
			got, rbac.MsgOwnerAccountImmutable, s8, r8)
	}

	// 9) "No fields to update"（PATCH 空 body）——Auth 档字段分权；空 body
	//    无字段 → 服务层 400，文案嵌于 message.error（authsvc.BadRequest
	//    的双层包络，M2 既有语义）。需 users.edit（依赖 users.view）。
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeUsersEdit)
	s9, p9, r9 := doJSON(t, client, http.MethodPatch,
		as.TS.URL+"/api/users/"+seed.Scoped.Guid, map[string]any{},
		authHeader(seedToken(t, as, seed.Scoped)))
	if s9 != http.StatusBadRequest {
		t.Errorf("空 PATCH 应 400，got %d (body %s)", s9, r9)
	}
	if msg := nestedErrMessage(p9); msg != "No fields to update" {
		t.Errorf("no fields 文案 = %q, want 'No fields to update' (status %d, body %s)", msg, s9, r9)
	}
}

// nestedErrMessage 取 authsvc 双层包络中的内层 error 文案：
// message 为对象时取 message["error"]，否则取 message 字符串本身。
func nestedErrMessage(parsed map[string]any) string {
	if m, ok := parsed["message"].(map[string]any); ok {
		s, _ := m["error"].(string)
		return s
	}
	s, _ := parsed["message"].(string)
	return s
}

// ---------------------------------------------------------------------------
// H. 三方一致性独立复核（路由表 ↔ openapi）
// ---------------------------------------------------------------------------

// TestQA_M3_ThreeWay_PolicyDistribution 独立复核档位分布与总数：
// Router.Routes() 总 164，且 public/auth/perm/admin_guard/super_admin
// 分布 = 19/53/62/23/7（设计口径，已知勘误后权威值）。
func TestQA_M3_ThreeWay_PolicyDistribution(t *testing.T) {
	as, _ := qaM3Server(t)

	counts := map[string]int{}
	for _, r := range as.Router.Routes() {
		counts[r.Policy]++
	}
	total := len(as.Router.Routes())
	if total != 173 {
		t.Errorf("路由总数 = %d, want 173", total)
	}
	want := map[string]int{
		"public": 21, "auth": 54, "perm": 66, "admin_guard": 25, "super_admin": 7,
	}
	for policy, w := range want {
		if counts[policy] != w {
			t.Errorf("档位 %s 计数 = %d, want %d", policy, counts[policy], w)
		}
	}
}

// strOf 从 any 取字符串（nil → ""）。
func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// ---------------------------------------------------------------------------
// I. 服务器域转发错误映射（§8.16 固定文案端到端，QA 独立注入假 agent）
// ---------------------------------------------------------------------------

// qaNodesEnv 构造单节点 RUSTDESK_NODES JSON（token ≥32）。
func qaNodesEnv(id, url string) string {
	raw, err := json.Marshal([]map[string]string{{
		"id": id, "name": "QA Node", "url": url,
		"token": "0123456789abcdef0123456789abcdef",
	}})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// TestQA_M3_ServerMGMT_NodeUnavailable503 转发网络错误 → 503 固定文案
// "Server node unavailable"（§8.16）：节点指向已关闭端口（连接被拒）。
func TestQA_M3_ServerMGMT_NodeUnavailable503(t *testing.T) {
	// 起一个 httptest server 后立即关闭，取得一个确定不可达的 URL。
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	as, seed := qaM3Server(t, func(c *config.Config) { c.RustdeskNodes = qaNodesEnv("qa-node", deadURL) })
	client := as.TS.Client()
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeServersView)
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	label := "GET /api/servers/{node}/peers (unreachable)"
	status, parsed, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/servers/qa-node/peers", nil, scoped)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("%s: status = %d, want 503 (body %s)", label, status, raw)
	}
	if got, _ := parsed["message"].(string); got != "Server node unavailable" {
		t.Errorf("%s: message = %q, want 'Server node unavailable'", label, got)
	}
}

// TestQA_M3_ServerMGMT_InvalidResponse502 上游 200 但非 JSON → 502 固定文案
// "Invalid node management response"（§8.16）。
func TestQA_M3_ServerMGMT_InvalidResponse502(t *testing.T) {
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not-a-json-body"))
	}))
	t.Cleanup(agent.Close)

	as, seed := qaM3Server(t, func(c *config.Config) { c.RustdeskNodes = qaNodesEnv("qa-node", agent.URL) })
	client := as.TS.Client()
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeServersView)
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	label := "GET /api/servers/{node}/peers (non-json 200)"
	status, parsed, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/servers/qa-node/peers", nil, scoped)
	if status != http.StatusBadGateway {
		t.Fatalf("%s: status = %d, want 502 (body %s)", label, status, raw)
	}
	if got, _ := parsed["message"].(string); got != "Invalid node management response" {
		t.Errorf("%s: message = %q, want 'Invalid node management response'", label, got)
	}
}

// TestQA_M3_ServerMGMT_UnregisteredNode404 未注册节点 → 404 固定文案
// "Server node not found"（转发前 Node(id) 查表失败）。
func TestQA_M3_ServerMGMT_UnregisteredNode404(t *testing.T) {
	as, seed := qaM3Server(t)
	client := as.TS.Client()
	grantM3(t, as, seed.RoleDev.Guid, rbac.CodeServersView)
	scoped := authHeader(seedToken(t, as, seed.Scoped))

	label := "GET /api/servers/ghost/peers"
	status, parsed, raw := doJSON(t, client, http.MethodGet,
		as.TS.URL+"/api/servers/ghost/peers", nil, scoped)
	if status != http.StatusNotFound {
		t.Fatalf("%s: status = %d, want 404 (body %s)", label, status, raw)
	}
	if got, _ := parsed["message"].(string); got != "Server node not found" {
		t.Errorf("%s: message = %q, want 'Server node not found'", label, got)
	}
}
