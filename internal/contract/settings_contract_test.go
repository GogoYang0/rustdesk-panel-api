// settings_contract_test.go 设置域（M3 T07，事实④）6 端点契约用例：
// 以 openapi.yaml 为准绳做请求/响应双向校验，并锁定掩码回读
// （smtp.pass / ldap.bindCredentials 恒 '******'）、PUT 命中掩码跳过、
// test 恒 200、smto 未配置 404 固定文案、frontend 公开三键。
package contract

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// newSettingsContractServer 全栈契约服务器（可注入 Config 覆写）。
func newSettingsContractServer(t *testing.T, mutate func(*config.Config)) *contractServer {
	t.Helper()
	as := apptest.NewAppServer(t, mutate)
	cs := newContractServerWith(t, func() *server.Router {
		return server.NewRouter(server.RouterDeps{
			Logger:           testutil.TestLogger(),
			RateLimitEnabled: false,
			DB:               as.DB,
			Config:           as.Config,
		})
	})
	return cs
}

// TestContractSettingsFrontendPublic 前端三键无鉴权可读（Public 档）。
func TestContractSettingsFrontendPublic(t *testing.T) {
	cs := newSettingsContractServer(t, nil)

	raw := cs.get(t, "/api/settings/frontend", nil, http.StatusOK)
	var view struct {
		WatermarkEnabled bool   `json:"watermarkEnabled"`
		DefaultLanguage  string `json:"defaultLanguage"`
		WebauthnEnabled  bool   `json:"webauthnEnabled"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("frontend body not object: %v (%s)", err, raw)
	}
	if view.DefaultLanguage == "" {
		t.Errorf("defaultLanguage must be non-empty by default: %s", raw)
	}
}

// TestContractSettingsGeneral GET/PUT general 嵌套 DTO 与校验。
func TestContractSettingsGeneral(t *testing.T) {
	cs := newSettingsContractServer(t, nil)
	token, _ := abLogin(t, cs)

	raw := cs.get(t, "/api/settings/general", bearer(token), http.StatusOK)
	var view struct {
		WatermarkEnabled   bool   `json:"watermarkEnabled"`
		DefaultLanguage    string `json:"defaultLanguage"`
		JwtExpiryDays      int    `json:"jwtExpiryDays"`
		AuditRetentionDays int    `json:"auditRetentionDays"`
		Site               struct {
			FrontendUrl string `json:"frontendUrl"`
			BackendUrl  string `json:"backendUrl"`
		} `json:"site"`
		Webauthn struct {
			Enabled bool   `json:"enabled"`
			RpName  string `json:"rpName"`
		} `json:"webauthn"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("general body not object: %v (%s)", err, raw)
	}
	// 缺省：无 siteFrontendUrl 时 effectiveFrontendUrl 回退 localhost:3000。
	if view.Site.FrontendUrl != "http://localhost:3000" {
		t.Errorf("site.frontendUrl = %q, want localhost:3000 fallback", view.Site.FrontendUrl)
	}
	if view.JwtExpiryDays < 1 {
		t.Errorf("jwtExpiryDays = %d, want >= 1", view.JwtExpiryDays)
	}

	// PUT 全字段更新后回读一致。
	updated := cs.put(t, "/api/settings/general", map[string]any{
		"watermarkEnabled":   true,
		"defaultLanguage":    "en-US",
		"jwtExpiryDays":      7,
		"auditRetentionDays": 30,
		"siteFrontendUrl":    "https://panel.example",
		"siteBackendUrl":     "https://api.example",
		"webauthnEnabled":    true,
		"webauthnRpName":     "Panel RP",
	}, bearer(token), http.StatusOK)
	var after struct {
		WatermarkEnabled   bool   `json:"watermarkEnabled"`
		DefaultLanguage    string `json:"defaultLanguage"`
		JwtExpiryDays      int    `json:"jwtExpiryDays"`
		AuditRetentionDays int    `json:"auditRetentionDays"`
		Site               struct {
			FrontendUrl string `json:"frontendUrl"`
		} `json:"site"`
		Webauthn struct {
			Enabled bool   `json:"enabled"`
			RpName  string `json:"rpName"`
		} `json:"webauthn"`
	}
	if err := json.Unmarshal(updated, &after); err != nil {
		t.Fatalf("general update body not object: %v (%s)", err, updated)
	}
	if !after.WatermarkEnabled || after.DefaultLanguage != "en-US" || after.JwtExpiryDays != 7 {
		t.Errorf("general update not persisted: %s", updated)
	}
	if after.Site.FrontendUrl != "https://panel.example" {
		t.Errorf("site.frontendUrl = %q, want persisted value", after.Site.FrontendUrl)
	}
	if !after.Webauthn.Enabled || after.Webauthn.RpName != "Panel RP" {
		t.Errorf("webauthn not persisted: %s", updated)
	}

	// 形状违例：defaultLanguage 不匹配 ^[a-z]{2}-[A-Z]{2}$ → 400。
	cs.invalid(t, http.MethodPut, "/api/settings/general",
		map[string]any{"watermarkEnabled": true, "defaultLanguage": "zh_cn"},
		bearer(token), http.StatusBadRequest)
}

// TestContractSettingsSmtp SMTP 掩码回读 / 跳更 / 未配置 404 / test 恒 200。
func TestContractSettingsSmtp(t *testing.T) {
	cs := newSettingsContractServer(t, nil)
	token, _ := abLogin(t, cs)

	// 未配置 → 404 固定文案。
	raw := cs.get(t, "/api/settings/smtp", bearer(token), http.StatusNotFound)
	assertEnvelopeMessage(t, raw, http.StatusNotFound, "SMTP configuration does not exist")

	// 首次 PUT 建立配置；pass 落真实值。
	cs.put(t, "/api/settings/smtp", map[string]any{
		"host": "smtp.example", "port": 587, "secure": false,
		"user": "mailer", "pass": "s3cr3t", "from": "noreply@example", "enabled": true,
	}, bearer(token), http.StatusOK)

	// 回读：pass 恒掩码 '******'。
	raw = cs.get(t, "/api/settings/smtp", bearer(token), http.StatusOK)
	var view struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		User    string `json:"user"`
		Pass    string `json:"pass"`
		From    string `json:"from"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("smtp body not object: %v (%s)", err, raw)
	}
	if view.Pass != "******" {
		t.Errorf("smtp.pass = %q, want masked '******'", view.Pass)
	}
	if view.Host != "smtp.example" || view.User != "mailer" {
		t.Errorf("smtp config not persisted: %s", raw)
	}

	// PUT 命中掩码 → 跳过更新（真实口令不被 '******' 覆盖）。
	cs.put(t, "/api/settings/smtp", map[string]any{"pass": "******"}, bearer(token), http.StatusOK)

	// test 恒 200（不可达主机亦 200 + success:false）。
	raw = cs.post(t, "/api/settings/smtp/test", nil, bearer(token), http.StatusOK)
	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("smtp test body not object: %v (%s)", err, raw)
	}
	if result.Success {
		t.Errorf("smtp test against unreachable host must be success:false: %s", raw)
	}
	if result.Message == "" {
		t.Errorf("smtp test message must be non-empty: %s", raw)
	}
}

// TestContractSettingsLdap LDAP 掩码回读 / 跳更 / test 恒 200。
func TestContractSettingsLdap(t *testing.T) {
	cs := newSettingsContractServer(t, nil)
	token, _ := abLogin(t, cs)

	raw := cs.get(t, "/api/settings/ldap", bearer(token), http.StatusOK)
	var view struct {
		Urls            []string `json:"urls"`
		BindDN          string   `json:"bindDN"`
		BindCredentials string   `json:"bindCredentials"`
		SearchFilter    string   `json:"searchFilter"`
		Enabled         bool     `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("ldap body not object: %v (%s)", err, raw)
	}
	if view.BindCredentials != "******" {
		t.Errorf("ldap.bindCredentials = %q, want masked '******'", view.BindCredentials)
	}

	// PUT 建档（含真实凭据与 urls/attrs/adminGroups/tlsOptions）。
	cs.put(t, "/api/settings/ldap", map[string]any{
		"urls":              []string{"ldap://ldap.example:389"},
		"bindDN":            "cn=admin,dc=example",
		"bindCredentials":   "bind-secret",
		"searchBase":        "dc=example",
		"searchFilter":      "(uid=%s)",
		"searchAttributes":  []string{"uid", "mail"},
		"groupSearchBase":   "ou=groups,dc=example",
		"groupSearchFilter": "(member=%s)",
		"adminGroups":       []string{"admins"},
		"tlsOptions":        map[string]any{"servername": "ldap.example"},
		"enabled":           true,
	}, bearer(token), http.StatusOK)

	raw = cs.get(t, "/api/settings/ldap", bearer(token), http.StatusOK)
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("ldap reread not object: %v (%s)", err, raw)
	}
	if view.BindCredentials != "******" {
		t.Errorf("ldap.bindCredentials after PUT = %q, want masked", view.BindCredentials)
	}
	if view.BindDN != "cn=admin,dc=example" || !view.Enabled {
		t.Errorf("ldap config not persisted: %s", raw)
	}
	if len(view.Urls) != 1 {
		t.Errorf("ldap.urls = %v, want 1 entry", view.Urls)
	}

	// PUT 命中掩码 → 跳更。
	cs.put(t, "/api/settings/ldap",
		map[string]any{"bindCredentials": "******"}, bearer(token), http.StatusOK)

	// 形状违例：urls 项非 ldap:// 前缀 → 400。
	cs.invalid(t, http.MethodPut, "/api/settings/ldap",
		map[string]any{"urls": []string{"http://not-ldap.example"}},
		bearer(token), http.StatusBadRequest)

	// test 恒 200（不可达主机亦 200 + success:false）。
	raw = cs.post(t, "/api/settings/ldap/test", nil, bearer(token), http.StatusOK)
	var result struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("ldap test body not object: %v (%s)", err, raw)
	}
	if result.Success {
		t.Errorf("ldap test against unreachable host must be success:false: %s", raw)
	}
}

// TestContractSettingsUnauthorized 未认证 → 401（general/smtp/ldap
// 六档均 AdminGuard；frontend 为 Public 不在此列）。
func TestContractSettingsUnauthorized(t *testing.T) {
	cs := newSettingsContractServer(t, nil)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/settings/general"},
		{http.MethodPut, "/api/settings/general"},
		{http.MethodGet, "/api/settings/smtp"},
		{http.MethodPut, "/api/settings/smtp"},
		{http.MethodPost, "/api/settings/smtp/test"},
		{http.MethodGet, "/api/settings/ldap"},
		{http.MethodPut, "/api/settings/ldap"},
		{http.MethodPost, "/api/settings/ldap/test"},
	} {
		// 请求体须先满足 openapi 形状，否则在校验层即被拦截。
		var body any
		switch tc.path {
		case "/api/settings/general":
			if tc.method == http.MethodPut {
				body = map[string]any{"watermarkEnabled": true}
			}
		case "/api/settings/ldap":
			if tc.method == http.MethodPut {
				body = map[string]any{}
			}
		case "/api/settings/smtp":
			if tc.method == http.MethodPut {
				body = map[string]any{}
			}
		}
		cs.raw(t, tc.method, tc.path, body, nil, http.StatusUnauthorized)
	}
}
