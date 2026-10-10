// updatecheck_contract_test.go 更新检查域（M3 T07 事实④ + v0.2.1 问题 12）
// 1 端点契约用例：以 openapi.yaml 为准绳做请求/响应双向校验。版本源 =
// GitHub Releases（httptest stub 注入 GITHUB_API_BASE，仅测试用）；
// 遥测上游 stub 保留（best-effort，不再决定版本结果）。锁定
// backend/frontend 双分支、changelog/downloadUrl 与 frontend_version
// 查询参数仅影响 frontend 分支比对。
package contract

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
)

// githubReleaseStub 单仓 releases/latest 响应体。
func githubReleaseStub(tag, body, htmlURL string) string {
	return fmt.Sprintf(`{"tag_name":%q,"body":%q,"html_url":%q}`, tag, body, htmlURL)
}

// newUpdateCheckContractServer 全栈契约服务器 + 假 GitHub API + 假遥测上游。
//
// github 仓 → tag 映射：GogoYang0/rustdesk-panel-web → webTag（body=webBody），
// GogoYang0/rustdesk-panel-api → apiTag。遥测上游恒 200 空对象。
func newUpdateCheckContractServer(t *testing.T, webTag, webBody, apiTag string) *contractServer {
	t.Helper()
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/GogoYang0/rustdesk-panel-web/releases/latest":
			_, _ = w.Write([]byte(githubReleaseStub(webTag, webBody,
				"https://github.com/GogoYang0/rustdesk-panel-web/releases/tag/"+webTag)))
		case "/repos/GogoYang0/rustdesk-panel-api/releases/latest":
			_, _ = w.Write([]byte(githubReleaseStub(apiTag, "",
				"https://github.com/GogoYang0/rustdesk-panel-api/releases/tag/"+apiTag)))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(github.Close)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/update/check" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		// 遥测 payload 必须可解析为 JSON object（面板契约）。
		raw, _ := io.ReadAll(r.Body)
		if !json.Valid(raw) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(upstream.Close)

	return newSettingsContractServer(t, func(cfg *config.Config) {
		cfg.GitHubAPIBase = github.URL
		cfg.NexusUpstream = upstream.URL
	})
}

// TestContractUpdateCheck GitHub 有新版时 backend/frontend 双分支比对
// 正确（tag 去 v、changelog/downloadUrl 回填）。
func TestContractUpdateCheck(t *testing.T) {
	cs := newUpdateCheckContractServer(t, "v9.9.9", "- 修复审计上报\n- 修复标签 400", "v9.9.9")
	token, _ := abLogin(t, cs)

	raw := cs.get(t, "/api/update-check", bearer(token), http.StatusOK)
	var view struct {
		Backend  updateBranchView `json:"backend"`
		Frontend updateBranchView `json:"frontend"`
		InstallI *string          `json:"install_id,omitempty"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("update-check body not object: %v (%s)", err, raw)
	}
	if view.Backend.Latest != "9.9.9" {
		t.Errorf("backend.latest = %q, want 9.9.9 (%s)", view.Backend.Latest, raw)
	}
	if !view.Backend.HasUpdate {
		t.Errorf("backend.hasUpdate = false, want true for 9.9.9 > current (%s)", raw)
	}
	if view.Backend.DownloadUrl == "" {
		t.Errorf("backend.downloadUrl must be set when hasUpdate (%s)", raw)
	}
	if view.Frontend.Changelog != "- 修复审计上报\n- 修复标签 400" {
		t.Errorf("frontend.changelog = %q, want release body (%s)", view.Frontend.Changelog, raw)
	}
	if view.InstallI == nil || *view.InstallI == "" {
		t.Errorf("install_id must be non-empty (%s)", raw)
	}

	// 第二次请求命中内存缓存（仍 200 且形状一致）。
	cs.get(t, "/api/update-check", bearer(token), http.StatusOK)

	// frontend_version 查询参数仅影响 frontend 分支比对。
	raw = cs.get(t, "/api/update-check?frontend_version=9.9.9", bearer(token), http.StatusOK)
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("update-check with param not object: %v (%s)", err, raw)
	}
	if view.Frontend.Current != "9.9.9" {
		t.Errorf("frontend.current = %q, want query param value (%s)", view.Frontend.Current, raw)
	}
	if view.Frontend.HasUpdate {
		t.Errorf("frontend.hasUpdate must be false when current == latest (%s)", raw)
	}
	// backend 分支不受查询参数影响。
	if !view.Backend.HasUpdate {
		t.Errorf("backend branch must be unaffected by frontend_version (%s)", raw)
	}
}

// TestContractUpdateCheckUpstreamUnavailable GitHub 不可用时仍 200
// （零更新结果，不阻断面板）。
func TestContractUpdateCheckUpstreamUnavailable(t *testing.T) {
	// 覆写为不可达基址（127.0.0.1:1 端口拒绝）。
	cs := newSettingsContractServer(t, func(cfg *config.Config) {
		cfg.GitHubAPIBase = "http://127.0.0.1:1"
		cfg.NexusUpstream = "http://127.0.0.1:2"
	})
	token, _ := abLogin(t, cs)

	raw := cs.get(t, "/api/update-check", bearer(token), http.StatusOK)
	var view struct {
		Backend  updateBranchView `json:"backend"`
		Frontend updateBranchView `json:"frontend"`
	}
	if err := json.Unmarshal(raw, &view); err != nil {
		t.Fatalf("update-check body not object: %v (%s)", err, raw)
	}
	if view.Backend.HasUpdate || view.Frontend.HasUpdate {
		t.Errorf("upstream unavailable must yield zero-update result: %s", raw)
	}
}

// TestContractUpdateCheckUnauthorized 未认证 → 401（AdminGuard）。
func TestContractUpdateCheckUnauthorized(t *testing.T) {
	cs := newUpdateCheckContractServer(t, "v9.9.9", "notes", "v9.9.9")
	cs.get(t, "/api/update-check", nil, http.StatusUnauthorized)
}

// updateBranchView 单分支响应视图（backend/frontend 同构）。
type updateBranchView struct {
	Current     string `json:"current"`
	Latest      string `json:"latest"`
	HasUpdate   bool   `json:"hasUpdate"`
	DownloadUrl string `json:"downloadUrl"`
	Changelog   string `json:"changelog"`
}
