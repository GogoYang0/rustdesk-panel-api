// updatecheck_test.go 更新检查服务单测（v0.2.1 MIN-01）。
//
// 重点覆盖版本错位场景：backend 版本 ≥ GitHub latest 而用户
// frontend_version < latest 时，frontend 分支重算 hasUpdate=true，
// changelog/downloadUrl 必须仍来自 GitHub 响应（可达时），不得丢失。
package updatecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/migration"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// 测试常量：错位场景版本三元组（backend=0.3.0 / latest=0.2.0 / frontend=0.1.0）。
const (
	testBackendVersion  = "0.3.0"
	testLatestTag       = "v0.2.0"
	testLatest          = "0.2.0"
	testFrontendVersion = "0.1.0"
	testChangelog       = "- 修复审计上报\n- 修复标签 400"
	testDownloadURL     = "https://github.com/GogoYang0/rustdesk-panel-web/releases/tag/v0.2.0"
)

// newTestService 构建带内存库 settings 仓储的测试服务。
//
// githubHandler 非 nil 时注入假 GitHub Releases 服务器
// （/repos/{web,api}/releases/latest 均返回 latest tag + changelog）；
// 为 nil 时注入不可达基址（127.0.0.1:1）。遥测上游留空（跳过）。
func newTestService(t *testing.T, version string, githubHandler http.HandlerFunc) *Service {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	m, err := migration.New(db, "sqlite")
	if err != nil {
		t.Fatalf("migration.New: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("migration.Up: %v", err)
	}
	opts := Options{
		Version:  version,
		Settings: repository.NewSystemSettingRepo(db),
	}
	if githubHandler != nil {
		github := httptest.NewServer(githubHandler)
		t.Cleanup(github.Close)
		opts.GitHubBase = github.URL
	} else {
		opts.GitHubBase = "http://127.0.0.1:1"
	}
	return NewService(opts)
}

// githubLatestHandler 假 GitHub API：latest 响应含 changelog 与下载地址。
func githubLatestHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/releases/latest") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"` + testLatestTag +
			`","body":` + quote(testChangelog) +
			`,"html_url":"` + testDownloadURL + `"}`))
	}
}

// quote 极简 JSON 字符串字面量包装（测试内容仅含换行/引号两类特殊字符）。
func quote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

// TestCheckBranchAlwaysCarriesReleaseInfo GitHub 可达时
// changelog/downloadUrl 始终回填，hasUpdate 只是比较结果（MIN-01 核心）。
func TestCheckBranchAlwaysCarriesReleaseInfo(t *testing.T) {
	svc := newTestService(t, testBackendVersion, githubLatestHandler(t))

	// backend(0.3.0) > latest(0.2.0)：hasUpdate=false 但 release 信息仍回填。
	out := svc.checkBranch(context.Background(), githubWebRepo, testBackendVersion)
	if out.HasUpdate {
		t.Errorf("hasUpdate = true, want false for %s > %s", testBackendVersion, testLatest)
	}
	if out.Latest != testLatest {
		t.Errorf("latest = %q, want %q", out.Latest, testLatest)
	}
	if out.Changelog != testChangelog {
		t.Errorf("changelog = %q, want GitHub release body", out.Changelog)
	}
	if out.DownloadURL != testDownloadURL {
		t.Errorf("downloadUrl = %q, want GitHub html_url", out.DownloadURL)
	}

	// latest > current：hasUpdate=true 且信息回填（原行为保持）。
	out = svc.checkBranch(context.Background(), githubWebRepo, testFrontendVersion)
	if !out.HasUpdate {
		t.Errorf("hasUpdate = false, want true for %s < %s", testFrontendVersion, testLatest)
	}
	if out.Changelog != testChangelog || out.DownloadURL != testDownloadURL {
		t.Errorf("changelog/downloadUrl must be filled when hasUpdate: %+v", out)
	}
}

// TestGetVersionMismatchScenario ★ MIN-01 复现场景：
// backend=0.3.0 ≥ latest=0.2.0（缓存 hasUpdate=false）而
// frontend_version=0.1.0 < latest → hasUpdate=true 且
// changelog/downloadUrl 来自 GitHub 响应（修复前两者为 null）。
func TestGetVersionMismatchScenario(t *testing.T) {
	svc := newTestService(t, testBackendVersion, githubLatestHandler(t))
	ctx := context.Background()

	// 首请求（同步刷新缓存 + frontend_version 覆盖比对基准）。
	got, err := svc.Get(ctx, testFrontendVersion)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Frontend.HasUpdate {
		t.Errorf("frontend.hasUpdate = false, want true for %s < %s: %+v",
			testFrontendVersion, testLatest, got.Frontend)
	}
	if got.Frontend.Current != testFrontendVersion {
		t.Errorf("frontend.current = %q, want query param value %q", got.Frontend.Current, testFrontendVersion)
	}
	if got.Frontend.Latest != testLatest {
		t.Errorf("frontend.latest = %q, want %q", got.Frontend.Latest, testLatest)
	}
	if got.Frontend.Changelog == nil || *got.Frontend.Changelog != testChangelog {
		t.Errorf("frontend.changelog = %v, want GitHub release body", got.Frontend.Changelog)
	}
	if got.Frontend.DownloadUrl == nil || *got.Frontend.DownloadUrl != testDownloadURL {
		t.Errorf("frontend.downloadUrl = %v, want GitHub html_url", got.Frontend.DownloadUrl)
	}

	// 第二次请求命中内存缓存（applyFrontendVersion 重算路径，结果须一致）。
	cached, err := svc.Get(ctx, testFrontendVersion)
	if err != nil {
		t.Fatalf("Get (cached): %v", err)
	}
	if !cached.Frontend.HasUpdate ||
		cached.Frontend.Changelog == nil || *cached.Frontend.Changelog != testChangelog ||
		cached.Frontend.DownloadUrl == nil || *cached.Frontend.DownloadUrl != testDownloadURL {
		t.Errorf("cached path lost release info: %+v", cached.Frontend)
	}

	// backend 分支不受 frontend_version 影响（0.3.0 > 0.2.0 → 无更新）。
	if got.Backend.HasUpdate {
		t.Errorf("backend.hasUpdate = true, want false for %s > %s", testBackendVersion, testLatest)
	}
}

// TestApplyFrontendVersionNoUpdateClearsReleaseInfo 无更新时
// changelog/downloadUrl 清空（不残留缓存文案、不提供下载入口）。
func TestApplyFrontendVersionNoUpdateClearsReleaseInfo(t *testing.T) {
	svc := newTestService(t, testFrontendVersion, githubLatestHandler(t))
	// 刷新缓存（0.1.0 < 0.2.0，release 信息已回填）。
	if _, err := svc.Get(context.Background(), testFrontendVersion); err != nil {
		t.Fatalf("Get: %v", err)
	}
	svc.mu.RLock()
	base := *svc.cache
	svc.mu.RUnlock()
	if base.Frontend.Changelog == nil || base.Frontend.DownloadUrl == nil {
		t.Fatalf("cache should carry release info before mismatch check: %+v", base.Frontend)
	}

	// 前端已是最新（current == latest）→ 清空 release 信息。
	got, err := svc.Get(context.Background(), testLatest)
	if err != nil {
		t.Fatalf("Get (up-to-date): %v", err)
	}
	if got.Frontend.HasUpdate {
		t.Errorf("frontend.hasUpdate = true, want false for current == latest")
	}
	if got.Frontend.DownloadUrl != nil {
		t.Errorf("frontend.downloadUrl = %v, want nil when no update", got.Frontend.DownloadUrl)
	}
	if got.Frontend.Changelog != nil {
		t.Errorf("frontend.changelog = %v, want nil when no update", got.Frontend.Changelog)
	}
}

// TestGetGitHubUnavailableFallback GitHub 不可达时回退零更新结果
// （原行为保持；不伪造 release 信息。注：frontend_version 小于 backend
// 版本时 hasUpdate 仍可为 true——latest 无真实数据源，changelog/downloadUrl
// 保持 null，由前端按 null 渲染"暂无更新日志"）。
func TestGetGitHubUnavailableFallback(t *testing.T) {
	svc := newTestService(t, testBackendVersion, nil)
	got, err := svc.Get(context.Background(), testFrontendVersion)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Backend.HasUpdate {
		t.Errorf("unreachable github must yield zero-update backend result: %+v", got)
	}
	if got.Frontend.Changelog != nil || got.Frontend.DownloadUrl != nil {
		t.Errorf("unreachable github must not fabricate release info: %+v", got.Frontend)
	}
}
