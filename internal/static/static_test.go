// static_test.go 静态资源域单测：SPA fallback（含三前缀排除）、
// FilesHandler 防穿越（400 Invalid path）与正常下载、WebpHandler
// 白名单与缓存头（设计 T01 验收：防穿越/fallback/MIME 断言）。
package static

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// get 对 handler 执行一次 GET 并返回 recorder。
func get(h http.Handler, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestSPAHandlerFallback 排除前缀外的 GET 一律回 index.html
// （SPA fallback，共享知识 25）。
func TestSPAHandlerFallback(t *testing.T) {
	h := SPAHandler()
	cases := []string{"/", "/login", "/devices/abc", "/a/b/c?x=1"}
	for _, target := range cases {
		rec := get(h, target)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 (SPA fallback)", target, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s content-type = %q, want text/html", target, ct)
		}
		if body := rec.Body.String(); !strings.Contains(body, "RustDesk Panel") {
			t.Errorf("GET %s body lacks placeholder index content", target)
		}
	}
}

// TestSPAHandlerExcludedPrefixes /api、/files、/avatars 三前缀内
// 未匹配路径不回 index.html，而是 NestJS 风格 404 包络。
func TestSPAHandlerExcludedPrefixes(t *testing.T) {
	h := SPAHandler()
	cases := []string{
		"/api", "/api/unknown", "/api/devices/",
		"/files", "/files/anything",
		"/avatars", "/avatars/x.webp",
	}
	for _, target := range cases {
		rec := get(h, target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (excluded prefix)", target, rec.Code)
		}
		if body := rec.Body.String(); !strings.Contains(body, "Cannot GET") {
			t.Errorf("GET %s body = %q, want NestJS-style 404 envelope", target, body)
		}
	}
}

// TestFilesHandlerSafeJoinAndDownload FilesHandler 防穿越与正常下载。
// 用例经真实 ServeMux 挂载（与生产注册同款模式），保证 {path...}
// PathValue 由路由层注入（直接调 handler 不会填充）。
func TestFilesHandlerSafeJoinAndDownload(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "build-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build-1", "app.exe"), []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /files/{path...}", FilesHandler(dir))
	h := http.Handler(mux)

	// 正常产物下载：octet-stream + attachment + basename。
	rec := get(h, "/files/build-1/app.exe")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET valid file = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("content-type = %q, want application/octet-stream", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="app.exe"` {
		t.Errorf("content-disposition = %q", cd)
	}
	if body := rec.Body.String(); body != "MZ" {
		t.Errorf("body = %q, want MZ", body)
	}

	// 防穿越矩阵：全部 400 Invalid path。
	traversal := []string{
		"/files/..%2fsecret.txt",
		"/files/build-1/..%2f..%2fsecret.txt",
		"/files/%2e%2e%2fsecret.txt",
	}
	for _, target := range traversal {
		rec := get(h, target)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("GET %s = %d, want 400 (path traversal)", target, rec.Code)
		} else if body := rec.Body.String(); !strings.Contains(body, "Invalid path") {
			t.Errorf("GET %s body = %q, want Invalid path", target, body)
		}
	}

	// 空路径与不存在文件。
	if rec := get(h, "/files/"); rec.Code != http.StatusBadRequest {
		t.Errorf("GET empty path = %d, want 400", rec.Code)
	}
	if rec := get(h, "/files/build-1/missing.exe"); rec.Code != http.StatusNotFound {
		t.Errorf("GET missing file = %d, want 404", rec.Code)
	}
}

// TestWebpHandlerWhitelistAndCache WebpHandler 白名单、缓存头与防穿越。
// 经真实 ServeMux 挂载（同生产模式）注入 {filename} PathValue。
func TestWebpHandlerWhitelistAndCache(t *testing.T) {
	dir := t.TempDir()
	name := "0123abcd-4567-89ef-abcd-ef0123456789.webp"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("RIFF"), 0o644); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /avatars/{filename}", WebpHandler(dir))
	h := http.Handler(mux)

	// 白名单命中：image/webp + public 缓存。
	rec := get(h, "/avatars/"+name)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET avatar = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/webp" {
		t.Errorf("content-type = %q, want image/webp", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=86400" {
		t.Errorf("cache-control = %q, want public, max-age=86400", cc)
	}

	// 白名单拒绝矩阵：非 hex/连字符、错误后缀、穿越面。
	rejected := []string{
		"/avatars/not-guid.webp",
		"/avatars/abc.png",
		"/avatars/abc%2e%2e%2fwebp.webp",
		"/avatars/",
	}
	for _, target := range rejected {
		rec := get(h, target)
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404 (whitelist)", target, rec.Code)
		}
	}
}
