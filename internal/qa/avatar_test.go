package qa

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// ---- 头像：字节回环 / 文件清理 / 穿越变体不泄漏 ----

// customWebp 构造带唯一字节的合法 webp 载荷（RIFF/WEBP 魔数 + 填充），
// 供"GET 返回字节一致"断言使用。
func customWebp(t *testing.T) []byte {
	t.Helper()
	payload := make([]byte, 96)
	copy(payload[0:4], "RIFF")
	copy(payload[8:12], "WEBP")
	for i := 12; i < len(payload); i++ {
		payload[i] = byte(i * 7) // 确定性指纹
	}
	return payload
}

// uploadAvatarBytes 以 multipart/form-data 上传头像，返回状态码与解析响应。
func uploadAvatarBytes(t *testing.T, ts *apptest.AppServer, token string, payload []byte) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("avatar", "avatar.webp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.TS.URL+"/api/users/me/avatar", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.TS.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	parsed := map[string]any{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("avatar upload response not json: %v (%s)", err, raw)
	}
	return resp.StatusCode, parsed
}

// TestQAAvatarByteRoundtripAndFileCleanup 任务指定高风险点：
// 上传合法 webp → 静态 GET 返回与上传内容逐字节一致（Content-Type image/webp）
// → 删除后 GET 404，且磁盘文件与 users.avatar 列同步清理。
func TestQAAvatarByteRoundtripAndFileCleanup(t *testing.T) {
	ts := newQAServerNoLimit(t)
	token := mustLogin(t, ts, "databk", "databk")
	payload := customWebp(t)

	// 上传。
	status, parsed := uploadAvatarBytes(t, ts, token, payload)
	if status != 200 {
		t.Fatalf("upload status = %d: %v", status, parsed)
	}
	filename, _ := parsed["avatar"].(string)
	if filename == "" {
		t.Fatalf("upload missing avatar filename: %v", parsed)
	}

	// 静态 GET：逐字节一致 + Content-Type。
	resp, err := ts.TS.Client().Get(ts.TS.URL + "/api/avatars/" + filename)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("avatar GET status = %d (%s)", resp.StatusCode, raw)
	}
	if !bytes.Equal(raw, payload) {
		t.Errorf("avatar bytes mismatch: got %d bytes, want %d identical bytes", len(raw), len(payload))
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/webp" {
		t.Errorf("Content-Type = %q, want image/webp", ct)
	}

	// DB avatar 列已登记。
	var avatarCol string
	if err := ts.DB.Raw("SELECT avatar FROM users WHERE username = ?", "databk").Scan(&avatarCol).Error; err != nil {
		t.Fatal(err)
	}
	if avatarCol != filename {
		t.Errorf("users.avatar = %q, want %q", avatarCol, filename)
	}

	// 删除 → 200；文件与列同步清理。
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodDelete,
		ts.TS.URL+"/api/users/me/avatar", nil, authHeader(token))
	if status != 200 {
		t.Fatalf("delete avatar status = %d: %v", status, parsed)
	}
	if _, err := os.Stat(filepath.Join(ts.Config.DataDir, "avatars", filename)); !os.IsNotExist(err) {
		t.Errorf("avatar file must be removed after delete, stat err = %v", err)
	}
	if err := ts.DB.Raw("SELECT avatar FROM users WHERE username = ?", "databk").Scan(&avatarCol).Error; err != nil {
		t.Fatal(err)
	}
	if avatarCol != "" {
		t.Errorf("users.avatar after delete = %q, want empty", avatarCol)
	}

	// 删除后静态 GET → 404 包络。
	status, parsed, _ = doJSON(t, ts.TS.Client(), http.MethodGet,
		ts.TS.URL+"/api/avatars/"+filename, nil, nil)
	assertEnvelope(t, status, parsed, 404, "Avatar not found")
}

// TestQAAvatarTraversalVariantsNeverLeak 路径穿越变体全集必须拒绝：
// 白名单正则 ^[a-f0-9-]+\.webp$ 与 resolve 双重防线之下，任何编码
// （%2e%2e、%2f、%00）或点段形态都不得以 200 泄漏 DataDir 内外文件内容。
// 客户端禁用重定向跟随，确保 mux 的路径清理 301 不掩盖首响应判定。
func TestQAAvatarTraversalVariantsNeverLeak(t *testing.T) {
	ts := newQAServerNoLimit(t)
	noRedirect := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	variants := []string{
		"..%2f..%2fgo.mod",                  // 编码斜杠回溯
		"%2e%2e%2fmain.go",                  // 全编码点段
		"..%5csecret.webp",                  // 反斜杠变体
		"a%00.webp",                         // 空字节注入
		"sub%2fdir%2ftrick.webp",            // 段内路径分隔
		"....webp",                          // 非法字符（点不在白名单）
		"e04e2b1e-0000-4000-8000-!bad.webp", // 混入白名单外字符
	}
	for _, name := range variants {
		req, err := http.NewRequest(http.MethodGet, ts.TS.URL+"/api/avatars/"+name, nil)
		if err != nil {
			t.Fatalf("build request for %q: %v", name, err)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatalf("GET avatar %q: %v", name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("avatar traversal variant %q returned 200 and must never leak content: %q", name, body)
		}
		switch resp.StatusCode {
		case http.StatusNotFound, http.StatusBadRequest, http.StatusMovedPermanently, http.StatusTemporaryRedirect:
			// 404（白名单/资源不存在）、400（mux 拒绝）、3xx（路径清理重定向）均为安全拒绝。
		default:
			t.Errorf("avatar variant %q unexpected status %d", name, resp.StatusCode)
		}
	}
}
