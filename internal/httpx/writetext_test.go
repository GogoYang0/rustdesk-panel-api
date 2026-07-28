package httpx

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWriteText 覆盖 M2 设备端协议 sysinfo 出口：Content-Type text/plain。
func TestWriteText(t *testing.T) {
	w := httptest.NewRecorder()
	WriteText(w, 200, "SYSINFO_UPDATED")
	if w.Code != 200 {
		t.Errorf("code = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("content-type = %q, want text/plain; charset=utf-8", ct)
	}
	if body := w.Body.String(); body != "SYSINFO_UPDATED" {
		t.Errorf("body = %q", body)
	}

	w2 := httptest.NewRecorder()
	WriteText(w2, 200, "ID_NOT_FOUND")
	if w2.Code != 200 || w2.Body.String() != "ID_NOT_FOUND" {
		t.Errorf("ID_NOT_FOUND write = %d %q", w2.Code, w2.Body.String())
	}
	if !strings.HasPrefix(w2.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("content-type = %q", w2.Header().Get("Content-Type"))
	}
}
