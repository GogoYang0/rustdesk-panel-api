package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLevels(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"WARN":  slog.LevelWarn,
		"error": slog.LevelError,
		"":      slog.LevelInfo,
		"bogus": slog.LevelInfo,
	}
	for in, want := range cases {
		l := New(in)
		if !l.Enabled(context.Background(), want) {
			t.Errorf("New(%q) not enabled for level %v", in, want)
		}
	}
}

func TestRequestIDContext(t *testing.T) {
	ctx := context.Background()
	if got := RequestIDFromContext(ctx); got != "" {
		t.Errorf("RequestIDFromContext(empty ctx) = %q, want empty", got)
	}
	ctx = ContextWithRequestID(ctx, "req-1")
	if got := RequestIDFromContext(ctx); got != "req-1" {
		t.Errorf("RequestIDFromContext = %q, want req-1", got)
	}
}

func TestWithRequestID(t *testing.T) {
	var buf bytes.Buffer
	base := slog.New(slog.NewJSONHandler(&buf, nil))

	// 无 requestID：不加字段。
	buf.Reset()
	WithRequestID(context.Background(), base).Info("hello")
	if strings.Contains(buf.String(), "requestId") {
		t.Errorf("log without requestID should not contain requestId: %s", buf.String())
	}

	// 有 requestID：注入字段。
	buf.Reset()
	ctx := ContextWithRequestID(context.Background(), "req-42")
	WithRequestID(ctx, base).Info("hello")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not json: %v", err)
	}
	if rec["requestId"] != "req-42" {
		t.Errorf("requestId = %v, want req-42", rec["requestId"])
	}
}
