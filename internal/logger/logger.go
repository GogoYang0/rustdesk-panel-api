// Package logger 构建 slog JSON 日志器，并提供 RequestID 上下文注入助手。
package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"
)

// requestIDKey 是 context 中存放 RequestID 的私有键。
type requestIDKey struct{}

// New 构建 JSON Handler 的 slog.Logger。
// level 解析失败时回退 info。
func New(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// ContextWithRequestID 将 requestID 写入 context。
func ContextWithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestIDFromContext 读取 requestID；缺失返回空串。
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

// WithRequestID 返回附带 requestId 字段的 logger（供 AccessLog 等使用）。
func WithRequestID(ctx context.Context, l *slog.Logger) *slog.Logger {
	if id := RequestIDFromContext(ctx); id != "" {
		return l.With("requestId", id)
	}
	return l
}
