// Package httpx 提供统一响应出口、NestJS 兼容错误包络与请求绑定校验。
//
// 契约红线（共享知识 1）：成功不做业务包裹，直接返回业务 JSON；
// 错误统一 {statusCode, message, error}，message 三种形态并存：
// 业务对象（{"error": "..."}）、纯文本字符串、校验错误字符串数组。
package httpx

import (
	"encoding/json"
	"net/http"
)

// ErrorEnvelope 对齐 NestJS 默认异常过滤器形状。
type ErrorEnvelope struct {
	StatusCode int    `json:"statusCode"`
	Message    any    `json:"message"`
	Error      string `json:"error"`
}

// WriteJSON 成功出口：直接序列化业务 JSON（POST 成功一律 200，不用 201）。
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// 头部已发出，Encode 失败只能丢弃（调用侧应保证数据可序列化）。
	_ = json.NewEncoder(w).Encode(v)
}

// WriteText 纯文本成功出口（M2 设备端协议 sysinfo 专用）：
// Content-Type: text/plain; charset=utf-8，恒按调用方状态码写出
// （sysinfo 语义恒 200）。
func WriteText(w http.ResponseWriter, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(text))
}

// Fail 通用错误出口：message 原样透出（string / []string / map）。
func Fail(w http.ResponseWriter, status int, message any) {
	writeEnvelope(w, status, message)
}

func writeEnvelope(w http.ResponseWriter, status int, message any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorEnvelope{
		StatusCode: status,
		Message:    message,
		Error:      http.StatusText(status),
	})
}

// ErrBadRequest 业务校验失败：message 为 {"error": errorText} 对象形态
// （对齐参考 BadRequestException({error: "..."})）。
func ErrBadRequest(w http.ResponseWriter, errorText string) {
	writeEnvelope(w, http.StatusBadRequest, map[string]string{"error": errorText})
}

// ErrBadRequestMessages 校验错误：message 为字符串数组
// （对齐 class-validator + forbidNonWhitelisted）。
func ErrBadRequestMessages(w http.ResponseWriter, messages []string) {
	writeEnvelope(w, http.StatusBadRequest, messages)
}

// ErrUnauthorized 纯文本 message（如 "Token expired or revoked"）。
func ErrUnauthorized(w http.ResponseWriter, text string) {
	writeEnvelope(w, http.StatusUnauthorized, text)
}

// ErrNotFound 资源不存在（用户/会话/头像等）。
func ErrNotFound(w http.ResponseWriter, text string) {
	writeEnvelope(w, http.StatusNotFound, text)
}

// ErrConflict 用户名或邮箱冲突等。
func ErrConflict(w http.ResponseWriter, text string) {
	writeEnvelope(w, http.StatusConflict, text)
}

// ErrTooMany 限流固定文案（对齐 @nestjs/throttler）。
func ErrTooMany(w http.ResponseWriter) {
	writeEnvelope(w, http.StatusTooManyRequests, "ThrottlerException: Too many requests")
}

// ErrInternal 固定文案，不泄漏内部细节。
func ErrInternal(w http.ResponseWriter) {
	writeEnvelope(w, http.StatusInternalServerError, "Internal server error")
}
