// Package auth 认证域服务：JWT 有状态会话、登录分发、TOTP 2FA、
// WebAuthn/Passkey、OIDC 授权流与过期数据清理。
//
// 层次约定：本包只编排 repository 与外部协议库，不直接触碰 GORM；
// 错误统一以 ServiceError 携带 HTTP 语义，由 handler 层映射为
// NestJS 兼容错误包络（共享知识 1/13）。
package auth

import (
	"fmt"
	"time"
)

// ServiceError 携带 HTTP 语义的服务层错误。
// Message 遵循错误包络三种形态：400 业务错误为 {"error": text} 对象，
// 401/404 为纯文本字符串（共享知识 1）。
type ServiceError struct {
	Status  int
	Message any
}

// Error 实现 error 接口（纯文本形态直接透出，对象形态输出稳定描述）。
func (e *ServiceError) Error() string {
	if s, ok := e.Message.(string); ok {
		return s
	}
	if m, ok := e.Message.(map[string]string); ok {
		if text, ok := m["error"]; ok {
			return text
		}
	}
	return fmt.Sprintf("service error (status=%d)", e.Status)
}

// BadRequest 400 业务校验失败（message 为对象形态）。
func BadRequest(text string) *ServiceError {
	return &ServiceError{Status: 400, Message: map[string]string{"error": text}}
}

// Unauthorized 401 凭证/会话错误（message 为纯文本形态）。
func Unauthorized(text string) *ServiceError {
	return &ServiceError{Status: 401, Message: text}
}

// NotFound 404 资源不存在（message 为纯文本形态）。
func NotFound(text string) *ServiceError {
	return &ServiceError{Status: 404, Message: text}
}

// Conflict 409 冲突（message 为对象形态）。
func Conflict(text string) *ServiceError {
	return &ServiceError{Status: 409, Message: map[string]string{"error": text}}
}

// 固定文案（契约常量，测试断言依赖）。
const (
	// msgBadCredentials 登录失败统一文案（不区分用户不存在/密码错误）。
	msgBadCredentials = "Username or password is incorrect"
	// msgUserDisabled 账号被禁用（status != 1）。
	msgUserDisabled = "User is disabled"
	// msgStepSessionInvalid 两步验证会话无效/过期/复用。
	msgStepSessionInvalid = "Invalid or expired verification session"
	// msgTfaCodeInvalid 验证码错误（TOTP 或邮箱验证码）。
	msgTfaCodeInvalid = "Invalid verification code"
	// msgPasskeyRejected WebAuthn 校验失败统一文案。
	msgPasskeyRejected = "Passkey verification failed"
)

// 两步登录会话 TTL（共享知识 7：TFA/Email/Passkey 均 5 分钟）。
const twoStepTTL = 5 * time.Minute

// login_sessions.method 白名单值（共享知识 7）。
const (
	sessionMethodEmail      = "email"
	sessionMethodTfa        = "tfa"
	sessionMethodPasskeyReg = "passkey_reg"
	sessionMethodPasskey    = "passkey"
	sessionMethodPasskeyTfa = "passkey_tfa"
)

// oidc_auth_states.status 状态机取值。
const (
	oidcStatusPending = "pending"
	oidcStatusSuccess = "success"
	oidcStatusError   = "error"
)
