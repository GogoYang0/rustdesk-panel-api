// Package dto 认证域服务层数据传输对象与响应组装。
//
// 命名红线（共享知识 2）：auth 域请求字段 camelCase（由 openapi 生成类型保证）；
// 响应 user payload snake_case（BuildUserPayload）；JWT payload camelCase
// （isAdmin、deviceId）。本包类型是对 internal/api 生成类型的补充——
// 服务层内部流转与"契约外响应形状"（如 BeginAuthResult）在此定义。
package dto

import (
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// LoginDevice 归一化设备信息（请求 id/uuid/deviceInfo 展平，
// 用于 user_tokens 设备维度记录与撤销）。
type LoginDevice struct {
	Id   string
	Uuid string
	Name string
	Os   string
	Type string
}

// DeviceFromRequest 从请求字段组装设备信息。
func DeviceFromRequest(id, deviceUuid string, info *api.DeviceInfo) LoginDevice {
	dev := LoginDevice{Id: id, Uuid: deviceUuid}
	if info != nil {
		if info.Name != nil {
			dev.Name = *info.Name
		}
		if info.Os != nil {
			dev.Os = *info.Os
		}
		if info.Type != nil {
			dev.Type = *info.Type
		}
	}
	return dev
}

// SetupTfaResult POST /api/2fa/setup 响应：{secret, otpauth_url}（snake_case 契约）。
type SetupTfaResult struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
}

// BeginAuthResult POST /api/passkey/auth/begin 响应：{secret, options}。
// options 为 PublicKeyCredentialRequestOptionsJSON 通用形状。
type BeginAuthResult struct {
	Secret  string         `json:"secret"`
	Options map[string]any `json:"options"`
}

// VerifyAuthRequest POST /api/passkey/auth/verify 请求的服务层归一化视图。
type VerifyAuthRequest struct {
	Secret   string
	Response map[string]any
	Device   LoginDevice
}

// CallbackQuery GET /api/oidc/callback 查询参数。
type CallbackQuery struct {
	Code  string
	State string
	Error string
}

// CallbackResult OIDC 回调渲染结果（handler 据此选择模板与跳转脚本）。
type CallbackResult struct {
	OK      bool
	Title   string
	Message string
	// RedirectURL 非空时页面脚本自动跳转（web 模式，携带 token fragment）。
	RedirectURL string
}

// AuthQueryResult GET /api/oidc/auth-query 响应（status: pending|success|error）。
type AuthQueryResult struct {
	Status  string `json:"status"`
	Token   string `json:"token,omitempty"`
	Message string `json:"message,omitempty"`
}

// BuildUserPayload 组装 snake_case 用户响应 payload（契约，禁止改名）。
//
// 语义前提：u 来自全列加载（WithSecrets 系仓储方法）——
// tfa_enabled/has_password/verifier 仅在敏感列确实加载后返回（共享知识 5）。
func BuildUserPayload(u *entity.User) api.UserPayload {
	payload := api.UserPayload{
		Guid:    u.Guid,
		Name:    u.Username,
		IsAdmin: u.IsAdmin,
	}
	if u.DisplayName != "" {
		displayName := u.DisplayName
		payload.DisplayName = &displayName
	}
	if u.Email != "" {
		email := u.Email
		payload.Email = &email
	}
	if u.Note != "" {
		note := u.Note
		payload.Note = &note
	}
	if u.Avatar != "" {
		avatar := u.Avatar
		payload.Avatar = &avatar
	}
	if u.StrategyGuid != nil && *u.StrategyGuid != "" {
		payload.StrategyGuid = u.StrategyGuid
	}
	if u.UserGroupGuid != nil && *u.UserGroupGuid != "" {
		payload.UserGroupGuid = u.UserGroupGuid
	}
	if u.ThirdAuthType != "" {
		third := u.ThirdAuthType
		payload.ThirdAuthType = &third
	}
	hasPassword := u.Password != ""
	payload.HasPassword = &hasPassword
	tfaEnabled := u.TfaEnabled()
	payload.TfaEnabled = &tfaEnabled
	if u.Verifier != "" {
		verifier := u.Verifier
		payload.Verifier = &verifier
	}
	return payload
}
