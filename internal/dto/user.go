// Package dto 定义 user 域请求/响应载体。
// user 域请求字段为 snake_case（契约红线，禁止"规范化"）。
package dto

import "github.com/rustdesk-panel/rustdesk-panel-api/internal/api"

// UpdateMeRequest PATCH /api/users/me 请求体（snake_case 契约）。
// 指针语义：nil 字段不更新。
type UpdateMeRequest struct {
	DisplayName *string `json:"display_name"`
	Email       *string `json:"email"`
	Note        *string `json:"note"`
}

// ChangePasswordRequest PATCH /api/users/me/password 请求体。
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// AvatarResponse 头像上传响应：文件名 {guid}.webp。
type AvatarResponse struct {
	Avatar string `json:"avatar"`
}

// Message 是通用 message 响应的便捷构造。
func Message(text string) api.MessageResponse {
	return api.MessageResponse{Message: text}
}
