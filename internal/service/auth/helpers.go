package auth

import (
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// marshalInfo 序列化 UserInfo 回 Info 列存储
// （复用 entity.User.SetUserInfo 的契约序列化逻辑）。
func marshalInfo(info entity.UserInfo) string {
	u := &entity.User{}
	u.SetUserInfo(info)
	return u.Info
}
