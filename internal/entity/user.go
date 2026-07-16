// Package entity 定义 GORM 实体：列名 = DB 契约（camelCase 原样），
// 与迁移 SQL 逐列一致（migration 列断言测试保障）。
package entity

import (
	"encoding/json"
	"time"
)

// User users 表实体。
//
// 敏感列 password / verifier / tfaSecret / emailVerificationCode 按参考
// select:false 语义默认不查（UserRepo 公共列查询），凭
// FindByUsernameOrEmail / FindByGuidWithSecrets 显式加载。
type User struct {
	Guid                  string    `gorm:"column:guid;primaryKey;size:36"`
	Username              string    `gorm:"column:username;size:255;not null"`
	DisplayName           string    `gorm:"column:displayName;size:255"`
	Email                 string    `gorm:"column:email;size:255"`
	Password              string    `gorm:"column:password;size:255"`
	Note                  string    `gorm:"column:note"`
	Verifier              string    `gorm:"column:verifier"`
	Status                int       `gorm:"column:status;not null;default:0"`
	IsAdmin               bool      `gorm:"column:isAdmin;not null;default:false"`
	EmailVerificationCode string    `gorm:"column:emailVerificationCode;size:255"`
	TfaSecret             string    `gorm:"column:tfaSecret;size:255"`
	Info                  string    `gorm:"column:info"`
	ThirdAuthType         string    `gorm:"column:thirdAuthType;size:255"`
	OidcSubject           string    `gorm:"column:oidcSubject;size:255"`
	Avatar                string    `gorm:"column:avatar;size:255"`
	// 可空外键列：SET NULL 语义（迁移 SQL 契约），用指针正确建模 NULL。
	StrategyGuid  *string   `gorm:"column:strategyGuid;size:36"`
	UserGroupGuid *string   `gorm:"column:userGroupGuid;size:36"`
	CreatedAt     time.Time `gorm:"column:createdAt"`
	UpdatedAt     time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (User) TableName() string { return "users" }

// UserInfo 是 users.info JSON 的结构化视图（共享知识 6：
// 2FA/Passkey 隐蔽状态存 info.other，非独立列）。
type UserInfo struct {
	Other map[string]any `json:"other,omitempty"`
}

// ParseUserInfo 解析 Info JSON；空/坏数据返回空视图。
func (u *User) ParseUserInfo() UserInfo {
	if u.Info == "" {
		return UserInfo{Other: map[string]any{}}
	}
	var info UserInfo
	if err := json.Unmarshal([]byte(u.Info), &info); err != nil {
		return UserInfo{Other: map[string]any{}}
	}
	if info.Other == nil {
		info.Other = map[string]any{}
	}
	return info
}

// SetUserInfo 序列化回 Info 列。
func (u *User) SetUserInfo(info UserInfo) {
	if info.Other == nil {
		info.Other = map[string]any{}
	}
	raw, err := json.Marshal(info)
	if err != nil {
		u.Info = "{}"
		return
	}
	u.Info = string(raw)
}

// TfaPendingSecret 读取待绑定的 TOTP secret（info.other.tfa_pending_secret）。
func (i UserInfo) TfaPendingSecret() string {
	if v, ok := i.Other["tfa_pending_secret"].(string); ok {
		return v
	}
	return ""
}

// SetTfaPendingSecret 写入待绑定的 TOTP secret（空串表示清除）。
func (i UserInfo) SetTfaPendingSecret(s string) {
	if s == "" {
		delete(i.Other, "tfa_pending_secret")
		return
	}
	i.Other["tfa_pending_secret"] = s
}

// PasskeyTfaEnabled 读取 passkey 作为 2FA 的开关（info.other.passkey_tfa_enabled）。
func (i UserInfo) PasskeyTfaEnabled() bool {
	v, _ := i.Other["passkey_tfa_enabled"].(bool)
	return v
}

// SetPasskeyTfaEnabled 写入 passkey 2FA 开关。
func (i UserInfo) SetPasskeyTfaEnabled(b bool) {
	if !b {
		delete(i.Other, "passkey_tfa_enabled")
		return
	}
	i.Other["passkey_tfa_enabled"] = true
}

// TfaEnabled 报告用户是否已绑定 TOTP。
func (u *User) TfaEnabled() bool { return u.TfaSecret != "" }
