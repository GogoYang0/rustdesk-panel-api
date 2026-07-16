package entity

import "time"

// LoginSession login_sessions 表实体。
// 两步验证临时会话：guid 即对外 secret（共享知识 3），
// method ∈ email|tfa|passkey_reg|passkey|passkey_tfa（共享知识 7）。
type LoginSession struct {
	Guid      string    `gorm:"column:guid;primaryKey;size:36"`
	UserGuid  string    `gorm:"column:userGuid;size:36;not null"`
	Method    string    `gorm:"column:method;size:32;not null"`
	Email     string    `gorm:"column:email;size:255"`
	Code      string    `gorm:"column:code;size:255"`
	ExpiresAt time.Time `gorm:"column:expiresAt;not null"`
	Used      bool      `gorm:"column:used;not null;default:false"`
}

// TableName 指定表名。
func (LoginSession) TableName() string { return "login_sessions" }
