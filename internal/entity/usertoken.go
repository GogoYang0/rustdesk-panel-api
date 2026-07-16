package entity

import "time"

// UserToken user_tokens 表实体。
// guid 恒等于 jti（共享知识 3），有状态撤销按 (userGuid, jti, isRevoked) 校验。
type UserToken struct {
	Guid       string    `gorm:"column:guid;primaryKey;size:36"`
	UserGuid   string    `gorm:"column:userGuid;size:36;not null"`
	Jti        string    `gorm:"column:jti;size:36;not null"`
	DeviceId   string    `gorm:"column:deviceId;size:255"`
	DeviceUuid string    `gorm:"column:deviceUuid;size:255"`
	ExpiresAt  time.Time `gorm:"column:expiresAt;not null"`
	IsRevoked  bool      `gorm:"column:isRevoked;not null;default:false"`
	DeviceOs   string    `gorm:"column:deviceOs;size:255"`
	DeviceType string    `gorm:"column:deviceType;size:255"`
	DeviceName string    `gorm:"column:deviceName;size:255"`
	CreatedAt  time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (UserToken) TableName() string { return "user_tokens" }
