package entity

import "time"

// UserUserPermission user_user_permissions 表实体：
// 用户 → 用户的设备可见性授权（复合 PK；/peers 三源可见性之一，
// targetUserGuid 名下设备对 userGuid 可见）。
type UserUserPermission struct {
	UserGuid       string    `gorm:"column:userGuid;primaryKey;size:36"`
	TargetUserGuid string    `gorm:"column:targetUserGuid;primaryKey;size:36"`
	CreatedAt      time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (UserUserPermission) TableName() string { return "user_user_permissions" }
