package entity

import "time"

// DeviceGroupUserPermission device_group_user_permissions 表实体：
// 设备组 → 用户的显式授权关联（复合 PK；/peers 三源可见性之一）。
type DeviceGroupUserPermission struct {
	DeviceGroupGuid string    `gorm:"column:deviceGroupGuid;primaryKey;size:36"`
	UserGuid        string    `gorm:"column:userGuid;primaryKey;size:36"`
	CreatedAt       time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (DeviceGroupUserPermission) TableName() string { return "device_group_user_permissions" }
