package entity

import "time"

// SystemSetting system_settings 表实体：系统设置 KV（M3 settings 域）。
//
// 主键列 key（保留字，MySQL 方言反引号包裹；GORM 引用由驱动转义）。
// Value 为 JSON 串或明文；IsSensitive 标记掩码键（smtp/ldap 密码类，
// 回读掩码/跳更约定见设计 settings 段）。
type SystemSetting struct {
	Key         string    `gorm:"column:key;primaryKey;size:255"`
	Value       string    `gorm:"column:value"`
	Category    string    `gorm:"column:category;size:64;not null;default:''"`
	Description *string   `gorm:"column:description;size:255"`
	IsSensitive bool      `gorm:"column:isSensitive;not null;default:false"`
	UpdatedAt   time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (SystemSetting) TableName() string { return "system_settings" }
