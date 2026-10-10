// Package entity 定义 GORM 实体：列名 = DB 契约（camelCase 原样，
// sysinfos 的 preset_* 为 snake_case 例外，见 sysinfo.go），
// 与迁移 SQL 逐列一致（migration 列断言测试保障）。
package entity

import "time"

// Strategy strategies 表实体：下发策略（configOptions 存 JSON 串原文，
// API 层字段名 config_options，禁止规范化）。
type Strategy struct {
	Guid          string    `gorm:"column:guid;primaryKey;size:36"`
	Name          string    `gorm:"column:name;size:255;not null"`
	Note          string    `gorm:"column:note"`
	ConfigOptions string    `gorm:"column:configOptions"`
	CreatedAt     time.Time `gorm:"column:createdAt"`
	UpdatedAt     time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (Strategy) TableName() string { return "strategies" }
