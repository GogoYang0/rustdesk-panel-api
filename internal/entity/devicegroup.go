package entity

import "time"

// DeviceGroup device_groups 表实体。
//
// StrategyGuid 可空外键：SET NULL 语义（迁移 SQL 契约，删除策略置空
// 由应用层事务保证），用指针正确建模 NULL。
type DeviceGroup struct {
	Guid         string    `gorm:"column:guid;primaryKey;size:36"`
	Name         string    `gorm:"column:name;size:255;not null"`
	Note         string    `gorm:"column:note"`
	StrategyGuid *string   `gorm:"column:strategyGuid;size:36"`
	CreatedAt    time.Time `gorm:"column:createdAt"`
	UpdatedAt    time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (DeviceGroup) TableName() string { return "device_groups" }
