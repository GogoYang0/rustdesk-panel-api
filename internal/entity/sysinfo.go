package entity

import "time"

// Sysinfo sysinfos 表实体：设备系统信息（uuid PK，与 peers.uuid 逻辑
// 关联，无 FK——设备可不注册直接上报被拒，共享知识 / 设计 §4.2）。
//
// 列名契约（共享知识 11）：preset_* 三列为 snake_case——与全库
// camelCase 惯例不同，是契约本身，GORM tag 显式声明、列断言测试锁定。
type Sysinfo struct {
	UUID                  string    `gorm:"column:uuid;primaryKey;size:36"`
	Hostname              string    `gorm:"column:hostname;size:255"`
	Username              string    `gorm:"column:username;size:255"`
	OS                    string    `gorm:"column:os;size:255"`
	CPU                   string    `gorm:"column:cpu;size:255"`
	Memory                string    `gorm:"column:memory;size:255"`
	PresetUsername        string    `gorm:"column:preset_username;size:255"`
	PresetStrategyName    string    `gorm:"column:preset_strategy_name;size:255"`
	PresetDeviceGroupName string    `gorm:"column:preset_device_group_name;size:255"`
	CreatedAt             time.Time `gorm:"column:createdAt"`
	UpdatedAt             time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (Sysinfo) TableName() string { return "sysinfos" }
