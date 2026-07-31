package entity

import "time"

// ActiveConnection active_connections 表实体：设备活跃连接快照
// （心跳 conns diff 同步，事务内增删，设计 §4.1 步骤 6）。
type ActiveConnection struct {
	ID         int64     `gorm:"column:id;primaryKey;autoIncrement"`
	ConnID     int64     `gorm:"column:connId;not null"`
	DeviceUuid string    `gorm:"column:deviceUuid;size:36;not null"`
	CreatedAt  time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (ActiveConnection) TableName() string { return "active_connections" }
