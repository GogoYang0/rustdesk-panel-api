package entity

import "time"

// AlarmAudit alarm_audits 表实体：告警审计。
//
// 幂等：UNIQUE(deviceId, nonce)——同 file_audits；nonce 为 NULL 不参与
// 去重。CreatedAt 为落库时刻（应用层赋值）：类图未列时间字段，但仪表盘
// alarmTrend 按日聚合必需（设计事实⑥），故迁移补列 + IDX。
type AlarmAudit struct {
	Id           uint      `gorm:"column:id;primaryKey;autoIncrement"`
	DeviceId     string    `gorm:"column:deviceId;size:255;not null"`
	DeviceUuid   string    `gorm:"column:deviceUuid;size:36;not null"`
	Typ          int       `gorm:"column:typ;not null;default:0"`
	InfoId       *string   `gorm:"column:infoId;size:255"`
	InfoIp       *string   `gorm:"column:infoIp;size:64"`
	InfoName     *string   `gorm:"column:infoName;size:255"`
	ConnId       *string   `gorm:"column:connId;size:64"`
	Nonce        *string   `gorm:"column:nonce;size:36"`
	ConnAuditRef *string   `gorm:"column:connAuditRef;size:36"`
	CreatedAt    time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (AlarmAudit) TableName() string { return "alarm_audits" }
