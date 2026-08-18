package entity

import "time"

// FileAudit file_audits 表实体：文件传输审计。
//
// 幂等：UNIQUE(deviceId, nonce)——nonce 冲突重查返回既有行（设计事实②）；
// nonce 为 NULL 的行不参与去重。Files 为 JSON 串（文件清单，mediumtext
// 容量档）。时间锚点：RequestedAt 由上报链赋值。
type FileAudit struct {
	Id          uint      `gorm:"column:id;primaryKey;autoIncrement"`
	DeviceId    string    `gorm:"column:deviceId;size:255;not null"`
	DeviceUuid  string    `gorm:"column:deviceUuid;size:36;not null"`
	PeerId      string    `gorm:"column:peerId;size:255;not null"`
	ConnId      *string   `gorm:"column:connId;size:64"`
	Type        int       `gorm:"column:type;not null;default:0"`
	Path        string    `gorm:"column:path"`
	IsFile      bool      `gorm:"column:isFile;not null;default:false"`
	ClientIp    *string   `gorm:"column:clientIp;size:64"`
	ClientName  *string   `gorm:"column:clientName;size:255"`
	FileCount   int       `gorm:"column:fileCount;not null;default:0"`
	Files       string    `gorm:"column:files"`
	Nonce       *string   `gorm:"column:nonce;size:36"`
	RequestedAt time.Time `gorm:"column:requestedAt;not null"`
	CreatedAt   time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (FileAudit) TableName() string { return "file_audits" }
