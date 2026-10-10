package entity

import "time"

// 审计 result 取值（共享知识 6）。
const (
	AuditResultAllowed = "allowed"
	AuditResultDenied  = "denied"
)

// ConsoleAudit console_audits 表实体：控制台审计（写入端 M2，
// 查询端点 M3 提供）。ActorUserGuid 可空（系统级动作）。
type ConsoleAudit struct {
	Guid          string    `gorm:"column:guid;primaryKey;size:36"`
	ActorUserGuid *string   `gorm:"column:actorUserGuid;size:36"`
	TargetType    string    `gorm:"column:targetType;size:255;not null"`
	TargetGuid    string    `gorm:"column:targetGuid;size:36"`
	Action        string    `gorm:"column:action;size:255;not null"`
	Result        string    `gorm:"column:result;size:32;not null"`
	Reason        string    `gorm:"column:reason"`
	BeforeState   string    `gorm:"column:beforeState"`
	AfterState    string    `gorm:"column:afterState"`
	RequestID     string    `gorm:"column:requestId;size:36"`
	CreatedAt     time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (ConsoleAudit) TableName() string { return "console_audits" }
