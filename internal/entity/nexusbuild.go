package entity

import "time"

// NexusBuild status 取值（轮询状态机：pending/building 参与轮询，
// 终态由 poller 下载产物后落库）。
const (
	NexusStatusPending  = "pending"
	NexusStatusBuilding = "building"
	NexusStatusDone     = "done"
	NexusStatusFailed   = "failed"
	NexusStatusCanceled = "canceled"
)

// NexusBuild nexus_builds 表实体：客户端定制构建任务。
//
// 主键 uuid（任务标识，非 guid 命名契约——参考实测即如此）；Custom/Files
// 为 JSON 串。轮询：10s 扫 pending|building（NexusBuildRepo.ListPolling）。
type NexusBuild struct {
	Uuid      string    `gorm:"column:uuid;primaryKey;size:36"`
	UserGuid  string    `gorm:"column:userGuid;size:36;not null"`
	Os        string    `gorm:"column:os;size:32;not null"`
	Arch      string    `gorm:"column:arch;size:32;not null"`
	AppName   *string   `gorm:"column:appName;size:255"`
	Custom    string    `gorm:"column:custom"`
	Status    string    `gorm:"column:status;size:32;not null;default:'pending'"`
	Files     string    `gorm:"column:files"`
	Message   string    `gorm:"column:message"`
	CreatedAt time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (NexusBuild) TableName() string { return "nexus_builds" }

// IsPolling 是否仍在轮询窗口内。
func (b NexusBuild) IsPolling() bool {
	return b.Status == NexusStatusPending || b.Status == NexusStatusBuilding
}
