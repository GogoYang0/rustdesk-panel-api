package entity

import "time"

// NexusToken nexus_tokens 表实体：GitHub 设备码流绑定态。
//
// 主键 userGuid（每用户一条绑定记录，unbind 即删行）；
// CurrentUuid 为绑定期间轮询用的 login uuid。
type NexusToken struct {
	UserGuid      string    `gorm:"column:userGuid;primaryKey;size:36"`
	NexusToken    string    `gorm:"column:nexusToken;size:255;not null"`
	NexusUsername *string   `gorm:"column:nexusUsername;size:255"`
	ExpiresAt     time.Time `gorm:"column:expiresAt;not null"`
	CurrentUuid   *string   `gorm:"column:currentUuid;size:36"`
	CreatedAt     time.Time `gorm:"column:createdAt"`
	UpdatedAt     time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (NexusToken) TableName() string { return "nexus_tokens" }
