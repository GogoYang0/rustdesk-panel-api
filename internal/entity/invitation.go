package entity

import "time"

// Invitation invitations 表实体：邀请注册状态机（设计 §4.1）。
//
// 生命周期：Invite 建行（token=32B hex、expiresAt=+7d、userGuid 指向
// 新建的 UNVERIFIED 用户）→ Verify（公开校验）→ Accept（usedAt=now）。
// UserGuid 可空：MySQL 侧 FK invitations_user（ON DELETE SET NULL），
// SQLite 侧无 FK（应用层保证，共享知识 9）。
type Invitation struct {
	Guid          string     `gorm:"column:guid;primaryKey;size:36"`
	Token         string     `gorm:"column:token;size:64;not null"`
	Email         string     `gorm:"column:email;size:255;not null"`
	Name          string     `gorm:"column:name;size:255;not null"`
	DisplayName   *string    `gorm:"column:displayName;size:255"`
	UserGroupGuid *string    `gorm:"column:userGroupGuid;size:36"`
	Note          string     `gorm:"column:note"`
	UserGuid      *string    `gorm:"column:userGuid;size:36"`
	ExpiresAt     time.Time  `gorm:"column:expiresAt;not null"`
	UsedAt        *time.Time `gorm:"column:usedAt"`
	CreatedAt     time.Time  `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (Invitation) TableName() string { return "invitations" }

// IsExpired 是否已过期（verify/accept 前置校验）。
func (i Invitation) IsExpired(now time.Time) bool { return now.After(i.ExpiresAt) }

// IsUsed 是否已被接受。
func (i Invitation) IsUsed() bool { return i.UsedAt != nil }
