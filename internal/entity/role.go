package entity

import "time"

// Role roles 表实体：RBAC 角色。
//
// ProtectedAccount：保护角色——持有该角色的用户受保护（仅超管可改/
// 不可删除），保护判定走 assignments 联查（rbac.IsProtectedUser）。
type Role struct {
	Guid             string    `gorm:"column:guid;primaryKey;size:36"`
	Name             string    `gorm:"column:name;size:255;not null"`
	Note             string    `gorm:"column:note"`
	ProtectedAccount bool      `gorm:"column:protectedAccount;not null;default:false"`
	CreatedAt        time.Time `gorm:"column:createdAt"`
	UpdatedAt        time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (Role) TableName() string { return "roles" }
