package entity

import "time"

// 用户角色指派 scope_type 取值（共享知识 6）。
const (
	ScopeTypeGlobal      = "global"
	ScopeTypeDeviceGroup = "device_group"
)

// UserRoleAssignment user_role_assignments 表实体：用户角色指派
// （UQ(userGuid, roleGuid)：同一用户同一角色至多一条，组维度差异由
// user_role_assignment_device_groups 承载）。
type UserRoleAssignment struct {
	Guid      string    `gorm:"column:guid;primaryKey;size:36"`
	UserGuid  string    `gorm:"column:userGuid;size:36;not null"`
	RoleGuid  string    `gorm:"column:roleGuid;size:36;not null"`
	ScopeType string    `gorm:"column:scopeType;size:255;not null"`
	CreatedAt time.Time `gorm:"column:createdAt"`
	UpdatedAt time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (UserRoleAssignment) TableName() string { return "user_role_assignments" }
