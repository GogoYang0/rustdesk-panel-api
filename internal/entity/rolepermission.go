package entity

// RolePermission role_permissions 表实体：角色 → 权限码关联
// （复合 PK；权限码即契约，见 rbac 目录 36 码）。
type RolePermission struct {
	RoleGuid       string `gorm:"column:roleGuid;primaryKey;size:36"`
	PermissionCode string `gorm:"column:permissionCode;primaryKey;size:255"`
}

// TableName 指定表名。
func (RolePermission) TableName() string { return "role_permissions" }
