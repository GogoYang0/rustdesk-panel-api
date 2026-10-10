package entity

// UserRoleAssignmentDeviceGroup user_role_assignment_device_groups 表实体：
// device_group 档指派的设备组授权范围（复合 PK；device_groups 侧 FK 为
// RESTRICT——删除被引用组由应用层 400 拦截 + DB 兜底）。
type UserRoleAssignmentDeviceGroup struct {
	AssignmentGuid  string `gorm:"column:assignmentGuid;primaryKey;size:36"`
	DeviceGroupGuid string `gorm:"column:deviceGroupGuid;primaryKey;size:36"`
}

// TableName 指定表名。
func (UserRoleAssignmentDeviceGroup) TableName() string {
	return "user_role_assignment_device_groups"
}
