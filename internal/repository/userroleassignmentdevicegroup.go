// Package repository 本文件：AssignmentGroupRepo——
// user_role_assignment_device_groups 表仓储（指派设备组关联）。
package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// assignmentGroupRow GroupsByAssignments 的扫描行（显式列 tag）。
type assignmentGroupRow struct {
	AssignmentGuid  string `gorm:"column:assignmentGuid"`
	DeviceGroupGuid string `gorm:"column:deviceGroupGuid"`
}

// AssignmentGroupRepo user_role_assignment_device_groups 表仓储。
type AssignmentGroupRepo struct {
	*GenericRepository[entity.UserRoleAssignmentDeviceGroup]
}

// NewAssignmentGroupRepo 构建仓储。
func NewAssignmentGroupRepo(db *gorm.DB) *AssignmentGroupRepo {
	return &AssignmentGroupRepo{GenericRepository: New[entity.UserRoleAssignmentDeviceGroup](db)}
}

// GroupsByAssignments assignmentGuid → 设备组 guid 列表
// （rbac scope 计算端口；缺失的 assignmentGuid 不出现在映射中）。
func (r *AssignmentGroupRepo) GroupsByAssignments(ctx context.Context, assignmentGuids []string) (map[string][]string, error) {
	out := make(map[string][]string, len(assignmentGuids))
	if len(assignmentGuids) == 0 {
		return out, nil
	}
	rows := make([]assignmentGroupRow, 0)
	err := r.db.WithContext(ctx).Model(&entity.UserRoleAssignmentDeviceGroup{}).
		Where("assignmentGuid IN ?", assignmentGuids).
		Select("assignmentGuid", "deviceGroupGuid").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.AssignmentGuid] = append(out[row.AssignmentGuid], row.DeviceGroupGuid)
	}
	return out, nil
}

// ReplaceForAssignment 事务整删整插单个指派的设备组关联
// （device_group 档指派的组集更新）。
func (r *AssignmentGroupRepo) ReplaceForAssignment(ctx context.Context, assignmentGuid string, groupGuids []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("assignmentGuid = ?", assignmentGuid).
			Delete(&entity.UserRoleAssignmentDeviceGroup{}).Error; err != nil {
			return err
		}
		for _, g := range groupGuids {
			row := &entity.UserRoleAssignmentDeviceGroup{AssignmentGuid: assignmentGuid, DeviceGroupGuid: g}
			if err := tx.Create(row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// DeleteByAssignment 删除单个指派的全部组关联（指派行删除前显式清理，
// 方言无关）。
func (r *AssignmentGroupRepo) DeleteByAssignment(ctx context.Context, assignmentGuid string) error {
	return r.db.WithContext(ctx).
		Where("assignmentGuid = ?", assignmentGuid).
		Delete(&entity.UserRoleAssignmentDeviceGroup{}).Error
}
