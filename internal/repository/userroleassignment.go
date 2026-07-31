// Package repository 本文件：AssignmentRepo——user_role_assignments
// 表仓储（用户角色指派；替换为事务整删整插）。
package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// AssignmentWithGroups 指派及其设备组关联载荷（ReplaceAll 输入；
// Guid 由服务层生成，DeviceGroupGuids 仅 device_group 档非空）。
type AssignmentWithGroups struct {
	Assignment       entity.UserRoleAssignment
	DeviceGroupGuids []string
}

// AssignmentRepo user_role_assignments 表仓储。
type AssignmentRepo struct {
	*GenericRepository[entity.UserRoleAssignment]
}

// NewAssignmentRepo 构建仓储。
func NewAssignmentRepo(db *gorm.DB) *AssignmentRepo {
	return &AssignmentRepo{GenericRepository: New[entity.UserRoleAssignment](db)}
}

// ListByUser 用户全部指派（createdAt ASC 稳定序）。
func (r *AssignmentRepo) ListByUser(ctx context.Context, userGuid string) ([]entity.UserRoleAssignment, error) {
	out := make([]entity.UserRoleAssignment, 0)
	err := r.db.WithContext(ctx).
		Where("userGuid = ?", userGuid).
		Order("createdAt ASC").
		Find(&out).Error
	return out, err
}

// ListByUsers 批量用户指派（rbac 保护账号判定端口；缺失用户不出现在映射中）。
func (r *AssignmentRepo) ListByUsers(ctx context.Context, userGuids []string) (map[string][]entity.UserRoleAssignment, error) {
	out := make(map[string][]entity.UserRoleAssignment, len(userGuids))
	if len(userGuids) == 0 {
		return out, nil
	}
	rows := make([]entity.UserRoleAssignment, 0)
	err := r.db.WithContext(ctx).
		Where("userGuid IN ?", userGuids).
		Find(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, a := range rows {
		out[a.UserGuid] = append(out[a.UserGuid], a)
	}
	return out, nil
}

// ReplaceAll 事务整删整插用户全部指派（设计 §3.1：替换语义为全量
// 重建）。显式清理关联设备组（方言无关，共享知识 9），再删指派行、
// 整插新载荷（指派行 + 组关联）。
func (r *AssignmentRepo) ReplaceAll(ctx context.Context, userGuid string, items []AssignmentWithGroups) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var oldGuids []string
		if err := tx.Model(&entity.UserRoleAssignment{}).
			Where("userGuid = ?", userGuid).
			Pluck("guid", &oldGuids).Error; err != nil {
			return err
		}
		if len(oldGuids) > 0 {
			if err := tx.Where("assignmentGuid IN ?", oldGuids).
				Delete(&entity.UserRoleAssignmentDeviceGroup{}).Error; err != nil {
				return err
			}
			if err := tx.Where("userGuid = ?", userGuid).
				Delete(&entity.UserRoleAssignment{}).Error; err != nil {
				return err
			}
		}
		for _, item := range items {
			row := item.Assignment
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
			for _, g := range item.DeviceGroupGuids {
				link := &entity.UserRoleAssignmentDeviceGroup{AssignmentGuid: row.Guid, DeviceGroupGuid: g}
				if err := tx.Create(link).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// DeleteByRole 删除角色的全部指派（含关联组；角色删除级联，T05）。
func (r *AssignmentRepo) DeleteByRole(ctx context.Context, roleGuid string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var guids []string
		if err := tx.Model(&entity.UserRoleAssignment{}).
			Where("roleGuid = ?", roleGuid).
			Pluck("guid", &guids).Error; err != nil {
			return err
		}
		if len(guids) > 0 {
			if err := tx.Where("assignmentGuid IN ?", guids).
				Delete(&entity.UserRoleAssignmentDeviceGroup{}).Error; err != nil {
				return err
			}
		}
		return tx.Where("roleGuid = ?", roleGuid).
			Delete(&entity.UserRoleAssignment{}).Error
	})
}
