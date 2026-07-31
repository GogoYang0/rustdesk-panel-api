// Package repository 本文件：DeviceGroupPermissionRepo——
// device_group_user_permissions 表仓储（设备组显式授权关联）。
package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// DeviceGroupPermissionRepo device_group_user_permissions 表仓储。
type DeviceGroupPermissionRepo struct {
	*GenericRepository[entity.DeviceGroupUserPermission]
}

// NewDeviceGroupPermissionRepo 构建仓储。
func NewDeviceGroupPermissionRepo(db *gorm.DB) *DeviceGroupPermissionRepo {
	return &DeviceGroupPermissionRepo{GenericRepository: New[entity.DeviceGroupUserPermission](db)}
}

// ListByUser 用户被显式授权的设备组关联行（/peers 三源之一、
// device-group accessible 补充源）。
func (r *DeviceGroupPermissionRepo) ListByUser(ctx context.Context, userGuid string) ([]entity.DeviceGroupUserPermission, error) {
	out := make([]entity.DeviceGroupUserPermission, 0)
	err := r.db.WithContext(ctx).
		Where("userGuid = ?", userGuid).
		Order("deviceGroupGuid ASC").
		Find(&out).Error
	return out, err
}

// ReplaceForGroup 事务整删整插组的授权用户清单（T04 组成员管理）。
func (r *DeviceGroupPermissionRepo) ReplaceForGroup(ctx context.Context, groupGuid string, userGuids []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("deviceGroupGuid = ?", groupGuid).
			Delete(&entity.DeviceGroupUserPermission{}).Error; err != nil {
			return err
		}
		for _, ug := range userGuids {
			row := &entity.DeviceGroupUserPermission{DeviceGroupGuid: groupGuid, UserGuid: ug}
			if err := tx.Create(row).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
