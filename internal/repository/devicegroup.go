// Package repository 本文件：DeviceGroupRepo——device_groups 表仓储
// （设备组；accessible 列表含 scope ∪ 显式授权双源）。
package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// DeviceGroupRepo device_groups 表仓储。
type DeviceGroupRepo struct {
	*GenericRepository[entity.DeviceGroup]
}

// NewDeviceGroupRepo 构建仓储。
func NewDeviceGroupRepo(db *gorm.DB) *DeviceGroupRepo {
	return &DeviceGroupRepo{GenericRepository: New[entity.DeviceGroup](db)}
}

// FindByName 精确名称查询；未找到返回 ErrNotFound。
func (r *DeviceGroupRepo) FindByName(ctx context.Context, name string) (*entity.DeviceGroup, error) {
	var g entity.DeviceGroup
	err := r.db.WithContext(ctx).Where("name = ?", name).First(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// ListAccessible 设备组分页（device-group accessible 语义）：
// Global 全量；scoped = RBAC scope 组 ∪ device_group_user_permissions
// 显式授权组。name 为 LIKE 过滤（可空）。
func (r *DeviceGroupRepo) ListAccessible(ctx context.Context, userGuid string, scope GuidSet, name string, q Query) ([]entity.DeviceGroup, int64, error) {
	conds := make([]Clause, 0, 1)
	if name != "" {
		conds = append(conds, Clause{Field: "name", Op: OpLike, Value: like(name)})
	}
	countBase := r.accessibleBase(ctx, userGuid, scope, conds)
	var total int64
	if err := countBase.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := r.accessibleBase(ctx, userGuid, scope, conds)
	if q.OrderBy != "" {
		fetch = fetch.Order(q.OrderBy)
	}
	if q.Limit > 0 {
		fetch = fetch.Limit(q.Limit)
		if q.Offset > 0 {
			fetch = fetch.Offset(q.Offset)
		}
	}
	out := make([]entity.DeviceGroup, 0)
	if err := fetch.Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// accessibleBase 构建 accessible 查询链（count/fetch 各自独立调用）。
func (r *DeviceGroupRepo) accessibleBase(ctx context.Context, userGuid string, scope GuidSet, conds []Clause) *gorm.DB {
	base := r.scoped(ctx, conds)
	if !scope.Global {
		base = base.Where(
			"guid IN ? OR EXISTS (SELECT 1 FROM device_group_user_permissions dgup"+
				" WHERE dgup.deviceGroupGuid = device_groups.guid AND dgup.userGuid = ?)",
			scope.Guids, userGuid)
	}
	return base
}

// CountRoleRefs 统计 user_role_assignment_device_groups 中引用该组的
// 行数（RESTRICT 语义的应用层检查：>0 时删除组返回 400）。
func (r *DeviceGroupRepo) CountRoleRefs(ctx context.Context, guid string) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.UserRoleAssignmentDeviceGroup{}).
		Where("deviceGroupGuid = ?", guid).
		Count(&n).Error
	return n, err
}
