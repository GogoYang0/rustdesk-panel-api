// Package repository 本文件：DashboardRepo——仪表盘跨表聚合计数
// （设计事实⑥ overview 口径；仅 COUNT 不取行数据。repository 是
// 唯一允许直接写 GORM 的层，跨表聚合无归属域，独立成文件）。
package repository

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// DashboardRepo 仪表盘聚合专用仓储（users/peers/user_groups/
// device_groups/roles/strategies 六表计数）。
type DashboardRepo struct {
	db *gorm.DB
}

// NewDashboardRepo 构建仓储。
func NewDashboardRepo(db *gorm.DB) *DashboardRepo {
	return &DashboardRepo{db: db}
}

// CountUsers 用户总数与管理员数（overview.users.total/admin，
// 参考 userRepository.count({where:{isAdmin:true}})）。
func (r *DashboardRepo) CountUsers(ctx context.Context) (total, admin int64, err error) {
	if err = r.db.WithContext(ctx).Model(&entity.User{}).Count(&total).Error; err != nil {
		return 0, 0, err
	}
	if err = r.db.WithContext(ctx).Model(&entity.User{}).
		Where("isAdmin = ?", true).Count(&admin).Error; err != nil {
		return 0, 0, err
	}
	return total, admin, nil
}

// CountDevices 设备总数与在线数（overview.devices；在线口径
// lastHeartbeat >= onlineSince AND status=1，设计事实⑥ 60s 窗口）。
func (r *DashboardRepo) CountDevices(ctx context.Context, onlineSince time.Time) (total, online int64, err error) {
	if err = r.db.WithContext(ctx).Model(&entity.Peer{}).Count(&total).Error; err != nil {
		return 0, 0, err
	}
	if err = r.db.WithContext(ctx).Model(&entity.Peer{}).
		Where("lastHeartbeat >= ? AND status = ?", onlineSince, entity.PeerStatusActive).
		Count(&online).Error; err != nil {
		return 0, 0, err
	}
	return total, online, nil
}

// CountUserGroups 用户组计数（overview.counts.groups 半边）。
func (r *DashboardRepo) CountUserGroups(ctx context.Context) (int64, error) {
	return r.countOf(ctx, &entity.UserGroup{})
}

// CountDeviceGroups 设备组计数（overview.counts.groups 半边）。
func (r *DashboardRepo) CountDeviceGroups(ctx context.Context) (int64, error) {
	return r.countOf(ctx, &entity.DeviceGroup{})
}

// CountRoles 角色计数（overview.counts.roles）。
func (r *DashboardRepo) CountRoles(ctx context.Context) (int64, error) {
	return r.countOf(ctx, &entity.Role{})
}

// CountStrategies 策略计数（overview.counts.strategies）。
func (r *DashboardRepo) CountStrategies(ctx context.Context) (int64, error) {
	return r.countOf(ctx, &entity.Strategy{})
}

// countOf 单表计数执行器（CountAll 同构；model 须带 TableName）。
func (r *DashboardRepo) countOf(ctx context.Context, model any) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(model).Count(&n).Error
	return n, err
}
