// Package repository 本文件：UpdateCheckCounters——update-check 遥测所需的
// 业务统计计数（M3 T07）。
//
// 以窄接口（updatecheck.Counters）暴露给 service/updatecheck，
// 避免该包直接依赖 GORM 与仓储细节。
package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// UpdateCheckCounters 业务统计计数器（用户/设备/用户组/策略）。
type UpdateCheckCounters struct {
	db *gorm.DB
}

// NewUpdateCheckCounters 构建计数器。
func NewUpdateCheckCounters(db *gorm.DB) *UpdateCheckCounters {
	return &UpdateCheckCounters{db: db}
}

// CountAllUsers 全部用户数。
func (c *UpdateCheckCounters) CountAllUsers(ctx context.Context) (int64, error) {
	return c.count(ctx, &entity.User{})
}

// CountAllDevices 全部设备数。
func (c *UpdateCheckCounters) CountAllDevices(ctx context.Context) (int64, error) {
	return c.count(ctx, &entity.Peer{})
}

// CountAllGroups 全部用户组数。
func (c *UpdateCheckCounters) CountAllGroups(ctx context.Context) (int64, error) {
	return c.count(ctx, &entity.UserGroup{})
}

// CountAllStrategies 全部策略数。
func (c *UpdateCheckCounters) CountAllStrategies(ctx context.Context) (int64, error) {
	return c.count(ctx, &entity.Strategy{})
}

// count 通用计数。
func (c *UpdateCheckCounters) count(ctx context.Context, model any) (int64, error) {
	var total int64
	if err := c.db.WithContext(ctx).Model(model).Count(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}
