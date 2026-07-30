// Package repository 本文件：ActiveConnectionRepo——active_connections
// 表仓储（活跃连接查询与清理）。
package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// ActiveConnectionRepo active_connections 表仓储。
type ActiveConnectionRepo struct {
	*GenericRepository[entity.ActiveConnection]
}

// NewActiveConnectionRepo 构建仓储。
func NewActiveConnectionRepo(db *gorm.DB) *ActiveConnectionRepo {
	return &ActiveConnectionRepo{GenericRepository: New[entity.ActiveConnection](db)}
}

// ListConnIds 设备当前活跃连接 ID（connId ASC 稳定序，供断连响应）。
func (r *ActiveConnectionRepo) ListConnIds(ctx context.Context, uuid string) ([]int64, error) {
	out := make([]int64, 0)
	err := r.db.WithContext(ctx).Model(&entity.ActiveConnection{}).
		Where("deviceUuid = ?", uuid).
		Order("connId ASC").
		Pluck("connId", &out).Error
	return out, err
}

// DeleteByDevice 删除设备全部连接记录（设备删除级联，共享知识 9）。
func (r *ActiveConnectionRepo) DeleteByDevice(ctx context.Context, uuid string) error {
	return r.db.WithContext(ctx).
		Where("deviceUuid = ?", uuid).
		Delete(&entity.ActiveConnection{}).Error
}
