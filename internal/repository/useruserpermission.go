// Package repository 本文件：UserUserPermissionRepo——
// user_user_permissions 表仓储（用户间设备可见性授权）。
package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// UserUserPermissionRepo user_user_permissions 表仓储。
type UserUserPermissionRepo struct {
	*GenericRepository[entity.UserUserPermission]
}

// NewUserUserPermissionRepo 构建仓储。
func NewUserUserPermissionRepo(db *gorm.DB) *UserUserPermissionRepo {
	return &UserUserPermissionRepo{GenericRepository: New[entity.UserUserPermission](db)}
}

// ListTargetByUser 用户被授权可见的目标用户关联行
// （/peers 三源之一：targetUserGuid 名下设备对 userGuid 可见）。
func (r *UserUserPermissionRepo) ListTargetByUser(ctx context.Context, userGuid string) ([]entity.UserUserPermission, error) {
	out := make([]entity.UserUserPermission, 0)
	err := r.db.WithContext(ctx).
		Where("userGuid = ?", userGuid).
		Order("targetUserGuid ASC").
		Find(&out).Error
	return out, err
}
