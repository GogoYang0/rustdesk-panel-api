package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// UserGroupRepo user_groups 表仓储。
type UserGroupRepo struct {
	*GenericRepository[entity.UserGroup]
}

// NewUserGroupRepo 构建仓储。
func NewUserGroupRepo(db *gorm.DB) *UserGroupRepo {
	return &UserGroupRepo{GenericRepository: New[entity.UserGroup](db)}
}

// FindDefault 返回默认用户组（isDefault=1）。
func (r *UserGroupRepo) FindDefault(ctx context.Context) (*entity.UserGroup, error) {
	var g entity.UserGroup
	err := r.db.WithContext(ctx).Where("isDefault = ?", true).First(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}
