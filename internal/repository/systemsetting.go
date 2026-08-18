// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：SystemSettingRepo——system_settings 表仓储（KV 服务底座）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// SystemSettingRepo system_settings 表仓储。
type SystemSettingRepo struct {
	*GenericRepository[entity.SystemSetting]
}

// NewSystemSettingRepo 构建仓储。
func NewSystemSettingRepo(db *gorm.DB) *SystemSettingRepo {
	return &SystemSettingRepo{GenericRepository: New[entity.SystemSetting](db)}
}

// Get 按 key 精确查询；未找到返回 ErrNotFound。
// 结构体条件交由驱动转义保留字 key（双方言中立）。
func (r *SystemSettingRepo) Get(ctx context.Context, key string) (*entity.SystemSetting, error) {
	var s entity.SystemSetting
	err := r.db.WithContext(ctx).Where(&entity.SystemSetting{Key: key}).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Set upsert 单键（PK key 冲突即更新 value/category/updatedAt）。
func (r *SystemSettingRepo) Set(ctx context.Context, key, value, category string) error {
	now := time.Now()
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]any{
			"value":     value,
			"category":  category,
			"updatedAt": now,
		}),
	}).Create(&entity.SystemSetting{
		Key:       key,
		Value:     value,
		Category:  category,
		UpdatedAt: now,
	}).Error
}

// GetAllByPrefix 取前缀下全部键（settings 域按 category 段装载；
// prefix 为代码内常量，无转义需求）。
func (r *SystemSettingRepo) GetAllByPrefix(ctx context.Context, prefix string) ([]entity.SystemSetting, error) {
	out := make([]entity.SystemSetting, 0)
	err := r.db.WithContext(ctx).
		Where("`key` LIKE ?", prefix+"%").
		Order("key ASC").
		Find(&out).Error
	return out, err
}

// DeleteByKey 删单键（结构体条件，驱动转义 key）。
func (r *SystemSettingRepo) DeleteByKey(ctx context.Context, key string) error {
	return r.db.WithContext(ctx).
		Where(&entity.SystemSetting{Key: key}).
		Delete(&entity.SystemSetting{}).Error
}
