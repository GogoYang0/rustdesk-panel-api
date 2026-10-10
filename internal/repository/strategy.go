// Package repository 本文件：StrategyRepo——strategies 表仓储
// （下发策略；删除走 DeleteWithDetach 事务置空三处引用）。
package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// StrategyRepo strategies 表仓储。
type StrategyRepo struct {
	*GenericRepository[entity.Strategy]
}

// NewStrategyRepo 构建仓储。
func NewStrategyRepo(db *gorm.DB) *StrategyRepo {
	return &StrategyRepo{GenericRepository: New[entity.Strategy](db)}
}

// FindByName 精确名称查询；未找到返回 ErrNotFound。
func (r *StrategyRepo) FindByName(ctx context.Context, name string) (*entity.Strategy, error) {
	var s entity.Strategy
	err := r.db.WithContext(ctx).Where("name = ?", name).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteWithDetach 事务删除策略并置空三处引用（共享知识 9：
// 跨表级联服务层事务显式处理，方言无关）：
// peers.strategyGuid / users.strategyGuid / device_groups.strategyGuid。
func (r *StrategyRepo) DeleteWithDetach(ctx context.Context, guid string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&entity.Peer{}).
			Where("strategyGuid = ?", guid).
			Update("strategyGuid", nil).Error; err != nil {
			return err
		}
		if err := tx.Model(&entity.User{}).
			Where("strategyGuid = ?", guid).
			Update("strategyGuid", nil).Error; err != nil {
			return err
		}
		if err := tx.Model(&entity.DeviceGroup{}).
			Where("strategyGuid = ?", guid).
			Update("strategyGuid", nil).Error; err != nil {
			return err
		}
		return tx.Where("guid = ?", guid).Delete(&entity.Strategy{}).Error
	})
}
