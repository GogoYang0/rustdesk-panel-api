// Package repository 本文件：SysinfoRepo——sysinfos 表仓储
// （设备系统信息；preset_* 列 snake_case 契约见实体 sysinfo.go）。
package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// SysinfoRepo sysinfos 表仓储。
type SysinfoRepo struct {
	*GenericRepository[entity.Sysinfo]
}

// NewSysinfoRepo 构建仓储。
func NewSysinfoRepo(db *gorm.DB) *SysinfoRepo {
	return &SysinfoRepo{GenericRepository: New[entity.Sysinfo](db)}
}

// FindByUUID 按 uuid 主键查询；未找到返回 ErrNotFound。
func (r *SysinfoRepo) FindByUUID(ctx context.Context, uuid string) (*entity.Sysinfo, error) {
	var s entity.Sysinfo
	err := r.db.WithContext(ctx).Where("uuid = ?", uuid).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Upsert 冲突时覆盖全部业务列（createdAt 保留首跳值；preset_* 的
// 覆盖策略——核心字段提供即覆盖、preset 非空真值才覆盖——由服务层
// 先行计算后传入，本方法只做幂等落库）。
func (r *SysinfoRepo) Upsert(ctx context.Context, s *entity.Sysinfo) error {
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "uuid"}},
		DoUpdates: clause.Assignments(map[string]any{
			"hostname":                 s.Hostname,
			"username":                 s.Username,
			"os":                       s.OS,
			"cpu":                      s.CPU,
			"memory":                   s.Memory,
			"preset_username":          s.PresetUsername,
			"preset_strategy_name":     s.PresetStrategyName,
			"preset_device_group_name": s.PresetDeviceGroupName,
		}),
	}).Create(s).Error
}
