// Package repository 本文件：M2 设备域补充查询——视图批量组装
// （sysinfos/strategies 批量）、设备关联名称解析（按用户名查用户）。
// 不属 RBAC 授权端口（见 rbacbatch.go）亦非 peer 写路径（见 peer.go），
// 集中一处避免散落。
package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// FindByUsername 精确用户名查询（PATCH /api/devices 的 userName 关联
// 解析；公共列足够）；未找到返回 ErrNotFound。
func (r *UserRepo) FindByUsername(ctx context.Context, username string) (*entity.User, error) {
	var u entity.User
	err := r.publicSelect(ctx).Where("username = ?", username).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByUUIDs 批量按 uuid 查 sysinfo（/peers、/devices 视图组装防 N+1）。
// 未找到的 uuid 不出现在结果中。
func (r *SysinfoRepo) FindByUUIDs(ctx context.Context, uuids []string) ([]entity.Sysinfo, error) {
	out := make([]entity.Sysinfo, 0)
	if len(uuids) == 0 {
		return out, nil
	}
	err := r.db.WithContext(ctx).Where("uuid IN ?", uuids).Find(&out).Error
	return out, err
}

// FindByGuids 批量按 guid 查策略（视图组装防 N+1）。
func (r *StrategyRepo) FindByGuids(ctx context.Context, guids []string) ([]entity.Strategy, error) {
	out := make([]entity.Strategy, 0)
	if len(guids) == 0 {
		return out, nil
	}
	err := r.db.WithContext(ctx).Where("guid IN ?", guids).Find(&out).Error
	return out, err
}
