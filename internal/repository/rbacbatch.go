// Package repository 本文件：RBAC 授权端口的批量读取扩展（M2）。
// rbac.Stores 各端口需要批量变体；作为既有仓储的自然扩展集中于此，
// 避免改动 M1 仓储文件（语义与单条版本一致）。
package repository

import (
	"context"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// FindByGuids 批量按 guid 查用户（公共列，排除敏感列；顺序按 SQL 返回，
// 消费方自行建索引映射）。未找到的 guid 不出现在结果中。
func (r *UserRepo) FindByGuids(ctx context.Context, guids []string) ([]entity.User, error) {
	out := make([]entity.User, 0)
	if len(guids) == 0 {
		return out, nil
	}
	err := r.publicSelect(ctx).Where("guid IN ?", guids).Find(&out).Error
	return out, err
}

// FindByGuids 批量按 guid 查角色。
func (r *RoleRepo) FindByGuids(ctx context.Context, guids []string) ([]entity.Role, error) {
	out := make([]entity.Role, 0)
	if len(guids) == 0 {
		return out, nil
	}
	err := r.db.WithContext(ctx).Where("guid IN ?", guids).Find(&out).Error
	return out, err
}

// FindByGuids 批量按 guid 查设备组。
func (r *DeviceGroupRepo) FindByGuids(ctx context.Context, guids []string) ([]entity.DeviceGroup, error) {
	out := make([]entity.DeviceGroup, 0)
	if len(guids) == 0 {
		return out, nil
	}
	err := r.db.WithContext(ctx).Where("guid IN ?", guids).Find(&out).Error
	return out, err
}

// FindByUUIDs 批量按 uuid 查设备。
func (r *PeerRepo) FindByUUIDs(ctx context.Context, uuids []string) ([]entity.Peer, error) {
	out := make([]entity.Peer, 0)
	if len(uuids) == 0 {
		return out, nil
	}
	err := r.db.WithContext(ctx).Where("uuid IN ?", uuids).Find(&out).Error
	return out, err
}
