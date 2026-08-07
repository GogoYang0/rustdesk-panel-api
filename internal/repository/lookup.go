// Package repository 本文件：M2 设备/策略域补充查询——视图批量组装
// （sysinfos/strategies 批量）、设备关联名称解析（按用户名查用户）、
// 设备组 device_count 计数与按 peer.id 命中、assign 族宿主表批量回写、
// 指派目标清单查询。不属 RBAC 授权端口（见 rbacbatch.go）亦非 peer
// 写路径（见 peer.go），集中一处避免散落。
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

// ==================== 设备组视图支撑（device_count / 按 peer.id 命中） ====================

// countRow device_count GROUP BY 行。显式列 tag 必需：SELECT 结果列
// deviceGroupGuid 与 GORM 命名策略推导的 device_group_guid 不同，
// 不加 tag 会静默映射为空。
type countRow struct {
	DeviceGroupGuid string `gorm:"column:deviceGroupGuid"`
	Cnt             int64  `gorm:"column:cnt"`
}

// CountPeersByGroups 统计设备组内设备数（DeviceGroupView.device_count）：
// 一次 GROUP BY 批量返回，未在结果中的 guid 计数为 0。
func (r *PeerRepo) CountPeersByGroups(ctx context.Context, guids []string) (map[string]int64, error) {
	out := make(map[string]int64, len(guids))
	if len(guids) == 0 {
		return out, nil
	}
	rows := make([]countRow, 0, len(guids))
	err := r.db.WithContext(ctx).Model(&entity.Peer{}).
		Select("deviceGroupGuid, COUNT(*) AS cnt").
		Where("deviceGroupGuid IN ?", guids).
		Group("deviceGroupGuid").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.DeviceGroupGuid] = row.Cnt
	}
	return out, nil
}

// FindByIDs 按 peers.id（数字设备 ID 字符串）批量查设备
// （设备组批量加入/移出按 ID 匹配，openapi body=peer.id[]）。
func (r *PeerRepo) FindByIDs(ctx context.Context, ids []string) ([]entity.Peer, error) {
	out := make([]entity.Peer, 0)
	if len(ids) == 0 {
		return out, nil
	}
	err := r.db.WithContext(ctx).Where("id IN ?", ids).Find(&out).Error
	return out, err
}

// UpdateColumnsByUUIDs 批量按 uuid 更新 peers 列（设备组批量加入/移出
// 与策略指派回写共用；updates 键=DB 列名，nil 值置 NULL）。
func (r *PeerRepo) UpdateColumnsByUUIDs(ctx context.Context, uuids []string, updates map[string]any) error {
	if len(uuids) == 0 || len(updates) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Model(&entity.Peer{}).
		Where("uuid IN ?", uuids).Updates(updates).Error
}

// ==================== assign 族宿主表批量回写（users / device_groups） ====================

// UpdateColumnsByGuids 批量按 guid 更新 users 列（策略指派回写
// users.strategyGuid；updates 键=DB 列名，nil 值置 NULL）。
func (r *UserRepo) UpdateColumnsByGuids(ctx context.Context, guids []string, updates map[string]any) error {
	if len(guids) == 0 || len(updates) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Model(&entity.User{}).
		Where("guid IN ?", guids).Updates(updates).Error
}

// UpdateColumnsByGuids 批量按 guid 更新 device_groups 列（策略指派
// 回写 device_groups.strategyGuid；updates 键=DB 列名，nil 值置 NULL）。
func (r *DeviceGroupRepo) UpdateColumnsByGuids(ctx context.Context, guids []string, updates map[string]any) error {
	if len(guids) == 0 || len(updates) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Model(&entity.DeviceGroup{}).
		Where("guid IN ?", guids).Updates(updates).Error
}

// ==================== 指派目标清单（target-candidates / assignments） ====================

// pageQuery 清单类查询的分页执行器：Count 与 Find 各自从 base 经
// Session 派生独立链，避免 finisher 复用污染（listPeersPage 同款模式）。
// order 为排序列 + 方向；pageSize<=0 时不分页。
func pageQuery[T any](base *gorm.DB, order string, current, pageSize int) ([]T, int64, error) {
	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := base.Session(&gorm.Session{}).Order(order)
	if pageSize > 0 {
		fetch = fetch.Limit(pageSize)
		if current > 1 {
			fetch = fetch.Offset((current - 1) * pageSize)
		}
	}
	out := make([]T, 0)
	if err := fetch.Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ListByStrategy 策略指派的设备清单分页（assignments 的 device 形态）：
// strategyGuid = guid；Global 全量，scoped 仅授权组内设备（未分组排除）。
// 排序 peers.id ASC（设备域清单排序契约）。
func (r *PeerRepo) ListByStrategy(ctx context.Context, strategyGuid string, scope GuidSet, current, pageSize int) ([]entity.Peer, int64, error) {
	base := r.db.WithContext(ctx).Table("peers p").Where("p.strategyGuid = ?", strategyGuid)
	if !scope.Global {
		if len(scope.Guids) == 0 {
			return []entity.Peer{}, 0, nil
		}
		base = base.Where("p.deviceGroupGuid IN ?", scope.Guids)
	}
	return pageQuery[entity.Peer](base, "p.id ASC", current, pageSize)
}

// ListPagedPublic 用户分页（公共列，target-candidates 的 user 形态）：
// onlyNonAdmin 时排除管理员（非管理员操作者只见非管理员用户）。
// 排序 username ASC（确定性契约）。
func (r *UserRepo) ListPagedPublic(ctx context.Context, onlyNonAdmin bool, current, pageSize int) ([]entity.User, int64, error) {
	base := r.publicSelect(ctx)
	if onlyNonAdmin {
		base = base.Where("isAdmin = ?", false)
	}
	return pageQuery[entity.User](base, "username ASC", current, pageSize)
}

// ListByStrategy 策略指派的用户清单分页（assignments 的 user 形态，
// 公共列）。排序 username ASC。
func (r *UserRepo) ListByStrategy(ctx context.Context, strategyGuid string, current, pageSize int) ([]entity.User, int64, error) {
	base := r.publicSelect(ctx).Where("strategyGuid = ?", strategyGuid)
	return pageQuery[entity.User](base, "username ASC", current, pageSize)
}

// ListByStrategy 策略指派的设备组清单分页（assignments 的
// device_group 形态）。排序 name ASC（openapi 契约）。
func (r *DeviceGroupRepo) ListByStrategy(ctx context.Context, strategyGuid string, current, pageSize int) ([]entity.DeviceGroup, int64, error) {
	base := r.db.WithContext(ctx).Model(&entity.DeviceGroup{}).Where("strategyGuid = ?", strategyGuid)
	return pageQuery[entity.DeviceGroup](base, "name ASC", current, pageSize)
}
