// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：NexusBuildRepo——nexus_builds 表仓储（构建任务状态机 +
// poller 扫描窗口）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// NexusBuildRepo nexus_builds 表仓储。
type NexusBuildRepo struct {
	*GenericRepository[entity.NexusBuild]
}

// NewNexusBuildRepo 构建仓储。
func NewNexusBuildRepo(db *gorm.DB) *NexusBuildRepo {
	return &NexusBuildRepo{GenericRepository: New[entity.NexusBuild](db)}
}

// FindByUUID 按任务 uuid 查询（主键 uuid，非 guid 命名契约）；
// 未找到返回 ErrNotFound。
func (r *NexusBuildRepo) FindByUUID(ctx context.Context, buildUuid string) (*entity.NexusBuild, error) {
	var b entity.NexusBuild
	err := r.db.WithContext(ctx).Where("uuid = ?", buildUuid).First(&b).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// ListByUser 用户构建历史分页（GET nexus/builds；排序 createdAt DESC）。
func (r *NexusBuildRepo) ListByUser(ctx context.Context, userGuid string, current, pageSize int) ([]entity.NexusBuild, int64, error) {
	base := r.db.WithContext(ctx).Model(&entity.NexusBuild{}).Where("userGuid = ?", userGuid)
	var total int64
	if err := base.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := base.Session(&gorm.Session{}).Order("createdAt DESC, uuid ASC")
	if pageSize > 0 {
		fetch = fetch.Limit(pageSize)
		if current > 1 {
			fetch = fetch.Offset((current - 1) * pageSize)
		}
	}
	out := make([]entity.NexusBuild, 0)
	if err := fetch.Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// UpdateStatus 仅迁移动作（cancel/轮询中间态）。
func (r *NexusBuildRepo) UpdateStatus(ctx context.Context, buildUuid, status string) error {
	return r.db.WithContext(ctx).Model(&entity.NexusBuild{}).
		Where("uuid = ?", buildUuid).
		Update("status", status).Error
}

// UpdateResult 轮询终态落库（status + files/message，nil 列不覆盖）。
func (r *NexusBuildRepo) UpdateResult(ctx context.Context, buildUuid, status string, files, message *string) error {
	updates := map[string]any{"status": status}
	if files != nil {
		updates["files"] = *files
	}
	if message != nil {
		updates["message"] = *message
	}
	return r.db.WithContext(ctx).Model(&entity.NexusBuild{}).
		Where("uuid = ?", buildUuid).
		Updates(updates).Error
}

// ListPolling poller 扫描窗口（10s 周期）：pending|building 全量，
// 按 createdAt ASC（先到先处理）。
func (r *NexusBuildRepo) ListPolling(ctx context.Context) ([]entity.NexusBuild, error) {
	out := make([]entity.NexusBuild, 0)
	err := r.db.WithContext(ctx).
		Where("status IN ?", []string{entity.NexusStatusPending, entity.NexusStatusBuilding}).
		Order("createdAt ASC, uuid ASC").
		Find(&out).Error
	return out, err
}

// PollDue 轮询到期判定参考时刻（poller 侧 10s 间隔对齐用）。
const PollInterval = 10 * time.Second
