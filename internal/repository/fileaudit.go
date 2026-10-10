// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：FileAuditRepo——file_audits 表仓储（nonce 幂等，设计事实②）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// FileAuditFilter GET /api/audits/file 过滤（契约 ListFileAuditsParams）。
type FileAuditFilter struct {
	PeerId   string // 精确 peerId
	Uuid     string // 精确 deviceUuid
	Type     *int   // 精确 type
	Current  int    // 页码（1 起）
	PageSize int    // 页大小（0 = 不分页）
}

// FileAuditRepo file_audits 表仓储。
type FileAuditRepo struct {
	*GenericRepository[entity.FileAudit]
}

// NewFileAuditRepo 构建仓储。
func NewFileAuditRepo(db *gorm.DB) *FileAuditRepo {
	return &FileAuditRepo{GenericRepository: New[entity.FileAudit](db)}
}

// UpsertByNonce nonce 幂等落库（设计事实②）：UNIQUE(deviceId, nonce)
// 冲突 → DoNothing 后重查返回既有行（幂等重放保护）。
// nonce 为 NULL 的行不参与唯一约束（双方言一致），恒新建。
// 返回落库后的行与是否新建。
func (r *FileAuditRepo) UpsertByNonce(ctx context.Context, in *entity.FileAudit) (*entity.FileAudit, bool, error) {
	res := r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "deviceId"}, {Name: "nonce"}},
		DoNothing: true,
	}).Create(in)
	if res.Error != nil {
		return nil, false, res.Error
	}
	if res.RowsAffected == 1 {
		return in, true, nil
	}
	// 冲突重查（nonce 非 NULL 才可能冲突）。
	got, err := r.FindByDeviceNonce(ctx, in.DeviceId, *in.Nonce)
	if err != nil {
		return nil, false, err
	}
	return got, false, nil
}

// FindByDeviceNonce 按幂等键重查；未找到返回 ErrNotFound。
func (r *FileAuditRepo) FindByDeviceNonce(ctx context.Context, deviceId, nonce string) (*entity.FileAudit, error) {
	var row entity.FileAudit
	err := r.db.WithContext(ctx).
		Where("deviceId = ? AND nonce = ?", deviceId, nonce).
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// ListPaged 文件审计分页（GET /api/audits/file）。
func (r *FileAuditRepo) ListPaged(ctx context.Context, f FileAuditFilter) ([]entity.FileAudit, int64, error) {
	apply := func(q *gorm.DB) *gorm.DB {
		if f.PeerId != "" {
			q = q.Where("peerId = ?", f.PeerId)
		}
		if f.Uuid != "" {
			q = q.Where("deviceUuid = ?", f.Uuid)
		}
		if f.Type != nil {
			q = q.Where("type = ?", *f.Type)
		}
		return q
	}
	base := r.db.WithContext(ctx).Model(&entity.FileAudit{})
	return auditPage[entity.FileAudit](r.GenericRepository, base, apply, "requestedAt", f.Current, f.PageSize)
}

// CountToday 今日文件传输数（dashboard overview；requestedAt >= dayStart）。
func (r *FileAuditRepo) CountToday(ctx context.Context, dayStart time.Time) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.FileAudit{}).
		Where("requestedAt >= ?", dayStart).
		Count(&n).Error
	return n, err
}

// CountTodayUpload 今日上传数（dashboard overview.files.upload，
// type=0；参考 uploadToday 口径）。
func (r *FileAuditRepo) CountTodayUpload(ctx context.Context, dayStart time.Time) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.FileAudit{}).
		Where("requestedAt >= ? AND type = ?", dayStart, 0).
		Count(&n).Error
	return n, err
}

// CountByDay 按日聚合（dashboard trends；DATE(requestedAt) 锚点，
// 左闭右开 [from, to)）。
func (r *FileAuditRepo) CountByDay(ctx context.Context, from, to time.Time) ([]DayCount, error) {
	out := make([]DayCount, 0)
	dayExpr := LocalDayExpr(r.db.Name(), "requestedAt")
	err := r.db.WithContext(ctx).Model(&entity.FileAudit{}).
		Select(dayExpr+" AS date, COUNT(*) AS count").
		Where("requestedAt >= ? AND requestedAt < ?", from, to).
		Group(dayExpr).
		Order("date ASC").
		Scan(&out).Error
	return out, err
}
