// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：AlarmAuditRepo——alarm_audits 表仓储（nonce 幂等，设计事实②）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// AlarmAuditFilter GET /api/audits/alarm 过滤（契约 ListAlarmAuditsParams）。
type AlarmAuditFilter struct {
	Typ      *int   // 精确 typ
	Uuid     string // 精确 deviceUuid
	Current  int    // 页码（1 起）
	PageSize int    // 页大小（0 = 不分页）
}

// AlarmAuditRepo alarm_audits 表仓储。
type AlarmAuditRepo struct {
	*GenericRepository[entity.AlarmAudit]
}

// NewAlarmAuditRepo 构建仓储。
func NewAlarmAuditRepo(db *gorm.DB) *AlarmAuditRepo {
	return &AlarmAuditRepo{GenericRepository: New[entity.AlarmAudit](db)}
}

// UpsertByNonce nonce 幂等落库（同 FileAuditRepo.UpsertByNonce；
// UNIQUE(deviceId, nonce) 冲突重查返回既有行，nonce NULL 恒新建）。
func (r *AlarmAuditRepo) UpsertByNonce(ctx context.Context, in *entity.AlarmAudit) (*entity.AlarmAudit, bool, error) {
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
func (r *AlarmAuditRepo) FindByDeviceNonce(ctx context.Context, deviceId, nonce string) (*entity.AlarmAudit, error) {
	var row entity.AlarmAudit
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

// ListPaged 告警审计分页（GET /api/audits/alarm；排序锚点 createdAt）。
func (r *AlarmAuditRepo) ListPaged(ctx context.Context, f AlarmAuditFilter) ([]entity.AlarmAudit, int64, error) {
	apply := func(q *gorm.DB) *gorm.DB {
		if f.Typ != nil {
			q = q.Where("typ = ?", *f.Typ)
		}
		if f.Uuid != "" {
			q = q.Where("deviceUuid = ?", f.Uuid)
		}
		return q
	}
	base := r.db.WithContext(ctx).Model(&entity.AlarmAudit{})
	return auditPage[entity.AlarmAudit](r.GenericRepository, base, apply, "createdAt", f.Current, f.PageSize)
}

// CountByDay 按日聚合（dashboard trends alarmTrend；锚点为落库时刻
// createdAt——类图无上报时间列，设计事实⑥裁定）。
func (r *AlarmAuditRepo) CountByDay(ctx context.Context, from, to time.Time) ([]DayCount, error) {
	out := make([]DayCount, 0)
	dayExpr := LocalDayExpr(r.db.Name(), "createdAt")
	err := r.db.WithContext(ctx).Model(&entity.AlarmAudit{}).
		Select(dayExpr+" AS date, COUNT(*) AS count").
		Where("createdAt >= ? AND createdAt < ?", from, to).
		Group(dayExpr).
		Order("date ASC").
		Scan(&out).Error
	return out, err
}
