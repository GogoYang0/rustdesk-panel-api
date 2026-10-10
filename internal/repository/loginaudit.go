// Package repository 本文件：LoginAuditRepo——login_audits 表仓储
// （GAP2 设计 §3.4）：best-effort 写入 + 查询分页 + 保留期清理。
package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// LoginAuditFilter 登录审计查询过滤（openapi /api/audits/login 参数契约）：
// result/username(LIKE)/start/end（createdAt 闭区间）+ 分页。
type LoginAuditFilter struct {
	Result   string // 精确 result 枚举
	Username string // LIKE username
	Start    *time.Time
	End      *time.Time
	Current  int
	PageSize int
}

// LoginAuditRowView 查询行（含 users 左联展示名）。
type LoginAuditRowView struct {
	entity.LoginAudit
	DisplayName *string
}

// LoginAuditRepo login_audits 表仓储。
type LoginAuditRepo struct {
	db *gorm.DB
}

// NewLoginAuditRepo 构建仓储。
func NewLoginAuditRepo(db *gorm.DB) *LoginAuditRepo {
	return &LoginAuditRepo{db: db}
}

// Create 写入一条登录审计（主流程 best-effort，调用方忽略错误仅告警）。
func (r *LoginAuditRepo) Create(ctx context.Context, rec *entity.LoginAudit) error {
	if rec.Guid == "" {
		rec.Guid = uuid.New().String()
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	return r.db.WithContext(ctx).Create(rec).Error
}

// ListPaged 分页查询（displayName 由 users LEFT JOIN 补齐，无对应用户
// 为 NULL；排序 createdAt DESC、guid DESC 稳定序）。
func (r *LoginAuditRepo) ListPaged(ctx context.Context, f LoginAuditFilter) ([]LoginAuditRowView, int64, error) {
	apply := func(q *gorm.DB) *gorm.DB {
		q = q.Table("login_audits la").
			Select("la.*, u.displayName AS display_name").
			Joins("LEFT JOIN users u ON u.guid = la.userGuid")
		if f.Result != "" {
			q = q.Where("la.result = ?", f.Result)
		}
		if f.Username != "" {
			q = q.Where("la.username LIKE ?", like(f.Username))
		}
		if f.Start != nil {
			q = q.Where("la.createdAt >= ?", *f.Start)
		}
		if f.End != nil {
			q = q.Where("la.createdAt <= ?", *f.End)
		}
		return q
	}
	var total int64
	if err := apply(r.db.WithContext(ctx).Session(&gorm.Session{})).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := apply(r.db.WithContext(ctx).Session(&gorm.Session{})).Order("la.createdAt DESC, la.guid DESC")
	if f.PageSize > 0 {
		fetch = fetch.Limit(f.PageSize)
		if f.Current > 1 {
			fetch = fetch.Offset((f.Current - 1) * f.PageSize)
		}
	}
	out := make([]LoginAuditRowView, 0)
	if err := fetch.Scan(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// DeleteOlderThan 保留期清理：删除 createdAt < before 的行，返回条数
// （OQ-7：纳入 general.auditRetentionDays 清理任务）。
func (r *LoginAuditRepo) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).Where("createdAt < ?", before).Delete(&entity.LoginAudit{})
	return res.RowsAffected, res.Error
}
