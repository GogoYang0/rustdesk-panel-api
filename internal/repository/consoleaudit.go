// Package repository 本文件：ConsoleAuditRepo——console_audits 表仓储
// （审计写入端；查询端点 M3 提供）。实现 rbac.AuditStore 端口。
package repository

import (
	"context"

	"gorm.io/gorm"
	"uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// ConsoleAuditRepo console_audits 表仓储。
type ConsoleAuditRepo struct {
	*GenericRepository[entity.ConsoleAudit]
}

// NewConsoleAuditRepo 构建仓储。
func NewConsoleAuditRepo(db *gorm.DB) *ConsoleAuditRepo {
	return &ConsoleAuditRepo{GenericRepository: New[entity.ConsoleAudit](db)}
}

// CreateAudit 实现 rbac.AuditStore：AuditRecord → 实体落库
// （guid/createdAt 由本层生成；ActorUserGuid 空串映射 NULL）。
func (r *ConsoleAuditRepo) CreateAudit(ctx context.Context, rec rbac.AuditRecord) error {
	return r.CreateAuditTx(r.db.WithContext(ctx), rec)
}

// CreateAuditTx CreateAudit 的事务变体：服务层把业务写与 allowed 审计
// 落库编排在同一事务（共享知识 13 "roles/user-role 在事务内写 allowed"）。
func (r *ConsoleAuditRepo) CreateAuditTx(tx *gorm.DB, rec rbac.AuditRecord) error {
	var actor *string
	if rec.ActorUserGuid != "" {
		v := rec.ActorUserGuid
		actor = &v
	}
	row := &entity.ConsoleAudit{
		Guid:          uuid.New().String(),
		ActorUserGuid: actor,
		TargetType:    rec.TargetType,
		TargetGuid:    rec.TargetGuid,
		Action:        rec.Action,
		Result:        rec.Result,
		Reason:        rec.Reason,
		BeforeState:   rec.BeforeState,
		AfterState:    rec.AfterState,
		RequestID:     rec.RequestID,
	}
	return tx.Create(row).Error
}

// ConsoleAuditFilter GET /api/audits/console 过滤（契约
// ListConsoleAuditsParams：result 精确（allowed/denied）、user_guid
// 精确 actorUserGuid；当前/页大小）。
type ConsoleAuditFilter struct {
	Result   string // 精确 result；空串不过滤
	UserGuid string // 精确 actorUserGuid；空串不过滤
	Current  int    // 页码（1 起）
	PageSize int    // 页大小（0 = 不分页）
}

// ConsoleAuditWithActor 控制台审计行 + 操作者用户名（LEFT JOIN
// users 补齐 actor_user_name；系统级动作 actorUserGuid 为 NULL，
// ActorName 亦 NULL）。
type ConsoleAuditWithActor struct {
	entity.ConsoleAudit
	ActorName *string `gorm:"column:actorName"`
}

// ListPaged 控制台审计分页（GET /api/audits/console；audit.view
// 中间件已过。排序 createdAt DESC + guid 稳定序，与参考一致）。
func (r *ConsoleAuditRepo) ListPaged(ctx context.Context, f ConsoleAuditFilter) ([]ConsoleAuditWithActor, int64, error) {
	apply := func(q *gorm.DB) *gorm.DB {
		if f.Result != "" {
			q = q.Where("console_audits.result = ?", f.Result)
		}
		if f.UserGuid != "" {
			q = q.Where("console_audits.actorUserGuid = ?", f.UserGuid)
		}
		return q
	}
	base := r.db.WithContext(ctx).Table("console_audits").
		Select("console_audits.*, users.username AS actorName").
		Joins("LEFT JOIN users ON users.guid = console_audits.actorUserGuid")
	base = apply(base)
	var total int64
	if err := r.db.WithContext(ctx).Table("console_audits").Scopes(apply).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := base.Order("console_audits.createdAt DESC, console_audits.guid DESC")
	if f.PageSize > 0 {
		fetch = fetch.Limit(f.PageSize)
		if f.Current > 1 {
			fetch = fetch.Offset((f.Current - 1) * f.PageSize)
		}
	}
	out := make([]ConsoleAuditWithActor, 0)
	if err := fetch.Scan(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}
