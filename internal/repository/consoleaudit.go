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
	return r.Create(ctx, row)
}
