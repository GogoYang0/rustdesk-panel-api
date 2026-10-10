// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：NexusTokenRepo——nexus_tokens 表仓储（每用户一条绑定态）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// NexusTokenRepo nexus_tokens 表仓储。
type NexusTokenRepo struct {
	*GenericRepository[entity.NexusToken]
}

// NewNexusTokenRepo 构建仓储。
func NewNexusTokenRepo(db *gorm.DB) *NexusTokenRepo {
	return &NexusTokenRepo{GenericRepository: New[entity.NexusToken](db)}
}

// FindByUser 按用户查绑定态；未找到返回 ErrNotFound。
func (r *NexusTokenRepo) FindByUser(ctx context.Context, userGuid string) (*entity.NexusToken, error) {
	var t entity.NexusToken
	err := r.db.WithContext(ctx).Where("userGuid = ?", userGuid).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Upsert 绑定态落库（PK userGuid 冲突即全列更新；unbind 走 DeleteByUser）。
func (r *NexusTokenRepo) Upsert(ctx context.Context, t *entity.NexusToken) error {
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "userGuid"}},
		DoUpdates: clause.Assignments(map[string]any{
			"nexusToken":    t.NexusToken,
			"nexusUsername": t.NexusUsername,
			"expiresAt":     t.ExpiresAt,
			"currentUuid":   t.CurrentUuid,
			"updatedAt":     now,
		}),
	}).Create(t).Error
}

// DeleteByUser 解绑（unbind；删除绑定行）。
func (r *NexusTokenRepo) DeleteByUser(ctx context.Context, userGuid string) error {
	return r.db.WithContext(ctx).
		Where("userGuid = ?", userGuid).
		Delete(&entity.NexusToken{}).Error
}
