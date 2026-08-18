// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：InvitationRepo——invitations 表仓储（邀请注册状态机，设计 §4.1）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// InvitationRepo invitations 表仓储。
type InvitationRepo struct {
	*GenericRepository[entity.Invitation]
}

// NewInvitationRepo 构建仓储。
func NewInvitationRepo(db *gorm.DB) *InvitationRepo {
	return &InvitationRepo{GenericRepository: New[entity.Invitation](db)}
}

// FindByToken 按 token 精确查询（verify/accept 公开入口）；
// 未找到返回 ErrNotFound。
func (r *InvitationRepo) FindByToken(ctx context.Context, token string) (*entity.Invitation, error) {
	var inv entity.Invitation
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&inv).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// MarkUsed 接受完成：写入 usedAt（accept 事务内调用，与用户激活同事务）。
func (r *InvitationRepo) MarkUsed(ctx context.Context, guid string, usedAt time.Time) error {
	return r.db.WithContext(ctx).Model(&entity.Invitation{}).
		Where("guid = ?", guid).
		Update("usedAt", usedAt).Error
}
