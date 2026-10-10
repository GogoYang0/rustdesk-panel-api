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

// MarkUsedTx 接受完成：事务内写入 usedAt（accept 与用户激活同事务；
// Tx 后缀强调必须在事务执行器上运行——内存库单连接池下根连接会
// 与持有行锁的事务互等死锁）。
func (r *InvitationRepo) MarkUsedTx(tx *gorm.DB, guid string, usedAt time.Time) error {
	return tx.Model(&entity.Invitation{}).
		Where("guid = ?", guid).
		Update("usedAt", usedAt).Error
}
