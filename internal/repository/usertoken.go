package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// UserTokenRepo user_tokens 表仓储（有状态 JWT 撤销）。
type UserTokenRepo struct {
	*GenericRepository[entity.UserToken]
}

// NewUserTokenRepo 构建仓储。
func NewUserTokenRepo(db *gorm.DB) *UserTokenRepo {
	return &UserTokenRepo{GenericRepository: New[entity.UserToken](db)}
}

// FindActive 校验 (userGuid, jti) 是否存在有效会话记录：
// isRevoked=false 且 expiresAt > now（共享知识 4：每个受保护请求查库）。
func (r *UserTokenRepo) FindActive(ctx context.Context, userGuid, jti string) (*entity.UserToken, error) {
	var t entity.UserToken
	err := r.db.WithContext(ctx).
		Where("userGuid = ? AND jti = ? AND isRevoked = ? AND expiresAt > ?", userGuid, jti, false, time.Now()).
		First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// RevokeByJti 按 jti 撤销。
func (r *UserTokenRepo) RevokeByJti(ctx context.Context, userGuid, jti string) error {
	return r.db.WithContext(ctx).Model(&entity.UserToken{}).
		Where("userGuid = ? AND jti = ?", userGuid, jti).
		Update("isRevoked", true).Error
}

// RevokeByDevice 设备维度撤销（登出场景：撤销同设备全部会话）。
func (r *UserTokenRepo) RevokeByDevice(ctx context.Context, userGuid, deviceId, deviceUuid string) error {
	q := r.db.WithContext(ctx).Model(&entity.UserToken{}).Where("userGuid = ?", userGuid)
	switch {
	case deviceId != "" && deviceUuid != "":
		q = q.Where("deviceId = ? AND deviceUuid = ?", deviceId, deviceUuid)
	case deviceId != "":
		q = q.Where("deviceId = ?", deviceId)
	case deviceUuid != "":
		q = q.Where("deviceUuid = ?", deviceUuid)
	default:
		return nil // 无设备维度信息时不撤销
	}
	return q.Update("isRevoked", true).Error
}

// ListActive 当前用户全部有效会话（createdAt 倒序，场景 D）。
func (r *UserTokenRepo) ListActive(ctx context.Context, userGuid string) ([]entity.UserToken, error) {
	list := make([]entity.UserToken, 0)
	err := r.db.WithContext(ctx).
		Where("userGuid = ? AND isRevoked = ? AND expiresAt > ?", userGuid, false, time.Now()).
		Order("createdAt DESC").
		Find(&list).Error
	return list, err
}

// DeleteExpired 清理过期 token（cron 清理，T04 cleanup 接入）；
// 返回删除行数。
func (r *UserTokenRepo) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("expiresAt < ?", before).
		Delete(&entity.UserToken{})
	return res.RowsAffected, res.Error
}
