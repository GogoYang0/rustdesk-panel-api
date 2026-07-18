package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// PasskeyRepo passkey_credentials 表仓储。
type PasskeyRepo struct {
	*GenericRepository[entity.PasskeyCredential]
}

// NewPasskeyRepo 构建仓储。
func NewPasskeyRepo(db *gorm.DB) *PasskeyRepo {
	return &PasskeyRepo{GenericRepository: New[entity.PasskeyCredential](db)}
}

// FindByCredentialId 按 WebAuthn credentialId（base64url）查找。
func (r *PasskeyRepo) FindByCredentialId(ctx context.Context, cid string) (*entity.PasskeyCredential, error) {
	var c entity.PasskeyCredential
	err := r.db.WithContext(ctx).Where("credentialId = ?", cid).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListByUser 用户全部凭据（创建时间顺序）。
func (r *PasskeyRepo) ListByUser(ctx context.Context, userGuid string) ([]entity.PasskeyCredential, error) {
	list := make([]entity.PasskeyCredential, 0)
	err := r.db.WithContext(ctx).
		Where("userGuid = ?", userGuid).
		Order("guid ASC").
		Find(&list).Error
	return list, err
}

// UpdateCounter 更新签名计数器（防凭据克隆）。
func (r *PasskeyRepo) UpdateCounter(ctx context.Context, guid string, counter uint32) error {
	err := r.db.WithContext(ctx).Model(&entity.PasskeyCredential{}).
		Where("guid = ?", guid).
		Update("counter", counter).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}
