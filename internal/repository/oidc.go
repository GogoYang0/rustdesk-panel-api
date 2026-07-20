package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// ProviderList OIDC 提供商列表别名。
type ProviderList = []entity.OidcProvider

// StatePatch OIDC 授权态完结补丁；nil 表示不更新。
type StatePatch struct {
	Status      *string
	UserGuid    *string
	AccessToken *string
}

// OidcRepo oidc_providers / oidc_auth_states 表仓储。
type OidcRepo struct {
	db *gorm.DB
}

// NewOidcRepo 构建仓储。
func NewOidcRepo(db *gorm.DB) *OidcRepo {
	return &OidcRepo{db: db}
}

// FindEnabledProviders 启用的提供商（priority 升序）。
func (r *OidcRepo) FindEnabledProviders(ctx context.Context) (ProviderList, error) {
	list := make(ProviderList, 0)
	err := r.db.WithContext(ctx).
		Where("enabled = ?", true).
		Order("priority ASC").
		Find(&list).Error
	return list, err
}

// FindByName 按名称查找提供商。
func (r *OidcRepo) FindByName(ctx context.Context, name string) (*entity.OidcProvider, error) {
	var p entity.OidcProvider
	err := r.db.WithContext(ctx).Where("name = ?", name).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// SaveState 保存授权中间态（upsert by guid）。
func (r *OidcRepo) SaveState(ctx context.Context, s *entity.OidcAuthState) error {
	return r.db.WithContext(ctx).Save(s).Error
}

// FindStateByCode 按轮询 code 查找授权中间态。
func (r *OidcRepo) FindStateByCode(ctx context.Context, code string) (*entity.OidcAuthState, error) {
	var s entity.OidcAuthState
	err := r.db.WithContext(ctx).Where("code = ?", code).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// FindStateByState 按 OAuth2 state 参数查找授权中间态（回调场景）。
func (r *OidcRepo) FindStateByState(ctx context.Context, state string) (*entity.OidcAuthState, error) {
	var s entity.OidcAuthState
	err := r.db.WithContext(ctx).Where("state = ?", state).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteExpiredStates 清理过期授权中间态（cron 清理），返回删除条数。
func (r *OidcRepo) DeleteExpiredStates(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("expiresAt < ?", before).
		Delete(&entity.OidcAuthState{})
	return res.RowsAffected, res.Error
}

// CompleteState 授权完结：更新 status/userGuid/accessToken。
func (r *OidcRepo) CompleteState(ctx context.Context, code string, patch StatePatch) error {
	updates := map[string]any{}
	if patch.Status != nil {
		updates["status"] = *patch.Status
	}
	if patch.UserGuid != nil {
		updates["userGuid"] = *patch.UserGuid
	}
	if patch.AccessToken != nil {
		updates["accessToken"] = *patch.AccessToken
	}
	if len(updates) == 0 {
		return nil
	}
	err := r.db.WithContext(ctx).Model(&entity.OidcAuthState{}).
		Where("code = ?", code).
		Updates(updates).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}
