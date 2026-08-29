// Package repository 本文件：OidcProviderAdminRepo——oidc_providers 表的
// 管理域读写（列表分页/CRUD/数组顺序重排，M3 T07）。
//
// 与 OidcRepo（登录流只读）分离：本仓储仅供 oidcadmin 服务使用，
// 写路径集中在此，避免登录流误用写接口。
package repository

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// oidcProviderNameCI 名称匹配列（SQLite 下 LIKE 已大小写不敏感；
// MySQL 默认排序规则同理）。
const oidcProviderNameCI = "name"

// OidcProviderAdminRepo oidc_providers 管理域仓储。
type OidcProviderAdminRepo struct {
	db *gorm.DB
}

// NewOidcProviderAdminRepo 构建仓储。
func NewOidcProviderAdminRepo(db *gorm.DB) *OidcProviderAdminRepo {
	return &OidcProviderAdminRepo{db: db}
}

// ListPaged 分页列表（priority ASC + name ASC）；返回 (rows, total, error)。
// pageSize <= 0 时不分页（返回全量），current >= 1。
func (r *OidcProviderAdminRepo) ListPaged(ctx context.Context, current, pageSize int) ([]entity.OidcProvider, int64, error) {
	query := r.db.WithContext(ctx).Model(&entity.OidcProvider{})
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	out := make([]entity.OidcProvider, 0)
	q := query.Order("priority ASC").Order("name ASC")
	if pageSize > 0 {
		if current < 1 {
			current = 1
		}
		q = q.Offset((current - 1) * pageSize).Limit(pageSize)
	}
	if err := q.Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// FindByGuid 按主键查找；未找到返回 ErrNotFound。
func (r *OidcProviderAdminRepo) FindByGuid(ctx context.Context, guid string) (*entity.OidcProvider, error) {
	var p entity.OidcProvider
	err := r.db.WithContext(ctx).Where(&entity.OidcProvider{Guid: guid}).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// FindByName 按名称查找（去空白后精确匹配）；未找到返回 ErrNotFound。
func (r *OidcProviderAdminRepo) FindByName(ctx context.Context, name string) (*entity.OidcProvider, error) {
	var p entity.OidcProvider
	err := r.db.WithContext(ctx).
		Where(oidcProviderNameCI+" = ?", strings.TrimSpace(name)).
		First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// Create 新建（主键冲突由唯一索引兜底）。
func (r *OidcProviderAdminRepo) Create(ctx context.Context, p *entity.OidcProvider) error {
	return r.db.WithContext(ctx).Create(p).Error
}

// Save 全字段更新（PATCH/toggle 路径复用）。
func (r *OidcProviderAdminRepo) Save(ctx context.Context, p *entity.OidcProvider) error {
	return r.db.WithContext(ctx).Save(p).Error
}

// DeleteByGuid 按主键删除（幂等：不存在也返回 nil）。
func (r *OidcProviderAdminRepo) DeleteByGuid(ctx context.Context, guid string) error {
	return r.db.WithContext(ctx).
		Where(&entity.OidcProvider{Guid: guid}).
		Delete(&entity.OidcProvider{}).Error
}

// ReorderPriorities 事务内按 guids 顺序写入 priority（0 起递增）。
//
// guids 中不存在的主键跳过（不报错，与参考实现一致）；
// 未出现在 guids 中的提供者保持原 priority。
func (r *OidcProviderAdminRepo) ReorderPriorities(ctx context.Context, guids []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for i, guid := range guids {
			if strings.TrimSpace(guid) == "" {
				continue
			}
			if err := tx.Model(&entity.OidcProvider{}).
				Where(&entity.OidcProvider{Guid: guid}).
				Update("priority", i).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
