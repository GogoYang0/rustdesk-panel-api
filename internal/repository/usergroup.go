package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// UserGroupRepo user_groups 表仓储。
type UserGroupRepo struct {
	*GenericRepository[entity.UserGroup]
}

// NewUserGroupRepo 构建仓储。
func NewUserGroupRepo(db *gorm.DB) *UserGroupRepo {
	return &UserGroupRepo{GenericRepository: New[entity.UserGroup](db)}
}

// FindDefault 返回默认用户组（isDefault=1）。
func (r *UserGroupRepo) FindDefault(ctx context.Context) (*entity.UserGroup, error) {
	var g entity.UserGroup
	err := r.db.WithContext(ctx).Where("isDefault = ?", true).First(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// FindByNameCI 大小写不敏感名称查询（用户组重名 409 判定；比对
// normalizedName——服务层创建/更新时维护为大写形式的规范化名）。
func (r *UserGroupRepo) FindByNameCI(ctx context.Context, name string) (*entity.UserGroup, error) {
	var g entity.UserGroup
	err := r.db.WithContext(ctx).Where("LOWER(normalizedName) = LOWER(?)", name).First(&g).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// NameMapByGuids 批量 guid → name 映射（强制 MFA 冲突名单标注来源组用；
// 未命中 guid 静默跳过）。
func (r *UserGroupRepo) NameMapByGuids(ctx context.Context, guids []string) (map[string]string, error) {
	out := make(map[string]string, len(guids))
	if len(guids) == 0 {
		return out, nil
	}
	rows := make([]entity.UserGroup, 0, len(guids))
	if err := r.db.WithContext(ctx).Where("guid IN ?", guids).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, g := range rows {
		out[g.Guid] = g.Name
	}
	return out, nil
}

// ListPaged 分页查询（name LIKE 过滤可空；normalizedName ASC、guid ASC
// 决胜排序，openapi 契约）。
func (r *UserGroupRepo) ListPaged(ctx context.Context, name string, q Query) ([]entity.UserGroup, int64, error) {
	conds := make([]Clause, 0, len(q.Where)+1)
	conds = append(conds, q.Where...)
	if name != "" {
		conds = append(conds, Clause{Field: "name", Op: OpLike, Value: like(name)})
	}
	return r.List(ctx, Query{
		Where:   conds,
		OrderBy: "normalizedName ASC, guid ASC",
		Limit:   q.Limit,
		Offset:  q.Offset,
	})
}

// DeleteTx 事务内删除组行（成员回落与组删除同事务）。
func (r *UserGroupRepo) DeleteTx(tx *gorm.DB, guid string) error {
	return tx.Where("guid = ?", guid).Delete(&entity.UserGroup{}).Error
}

// ListForShare 分享候选全量用户组（GET /api/ab/shared/{guid}/
// share-candidates groups 侧；name LIKE，排序 name ASC）。
func (r *UserGroupRepo) ListForShare(ctx context.Context, nameLike string) ([]entity.UserGroup, error) {
	out := make([]entity.UserGroup, 0)
	q := r.db.WithContext(ctx).Model(&entity.UserGroup{})
	if nameLike != "" {
		q = q.Where("name LIKE ?", like(nameLike))
	}
	err := q.Order("name ASC").Find(&out).Error
	return out, err
}
