// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：AddressBookRepo——address_books 表仓储（三态书 + 规则可见性
// 并集聚合 + 应用层级联删除，设计事实⑦/共享知识 9）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// AddressBookWithRule ListAccessible 行：书 + 当前用户视角的规则并集
// 最大值。owner 的 FULL_CONTROL 提升（MAX(owner→3, 并集最大)）由服务层
// 组装响应行时叠加——仓储只输出规则侧原值。
type AddressBookWithRule struct {
	entity.AddressBook
	EffectiveRule int `gorm:"column:effectiveRule"`
}

// AddressBookFilter 地址簿列表过滤（PaginationDto(current/pageSize/
// name/note)；name/note LIKE）。
type AddressBookFilter struct {
	Name     string // LIKE
	Note     string // LIKE
	Current  int    // 页码（1 起）
	PageSize int    // 页大小（0 = 不分页）
}

// AddressBookRepo address_books 表仓储。
type AddressBookRepo struct {
	*GenericRepository[entity.AddressBook]
}

// NewAddressBookRepo 构建仓储。
func NewAddressBookRepo(db *gorm.DB) *AddressBookRepo {
	return &AddressBookRepo{GenericRepository: New[entity.AddressBook](db)}
}

// FindByName 按名精确查询（非 personal——custom/shared 重名检查 409
// "Address book name already exists" 共用；personal 书名不参与该约束）。
// 未找到返回 ErrNotFound。
func (r *AddressBookRepo) FindByName(ctx context.Context, owner, name string) (*entity.AddressBook, error) {
	var b entity.AddressBook
	err := r.db.WithContext(ctx).
		Where("owner = ? AND isPersonal = 0 AND name = ?", owner, name).
		First(&b).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// accessibleScope 构建「owner ∪ 规则可见」公共链：
// LEFT JOIN 限定为目标用户命中的规则（targetUserId=我 / targetGroupId∈我所在组 /
// 双空=everyone），WHERE 放行 owner 或命中规则者。
func accessibleScope(ctx context.Context, r *AddressBookRepo, userGuid string, groupGuids []string) *gorm.DB {
	return r.db.WithContext(ctx).Table("address_books b").
		Joins("LEFT JOIN address_book_rules r ON r.addressBookGuid = b.guid"+
			" AND (r.targetUserId = ? OR r.targetGroupId IN ?"+
			" OR (r.targetUserId IS NULL AND r.targetGroupId IS NULL))",
			userGuid, groupGuids).
		Where("b.owner = ? OR r.guid IS NOT NULL", userGuid)
}

// ListAccessible 可见地址簿分页（shared/custom profiles 底座）：
// 可见 = owner（全权）∪ 存在命中规则；EffectiveRule = 命中规则并集
// 最大值（无命中规则时为 owner 的 0，服务层按 owner 提升 FULL_CONTROL）。
// 排序 name ASC + guid ASC（契约，事实⑦）。
func (r *AddressBookRepo) ListAccessible(ctx context.Context, userGuid string, groupGuids []string, f AddressBookFilter) ([]AddressBookWithRule, int64, error) {
	apply := func(q *gorm.DB) *gorm.DB {
		if f.Name != "" {
			q = q.Where("b.name LIKE ?", like(f.Name))
		}
		if f.Note != "" {
			q = q.Where("b.note LIKE ?", like(f.Note))
		}
		return q
	}

	var total int64
	if err := apply(accessibleScope(ctx, r, userGuid, groupGuids).Session(&gorm.Session{})).
		Distinct("b.guid").Count(&total).Error; err != nil {
		return nil, 0, err
	}

	fetch := apply(accessibleScope(ctx, r, userGuid, groupGuids).Session(&gorm.Session{})).
		Select("b.*, MAX(COALESCE(r.rule, 0)) AS effectiveRule").
		Group("b.guid").
		Order("b.name ASC, b.guid ASC")
	if f.PageSize > 0 {
		fetch = fetch.Limit(f.PageSize)
		if f.Current > 1 {
			fetch = fetch.Offset((f.Current - 1) * f.PageSize)
		}
	}
	out := make([]AddressBookWithRule, 0)
	if err := fetch.Scan(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// DeleteCascade 级联删除单本地址簿（事务显式清理，共享知识 9）：
// peer_tags（该书 peers 的关联）→ peers → tags → rules → book。
func (r *AddressBookRepo) DeleteCascade(ctx context.Context, guid string) error {
	return r.deleteCascade(ctx, []string{guid})
}

// DeleteByGuids 批量级联删除（deleteSharedAddressBooks 底座；
// 空集为无操作）。
func (r *AddressBookRepo) DeleteByGuids(ctx context.Context, guids []string) error {
	if len(guids) == 0 {
		return nil
	}
	return r.deleteCascade(ctx, guids)
}

// deleteCascade 事务级联删除核心。
func (r *AddressBookRepo) deleteCascade(ctx context.Context, guids []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("DELETE FROM address_book_peer_tags WHERE peerGuid IN"+
			" (SELECT guid FROM address_book_peers WHERE addressBookGuid IN ?)", guids).Error; err != nil {
			return err
		}
		if err := tx.Where("addressBookGuid IN ?", guids).
			Delete(&entity.AddressBookPeer{}).Error; err != nil {
			return err
		}
		if err := tx.Where("addressBookGuid IN ?", guids).
			Delete(&entity.AddressBookTag{}).Error; err != nil {
			return err
		}
		if err := tx.Where("addressBookGuid IN ?", guids).
			Delete(&entity.AddressBookRule{}).Error; err != nil {
			return err
		}
		return tx.Where("guid IN ?", guids).Delete(&entity.AddressBook{}).Error
	})
}

// CountAll 全表计数（dashboard overview counts.addressBooks）。
func (r *AddressBookRepo) CountAll(ctx context.Context) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.AddressBook{}).Count(&n).Error
	return n, err
}

// FindPersonal 取用户个人书（isPersonal=1 每用户至多一本）；未找到
// 返回 ErrNotFound（自动创建语义在服务层，设计事实⑦）。
func (r *AddressBookRepo) FindPersonal(ctx context.Context, owner string) (*entity.AddressBook, error) {
	var b entity.AddressBook
	err := r.db.WithContext(ctx).
		Where("owner = ? AND isPersonal = 1", owner).
		First(&b).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// Touch 刷新 updatedAt（应用层时间戳；SQLite 无 ON UPDATE）。
func (r *AddressBookRepo) Touch(ctx context.Context, guid string, at time.Time) error {
	return r.db.WithContext(ctx).Model(&entity.AddressBook{}).
		Where("guid = ?", guid).
		Update("updatedAt", at).Error
}
