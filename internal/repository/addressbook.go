// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：AddressBookRepo——address_books 表仓储（三态书 + 规则可见性
// 并集聚合 + 应用层级联删除，设计事实⑦/共享知识 9）。
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
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

	// ExcludePersonal 排除个人书（shared/custom profiles 契约：
	// isPersonal=0，事实⑦）。
	ExcludePersonal bool

	// SharedOnly 共享形态过滤（shared/list 契约：isShared=1 OR
	// EXTERNAL_GRANT_EXISTS）。
	SharedOnly bool
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
		if f.ExcludePersonal {
			q = q.Where("b.isPersonal = 0")
		}
		if f.SharedOnly {
			q = q.Where("(b.isShared = 1 OR " + externalGrantExists + ")")
		}
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

// externalGrantExists NOT(EXTERNAL_GRANT_EXISTS) 判定的子查询片段
// （参考复刻）：该书存在指向「非 owner 本人」的规则——组规则、
// everyone 规则、给其他用户的规则——即视为存在外部授权。
const externalGrantExists = "EXISTS (SELECT 1 FROM address_book_rules egr"+
	" WHERE egr.addressBookGuid = b.guid"+
	" AND (egr.targetGroupId IS NOT NULL"+
	" OR egr.targetUserId IS NULL"+
	" OR egr.targetUserId <> b.owner))"

// ExistsExternalGrant 单书 EXTERNAL_GRANT_EXISTS 判定（custom 定义
// 反向条件，共享知识 9/事实⑦）。
func (r *AddressBookRepo) ExistsExternalGrant(ctx context.Context, guid string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Table("address_book_rules egr").
		Joins("JOIN address_books b ON b.guid = egr.addressBookGuid").
		Where("b.guid = ? AND (egr.targetGroupId IS NOT NULL"+
			" OR egr.targetUserId IS NULL OR egr.targetUserId <> b.owner)", guid).
		Count(&n).Error
	return n > 0, err
}

// FindCustomOwned 私有自定义书复核（custom/update/delete 复核）：
// guid + owner + isPersonal=0 + isShared=0 + NOT(EXTERNAL_GRANT_EXISTS)。
// 未找到返回 ErrNotFound（'Private custom address book does not exist'）。
func (r *AddressBookRepo) FindCustomOwned(ctx context.Context, guid, owner string) (*entity.AddressBook, error) {
	var b entity.AddressBook
	err := r.db.WithContext(ctx).Table("address_books b").
		Where("b.guid = ? AND b.owner = ? AND b.isPersonal = 0 AND b.isShared = 0"+
			" AND NOT ("+externalGrantExists+")", guid, owner).
		First(&b).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// FindSharedForm 共享形态书复核（shared/update/delete/access 复核）：
// guid + isPersonal=0 + (isShared=1 OR EXTERNAL_GRANT_EXISTS)。
// 未找到返回 ErrNotFound。
func (r *AddressBookRepo) FindSharedForm(ctx context.Context, guid string) (*entity.AddressBook, error) {
	var b entity.AddressBook
	err := r.db.WithContext(ctx).Table("address_books b").
		Where("b.guid = ? AND b.isPersonal = 0"+
			" AND (b.isShared = 1 OR "+externalGrantExists+")", guid).
		First(&b).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// FindOrCreateCustom 按名取/建自定义书（preset-address-book 联动底座，
// M2 批复 #3）：owner 名下同名 custom 书命中即返回；否则建行
// （isPersonal=0/isShared=0）。UK 不存在——竞态兜底重查。
func (r *AddressBookRepo) FindOrCreateCustom(ctx context.Context, owner, name string) (*entity.AddressBook, error) {
	if b, err := r.FindByName(ctx, owner, name); err == nil {
		return b, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := time.Now()
	fresh := &entity.AddressBook{
		Guid:      uuid.New().String(),
		Owner:     owner,
		Name:      name,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := r.db.WithContext(ctx).Create(fresh).Error; err != nil {
		if b, qErr := r.FindByName(ctx, owner, name); qErr == nil {
			return b, nil
		}
		return nil, err
	}
	return fresh, nil
}

// DeleteSharedTx 共享书删除（deleteSharedAddressBooks 语义，参考复刻）：
// 事务内仅删 rules + books（peers/tags 留存为孤儿，与参考一致——
// 查询均按 addressBookGuid 定位，孤儿行不可达）。
func (r *AddressBookRepo) DeleteSharedTx(ctx context.Context, guids []string) error {
	if len(guids) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("addressBookGuid IN ?", guids).
			Delete(&entity.AddressBookRule{}).Error; err != nil {
			return err
		}
		return tx.Where("guid IN ?", guids).Delete(&entity.AddressBook{}).Error
	})
}
