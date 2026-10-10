// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：AddressBookTagRepo——address_book_tags 表仓储
// （UK(addressBookGuid, name) 幂等创建，设计事实⑦）。
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// AddressBookTagRepo address_book_tags 表仓储。
type AddressBookTagRepo struct {
	*GenericRepository[entity.AddressBookTag]
}

// NewAddressBookTagRepo 构建仓储。
func NewAddressBookTagRepo(db *gorm.DB) *AddressBookTagRepo {
	return &AddressBookTagRepo{GenericRepository: New[entity.AddressBookTag](db)}
}

// FindOrCreate 幂等创建：按 (addressBookGuid, name) 定位，命中返回既有
// 行（不覆盖颜色）；未命中建行（guid 应用层生成），UK 冲突竞态时重查。
func (r *AddressBookTagRepo) FindOrCreate(ctx context.Context, bookGuid, name string, color uint32) (*entity.AddressBookTag, error) {
	var tag entity.AddressBookTag
	err := r.db.WithContext(ctx).
		Where("addressBookGuid = ? AND name = ?", bookGuid, name).
		First(&tag).Error
	if err == nil {
		return &tag, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	fresh := &entity.AddressBookTag{
		Guid:            uuid.New().String(),
		AddressBookGuid: bookGuid,
		Name:            name,
		Color:           color,
		CreatedAt:       time.Now(),
	}
	if err := r.db.WithContext(ctx).Create(fresh).Error; err != nil {
		var existing entity.AddressBookTag
		if qErr := r.db.WithContext(ctx).
			Where("addressBookGuid = ? AND name = ?", bookGuid, name).
			First(&existing).Error; qErr == nil {
			return &existing, nil
		}
		return nil, err
	}
	return fresh, nil
}

// UpdateColor 改颜色（PATCH tag/color；ARGB uint32）。
func (r *AddressBookTagRepo) UpdateColor(ctx context.Context, guid string, color uint32) error {
	return r.db.WithContext(ctx).Model(&entity.AddressBookTag{}).
		Where("guid = ?", guid).
		Update("color", color).Error
}

// Rename 改名（PUT tag；同名冲突由 UK 抛错上抛）。
func (r *AddressBookTagRepo) Rename(ctx context.Context, guid, name string) error {
	return r.db.WithContext(ctx).Model(&entity.AddressBookTag{}).
		Where("guid = ?", guid).
		Update("name", name).Error
}

// ListByBook 书内全部标签（ab 数据组装；排序 name ASC）。
func (r *AddressBookTagRepo) ListByBook(ctx context.Context, bookGuid string) ([]entity.AddressBookTag, error) {
	out := make([]entity.AddressBookTag, 0)
	err := r.db.WithContext(ctx).
		Where("addressBookGuid = ?", bookGuid).
		Order("name ASC").
		Find(&out).Error
	return out, err
}

// FindByBookAndName 书内按名定位标签（add 同名 409 'Tag already
// exists'、rename 冲突 'New tag name already exists'）。
func (r *AddressBookTagRepo) FindByBookAndName(ctx context.Context, bookGuid, name string) (*entity.AddressBookTag, error) {
	var tag entity.AddressBookTag
	err := r.db.WithContext(ctx).
		Where("addressBookGuid = ? AND name = ?", bookGuid, name).
		First(&tag).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &tag, nil
}

// TagColorInput 全量替换的标签行（POST /api/ab/tags/{guid}）。
type TagColorInput struct {
	Name  string
	Color uint32
}

// ReplaceBookTagsTx 书内标签全量替换（事务：清书内 peer_tags →
// 清 tags → 按入参重建）。
func (r *AddressBookTagRepo) ReplaceBookTagsTx(tx *gorm.DB, bookGuid string, tags []TagColorInput) error {
	if err := tx.Exec("DELETE FROM address_book_peer_tags WHERE peerGuid IN"+
		" (SELECT guid FROM address_book_peers WHERE addressBookGuid = ?)", bookGuid).Error; err != nil {
		return err
	}
	if err := tx.Where("addressBookGuid = ?", bookGuid).
		Delete(&entity.AddressBookTag{}).Error; err != nil {
		return err
	}
	now := time.Now()
	for _, t := range tags {
		if err := tx.Create(&entity.AddressBookTag{
			Guid:            uuid.New().String(),
			AddressBookGuid: bookGuid,
			Name:            t.Name,
			Color:           t.Color,
			CreatedAt:       now,
		}).Error; err != nil {
			return err
		}
	}
	return nil
}

// DeleteByGuid 删单标签（调用方先清 peer_tags）。
func (r *AddressBookTagRepo) DeleteByGuid(ctx context.Context, guid string) error {
	return r.db.WithContext(ctx).
		Where("guid = ?", guid).
		Delete(&entity.AddressBookTag{}).Error
}
