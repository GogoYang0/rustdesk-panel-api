// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：AddressBookPeerTagRepo——address_book_peer_tags 表仓储
// （设备↔标签关联：全量替换 / 按设备查标签 / 书内关联枚举）。
package repository

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// AddressBookPeerTagRepo address_book_peer_tags 表仓储。
type AddressBookPeerTagRepo struct {
	*GenericRepository[entity.AddressBookPeerTag]
}

// NewAddressBookPeerTagRepo 构建仓储。
func NewAddressBookPeerTagRepo(db *gorm.DB) *AddressBookPeerTagRepo {
	return &AddressBookPeerTagRepo{GenericRepository: New[entity.AddressBookPeerTag](db)}
}

// ReplaceForPeer 全量替换设备的标签集合（事务：先删后插，入参去重
// 保持幂等；复合 PK 天然防重复行）。
func (r *AddressBookPeerTagRepo) ReplaceForPeer(ctx context.Context, peerGuid string, tagGuids []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("peerGuid = ?", peerGuid).
			Delete(&entity.AddressBookPeerTag{}).Error; err != nil {
			return err
		}
		seen := make(map[string]struct{}, len(tagGuids))
		now := time.Now()
		for _, tagGuid := range tagGuids {
			if _, ok := seen[tagGuid]; ok {
				continue
			}
			seen[tagGuid] = struct{}{}
			if err := tx.Create(&entity.AddressBookPeerTag{
				PeerGuid:  peerGuid,
				TagGuid:   tagGuid,
				CreatedAt: now,
			}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// TagsByPeer 查设备关联的标签行（JOIN tags；排序 name ASC）。
func (r *AddressBookPeerTagRepo) TagsByPeer(ctx context.Context, peerGuid string) ([]entity.AddressBookTag, error) {
	out := make([]entity.AddressBookTag, 0)
	err := r.db.WithContext(ctx).
		Table("address_book_peer_tags pt").
		Select("t.*").
		Joins("JOIN address_book_tags t ON t.guid = pt.tagGuid").
		Where("pt.peerGuid = ?", peerGuid).
		Order("t.name ASC").
		Scan(&out).Error
	return out, err
}

// ListByBook 枚举书内全部关联行（JOIN peers 过滤；数据组装用）。
func (r *AddressBookPeerTagRepo) ListByBook(ctx context.Context, bookGuid string) ([]entity.AddressBookPeerTag, error) {
	out := make([]entity.AddressBookPeerTag, 0)
	err := r.db.WithContext(ctx).
		Table("address_book_peer_tags pt").
		Select("pt.*").
		Joins("JOIN address_book_peers p ON p.guid = pt.peerGuid").
		Where("p.addressBookGuid = ?", bookGuid).
		Scan(&out).Error
	return out, err
}

// DeleteByTag 删某标签的全部关联行（删标签级联半边）。
func (r *AddressBookPeerTagRepo) DeleteByTag(ctx context.Context, tagGuid string) error {
	return r.db.WithContext(ctx).
		Where("tagGuid = ?", tagGuid).
		Delete(&entity.AddressBookPeerTag{}).Error
}

// DeleteByBook 删书内全部关联行（书级联半边，子查询定位该书 peers）。
func (r *AddressBookPeerTagRepo) DeleteByBook(ctx context.Context, bookGuid string) error {
	return r.db.WithContext(ctx).Exec(
		"DELETE FROM address_book_peer_tags WHERE peerGuid IN"+
			" (SELECT guid FROM address_book_peers WHERE addressBookGuid = ?)", bookGuid).Error
}
