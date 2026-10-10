// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：AddressBookPeerRepo——address_book_peers 表仓储
// （findOrCreatePeer 语义 + 标签双模式过滤列表，设计事实⑦）。
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// TagFilterMode 标签过滤模式（契约 PeersQueryDto.tagMode）。
const (
	TagModeUnion        = "union"        // 任一命中
	TagModeIntersection = "intersection" // 全部命中
)

// ABPeerFilter 地址簿设备列表过滤（PeersQueryDto：id/alias/tags[]/
// tagMode + PaginationDto）。
type ABPeerFilter struct {
	ID       string   // RustDesk ID LIKE（语义为 peers.id；deviceId 引用 uuid，服务层先反查后走 DeviceUUIDs）
	Alias    string   // LIKE
	TagGuids []string // 标签过滤（空 = 不过滤）
	TagMode  string   // union | intersection（空默认 union）
	Current  int      // 页码（1 起）
	PageSize int      // 页大小（0 = 不分页）

	// DeviceUUIDs deviceId IN 过滤（id 反查 uuid 的结果集）。
	DeviceUUIDs []string
}

// AddressBookPeerRepo address_book_peers 表仓储。
type AddressBookPeerRepo struct {
	*GenericRepository[entity.AddressBookPeer]
}

// NewAddressBookPeerRepo 构建仓储。
func NewAddressBookPeerRepo(db *gorm.DB) *AddressBookPeerRepo {
	return &AddressBookPeerRepo{GenericRepository: New[entity.AddressBookPeer](db)}
}

// FindOrCreate findOrCreatePeer 底座：按 (addressBookGuid, deviceId)
// 定位，命中返回既有行；否则建行（guid 由应用层生成 uuid v4，
// hash/password/alias 取默认空）。
func (r *AddressBookPeerRepo) FindOrCreate(ctx context.Context, bookGuid, deviceId string) (*entity.AddressBookPeer, error) {
	var p entity.AddressBookPeer
	err := r.db.WithContext(ctx).
		Where("addressBookGuid = ? AND deviceId = ?", bookGuid, deviceId).
		First(&p).Error
	if err == nil {
		return &p, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	now := time.Now()
	fresh := &entity.AddressBookPeer{
		Guid:            uuid.New().String(),
		AddressBookGuid: bookGuid,
		DeviceId:        deviceId,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := r.db.WithContext(ctx).Create(fresh).Error; err != nil {
		// 并发竞态兜底：重查既有行。
		var existing entity.AddressBookPeer
		if qErr := r.db.WithContext(ctx).
			Where("addressBookGuid = ? AND deviceId = ?", bookGuid, deviceId).
			First(&existing).Error; qErr == nil {
			return &existing, nil
		}
		return nil, err
	}
	return fresh, nil
}

// Upsert 按幂等键 (addressBookGuid, deviceId) 更新或插入：
// 命中则更新 hash/password/alias/note（identity 列不动），
// 未命中则落库入参（guid 空则生成）。返回落库后的行。
func (r *AddressBookPeerRepo) Upsert(ctx context.Context, p *entity.AddressBookPeer) (*entity.AddressBookPeer, error) {
	var existing entity.AddressBookPeer
	err := r.db.WithContext(ctx).
		Where("addressBookGuid = ? AND deviceId = ?", p.AddressBookGuid, p.DeviceId).
		First(&existing).Error
	switch {
	case err == nil:
		updates := map[string]any{"updatedAt": time.Now()}
		if p.Hash != nil {
			updates["hash"] = *p.Hash
		}
		if p.Password != nil {
			updates["password"] = *p.Password
		}
		if p.Alias != nil {
			updates["alias"] = *p.Alias
		}
		if p.Note != "" {
			updates["note"] = p.Note
		}
		if err := r.db.WithContext(ctx).Model(&entity.AddressBookPeer{}).
			Where("guid = ?", existing.Guid).
			Updates(updates).Error; err != nil {
			return nil, err
		}
		if err := r.db.WithContext(ctx).Where("guid = ?", existing.Guid).First(&existing).Error; err != nil {
			return nil, err
		}
		return &existing, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		now := time.Now()
		p.CreatedAt, p.UpdatedAt = now, now
		if p.Guid == "" {
			p.Guid = uuid.New().String()
		}
		if err := r.db.WithContext(ctx).Create(p).Error; err != nil {
			return nil, err
		}
		return p, nil
	default:
		return nil, err
	}
}

// applyABPeerFilter 构建 ab 设备过滤链（表别名 p；标签过滤走
// EXISTS/COUNT 关系除法，双方言通用）。
func applyABPeerFilter(f ABPeerFilter) func(*gorm.DB) *gorm.DB {
	return func(q *gorm.DB) *gorm.DB {
		if len(f.DeviceUUIDs) > 0 {
			q = q.Where("p.deviceId IN ?", f.DeviceUUIDs)
		}
		if f.Alias != "" {
			q = q.Where("p.alias LIKE ?", like(f.Alias))
		}
		if len(f.TagGuids) > 0 {
			switch f.TagMode {
			case TagModeIntersection:
				// 全部命中：该设备命中的去重标签数 == 传入标签数。
				q = q.Where(
					"(SELECT COUNT(DISTINCT pt.tagGuid) FROM address_book_peer_tags pt"+
						" WHERE pt.peerGuid = p.guid AND pt.tagGuid IN ?) = ?",
					f.TagGuids, len(f.TagGuids))
			default:
				// union（默认）：任一命中。
				q = q.Where("EXISTS (SELECT 1 FROM address_book_peer_tags pt"+
					" WHERE pt.peerGuid = p.guid AND pt.tagGuid IN ?)", f.TagGuids)
			}
		}
		return q
	}
}

// ExistsInBook 设备是否已在书内（ab peer add 的重复判定，参考
// 'Device already exists in the address book'）。
func (r *AddressBookPeerRepo) ExistsInBook(ctx context.Context, bookGuid, deviceId string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.AddressBookPeer{}).
		Where("addressBookGuid = ? AND deviceId = ?", bookGuid, deviceId).
		Count(&n).Error
	return n > 0, err
}

// DeleteByGuid 删单设备行（调用方先清 peer_tags）。
func (r *AddressBookPeerRepo) DeleteByGuid(ctx context.Context, guid string) error {
	return r.db.WithContext(ctx).
		Where("guid = ?", guid).
		Delete(&entity.AddressBookPeer{}).Error
}

// UpdateColumns 按列更新（ab peer 编辑：hash/password/alias/note/updatedAt）。
func (r *AddressBookPeerRepo) UpdateColumns(ctx context.Context, guid string, updates map[string]any) error {
	return r.db.WithContext(ctx).Model(&entity.AddressBookPeer{}).
		Where("guid = ?", guid).
		Updates(updates).Error
}

// ListByBook 书内设备分页（GET ab/peers 底座；排序 deviceId ASC +
// guid ASC，确定性输出）。
func (r *AddressBookPeerRepo) ListByBook(ctx context.Context, bookGuid string, f ABPeerFilter) ([]entity.AddressBookPeer, int64, error) {
	apply := applyABPeerFilter(f)
	base := r.db.WithContext(ctx).Table("address_book_peers p").
		Where("p.addressBookGuid = ?", bookGuid)

	var total int64
	if err := apply(base.Session(&gorm.Session{})).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := apply(base.Session(&gorm.Session{})).Order("p.deviceId ASC, p.guid ASC")
	if f.PageSize > 0 {
		fetch = fetch.Limit(f.PageSize)
		if f.Current > 1 {
			fetch = fetch.Offset((f.Current - 1) * f.PageSize)
		}
	}
	out := make([]entity.AddressBookPeer, 0)
	if err := fetch.Select("p.*").Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// DeleteByBook 删书内全部设备及其标签关联（legacy POST ab 全删全插的
// 删半边；事务显式级联，不依赖 FK）。
func (r *AddressBookPeerRepo) DeleteByBook(ctx context.Context, bookGuid string) error {
	return r.DeleteByBookTx(r.db.WithContext(ctx), bookGuid)
}

// DeleteByBookTx legacy 事务版删半边（外层事务由服务层编排）：
// peer_tags → ab_peers。
func (r *AddressBookPeerRepo) DeleteByBookTx(tx *gorm.DB, bookGuid string) error {
	if err := tx.Exec("DELETE FROM address_book_peer_tags WHERE peerGuid IN"+
		" (SELECT guid FROM address_book_peers WHERE addressBookGuid = ?)", bookGuid).Error; err != nil {
		return err
	}
	return tx.Where("addressBookGuid = ?", bookGuid).Delete(&entity.AddressBookPeer{}).Error
}

// InsertTagTx legacy 事务内按名幂等建标签（color 缺省 0；UK 冲突重查）。
func (r *AddressBookPeerRepo) InsertTagTx(tx *gorm.DB, bookGuid, name string, color uint32) (*entity.AddressBookTag, error) {
	var tag entity.AddressBookTag
	err := tx.Where("addressBookGuid = ? AND name = ?", bookGuid, name).First(&tag).Error
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
	if err := tx.Create(fresh).Error; err != nil {
		var existing entity.AddressBookTag
		if qErr := tx.Where("addressBookGuid = ? AND name = ?", bookGuid, name).First(&existing).Error; qErr == nil {
			return &existing, nil
		}
		return nil, err
	}
	return fresh, nil
}

// InsertPeerTx legacy 事务内建 ab peer 行（deviceId=peers.uuid）。
func (r *AddressBookPeerRepo) InsertPeerTx(tx *gorm.DB, bookGuid, deviceUUID, hash, alias string) (*entity.AddressBookPeer, error) {
	now := time.Now()
	row := &entity.AddressBookPeer{
		Guid:            uuid.New().String(),
		AddressBookGuid: bookGuid,
		DeviceId:        deviceUUID,
		Hash:            strPtrOf(hash),
		Password:        nil,
		Alias:           strPtrOf(alias),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := tx.Create(row).Error; err != nil {
		return nil, err
	}
	return row, nil
}

// LinkTagTx 幂等关联设备与标签（复合 PK 冲突忽略，双方言经
// ON CONFLICT DO NOTHING 表达）。
func (r *AddressBookPeerRepo) LinkTagTx(tx *gorm.DB, peerGuid, tagGuid string) error {
	return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&entity.AddressBookPeerTag{
		PeerGuid:  peerGuid,
		TagGuid:   tagGuid,
		CreatedAt: time.Now(),
	}).Error
}

// strPtrOf 空串→nil（ab peers 的 hash/alias 列语义：空值落 NULL，
// 参考行为 row.hash || '' 读侧兜底）。
func strPtrOf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
