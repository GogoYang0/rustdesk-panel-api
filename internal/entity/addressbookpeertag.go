package entity

import "time"

// AddressBookPeerTag address_book_peer_tags 表实体：设备↔标签关联
// （复合 PK peerGuid+tagGuid）。级联由应用层执行：删书清理全部关联
// 行、删标签清理该标签关联行（共享知识 9）。
type AddressBookPeerTag struct {
	PeerGuid  string    `gorm:"column:peerGuid;primaryKey;size:36"`
	TagGuid   string    `gorm:"column:tagGuid;primaryKey;size:36"`
	CreatedAt time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (AddressBookPeerTag) TableName() string { return "address_book_peer_tags" }
