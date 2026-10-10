package entity

import "time"

// AddressBookPeer address_book_peers 表实体：地址簿设备条目。
//
// Hash/Password 为受控访问凭据文本（参考即如此）；GUID 由应用层生成
// （uuid v4）。级联：书删除时应用层事务显式清理本表（共享知识 9）。
type AddressBookPeer struct {
	Guid            string    `gorm:"column:guid;primaryKey;size:36"`
	AddressBookGuid string    `gorm:"column:addressBookGuid;size:36;not null"`
	DeviceId        string    `gorm:"column:deviceId;size:255;not null"`
	Hash            *string   `gorm:"column:hash;size:255"`
	Password        *string   `gorm:"column:password;size:255"`
	Alias           *string   `gorm:"column:alias;size:255"`
	Note            string    `gorm:"column:note"`
	CreatedAt       time.Time `gorm:"column:createdAt"`
	UpdatedAt       time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (AddressBookPeer) TableName() string { return "address_book_peers" }
