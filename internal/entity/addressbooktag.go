package entity

import "time"

// AddressBookTag address_book_tags 表实体：地址簿标签。
//
// 唯一约束 UK(addressBookGuid, name)——FindOrCreate 冲突即返回既有行；
// Color 为 ARGB uint32（契约 color uint）。
type AddressBookTag struct {
	Guid            string    `gorm:"column:guid;primaryKey;size:36"`
	AddressBookGuid string    `gorm:"column:addressBookGuid;size:36;not null"`
	Name            string    `gorm:"column:name;size:255;not null"`
	Color           uint32    `gorm:"column:color;not null;default:0"`
	CreatedAt       time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (AddressBookTag) TableName() string { return "address_book_tags" }
