package entity

import "time"

// AddressBook address_books 表实体：地址簿三态（设计事实⑦）。
//
// personal：isPersonal=1（每用户至多一本，name='Personal'，首次访问自动建）；
// custom：isPersonal=0 AND isShared=0 且无 EXTERNAL_GRANT_EXISTS 规则；
// shared：isShared=1（经 share 链路产生）。
// Info 为 JSON 串（含 password，参考即如此复刻）。
type AddressBook struct {
	Guid       string    `gorm:"column:guid;primaryKey;size:36"`
	Owner      string    `gorm:"column:owner;size:36;not null"`
	IsPersonal bool      `gorm:"column:isPersonal;not null;default:false"`
	IsShared   bool      `gorm:"column:isShared;not null;default:false"`
	Name       string    `gorm:"column:name;size:255;not null"`
	Note       string    `gorm:"column:note"`
	Info       string    `gorm:"column:info"`
	CreatedAt  time.Time `gorm:"column:createdAt"`
	UpdatedAt  time.Time `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (AddressBook) TableName() string { return "address_books" }
