package entity

import "time"

// ShareRule 地址簿共享规则档位（设计事实⑦：ShareRule 枚举）。
const (
	ShareRuleRead        = 1 // 只读
	ShareRuleReadWrite   = 2 // 读写
	ShareRuleFullControl = 3 // 完全控制（owner 等效档）
)

// AddressBookRule address_book_rules 表实体：共享授权规则。
//
// 复合 PK (guid, addressBookGuid)；TargetUserId/TargetGroupId 双空 =
// everyone（对所有人可见）；权限判定 = owner 全权 ∪ 规则并集取最大
// （服务层 MAX(owner→FULL_CONTROL, 并集最大值) 组装响应行）。
// targetGroupId 的级联删除在 user-group 删除事务内显式执行（M2 批复 #4）。
type AddressBookRule struct {
	Guid            string    `gorm:"column:guid;primaryKey;size:36"`
	AddressBookGuid string    `gorm:"column:addressBookGuid;primaryKey;size:36;not null"`
	TargetUserId    *string   `gorm:"column:targetUserId;size:36"`
	TargetGroupId   *string   `gorm:"column:targetGroupId;size:36"`
	Rule            int       `gorm:"column:rule;not null"`
	CreatedAt       time.Time `gorm:"column:createdAt"`
}

// TableName 指定表名。
func (AddressBookRule) TableName() string { return "address_book_rules" }

// RuleType 规则档位名（类图方法；未知档位返回 unknown 兜底）。
func (r AddressBookRule) RuleType() string {
	switch r.Rule {
	case ShareRuleRead:
		return "read"
	case ShareRuleReadWrite:
		return "read_write"
	case ShareRuleFullControl:
		return "full_control"
	default:
		return "unknown"
	}
}

// IsEveryone 双空 = everyone 规则。
func (r AddressBookRule) IsEveryone() bool {
	return r.TargetUserId == nil && r.TargetGroupId == nil
}
