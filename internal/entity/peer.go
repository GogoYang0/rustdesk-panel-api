package entity

import "time"

// Peer peers 表实体：RustDesk 设备（uuid PK；peers/devices 同表两视图）。
//
// userGuid 无 FK（与参考一致，设备先于用户存在的合法态）；
// deviceGroupGuid/strategyGuid 可空外键：SET NULL 语义（迁移 SQL 契约）。
// Status：1=active / 0=disabled（共享知识 6）。
// Ver：客户端版本号编码整数（共享知识 8 格式化规则）；
// ModifiedAt：客户端策略版本戳（毫秒 epoch，共享知识 7）。
type Peer struct {
	UUID            string     `gorm:"column:uuid;primaryKey;size:36"`
	ID              string     `gorm:"column:id;size:255;not null;default:''"`
	UserGuid        *string    `gorm:"column:userGuid;size:36"`
	DeviceGroupGuid *string    `gorm:"column:deviceGroupGuid;size:36"`
	StrategyGuid    *string    `gorm:"column:strategyGuid;size:36"`
	Note            string     `gorm:"column:note"`
	Status          int        `gorm:"column:status;not null;default:1"`
	Ver             int64      `gorm:"column:ver;not null;default:0"`
	ModifiedAt      int64      `gorm:"column:modifiedAt;not null;default:0"`
	LastHeartbeat   *time.Time `gorm:"column:lastHeartbeat"`
	CreatedAt       time.Time  `gorm:"column:createdAt"`
	UpdatedAt       time.Time  `gorm:"column:updatedAt"`
}

// TableName 指定表名。
func (Peer) TableName() string { return "peers" }

// PeerStatus 状态取值。
const (
	PeerStatusDisabled int = 0
	PeerStatusActive   int = 1
)

// Online 在线判定（共享知识 6：lastHeartbeat > now-60s）。
func (p *Peer) Online(now time.Time, window time.Duration) bool {
	if p.LastHeartbeat == nil {
		return false
	}
	return p.LastHeartbeat.After(now.Add(-window))
}
