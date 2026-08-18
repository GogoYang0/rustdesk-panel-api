package entity

import "time"

// ConnectionAudit action 取值（设计事实②：conn 上报 upsert 状态机）。
const (
	ConnActionNew         = "new"         // 首报落库
	ConnActionOpen        = "open"        // 二次 action='new' → 迁移
	ConnActionEstablished = "established" // action='' → 迁移 + establishedAt
)

// ConnectionAudit connection_audits 表实体：连接审计（上报端 Public
// + per-IP 50/min；查询端 audit.view）。
//
// 定位键 (deviceId, deviceUuid, connId)（IDX_connection_audits_conn_key）；
// Nonce 可空——UNIQUE(deviceId,nonce) 中 NULL 不参与去重（双方言一致）；
// DeviceUuid/ConnId/SessionId 可空（note-only 上报仅带 session_id）。
// 时间锚点：RequestedAt 由上报链赋值（trends 按日聚合维度之一）。
type ConnectionAudit struct {
	Id            uint       `gorm:"column:id;primaryKey;autoIncrement"`
	DeviceId      string     `gorm:"column:deviceId;size:255;not null"`
	DeviceUuid    *string    `gorm:"column:deviceUuid;size:36"`
	ConnId        *string    `gorm:"column:connId;size:64"`
	SessionId     *string    `gorm:"column:sessionId;size:64"`
	Ip            *string    `gorm:"column:ip;size:64"`
	Action        string     `gorm:"column:action;size:32;not null;default:'new'"`
	PeerId        *string    `gorm:"column:peerId;size:255"`
	PeerName      *string    `gorm:"column:peerName;size:255"`
	Type          int        `gorm:"column:type;not null;default:0"`
	RequestedAt   time.Time  `gorm:"column:requestedAt;not null"`
	EstablishedAt *time.Time `gorm:"column:establishedAt"`
	ClosedAt      *time.Time `gorm:"column:closedAt"`
	Note          *string    `gorm:"column:note;size:256"`
	Nonce         *string    `gorm:"column:nonce;size:36"`
	ConnAuditRef  *string    `gorm:"column:connAuditRef;size:36"`
	PrimaryAuth   int        `gorm:"column:primaryAuth;not null;default:0"`
	TwoFactor     int        `gorm:"column:twoFactor;not null;default:0"`
}

// TableName 指定表名。
func (ConnectionAudit) TableName() string { return "connection_audits" }

// IsEstablished 连接是否已建立（仪表盘 success 口径半边）。
func (c ConnectionAudit) IsEstablished() bool { return c.EstablishedAt != nil }

// IsClosed 连接是否已关闭。
func (c ConnectionAudit) IsClosed() bool { return c.ClosedAt != nil }
