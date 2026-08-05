// Package dto 设备域请求/响应载体（设计 §2 dto/device.go）。
//
// 命名红线（共享知识 2）：设备端协议字段 snake_case（id/uuid/ver/
// modified_at），sysinfo 预设键 kebab-case（preset-username 等，struct
// tag 原样映射）；PATCH /api/devices 的关联字段为 camelCase（userName/
// deviceGroupName/strategyName）；分页参数 current/pageSize 为 camelCase
// 与 snake_case 过滤键混用——全部是契约本身，禁止"规范化"。
package dto

import (
	"net/url"
	"strconv"
	"time"
)

// PaginationQuery 列表端点共享分页参数（设计 §1.5，边界同 §1.1⑤：
// current 默认 1 ∈[1,100000]；pageSize 默认 20 ∈[1,100]）。
type PaginationQuery struct {
	Current  int
	PageSize int
}

// PageResult 泛型分页包络：恒为 {data, total}（无 extra 字段，共享知识 4）。
type PageResult[T any] struct {
	Data  []T   `json:"data"`
	Total int64 `json:"total"`
}

// 分页边界常量（openapi CurrentParam/PageSizeParam 契约镜像）。
const (
	DefaultCurrent  = 1
	DefaultPageSize = 20
	MaxCurrent      = 100000
	MaxPageSize     = 100
)

// paginationQuery 从 query 值解析分页参数；非法/越界值钳制到边界
// （契约校验由 openapi 层承担，服务端防御性钳制不回 400）。
func paginationQuery(q url.Values) PaginationQuery {
	current := clampInt(q.Get("current"), DefaultCurrent, MaxCurrent)
	pageSize := clampInt(q.Get("pageSize"), DefaultPageSize, MaxPageSize)
	return PaginationQuery{Current: current, PageSize: pageSize}
}

// clampInt 解析整型并钳制到 [min, max]；解析失败取 fallback。
func clampInt(raw string, fallback, max int) int {
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if v < 1 {
		return fallback
	}
	if v > max {
		return max
	}
	return v
}

// statusOr 读取 '0'/'1' 枚举查询参数为 *int；缺失或非法值返回 nil
// （表示未过滤）。
func statusOr(q url.Values, key string) *int {
	switch q.Get(key) {
	case "1":
		v := 1
		return &v
	case "0":
		v := 0
		return &v
	default:
		return nil
	}
}

// boolOr 读取 '0'/'1' 枚举查询参数为 *bool；缺失或非法值返回 nil。
func boolOr(q url.Values, key string) *bool {
	switch q.Get(key) {
	case "1":
		v := true
		return &v
	case "0":
		v := false
		return &v
	default:
		return nil
	}
}

// ==================== 设备端协议（heartbeat / sysinfo） ====================

// HeartbeatRequest POST /api/heartbeat 请求体（openapi HeartbeatRequest）。
// conns 为指针：键缺失 ≠ 空数组——nil 表示客户端未上报连接快照
// （不触发 conns diff 与断连确认），空数组表示已无活跃连接。
type HeartbeatRequest struct {
	ID         string   `json:"id" validate:"required"`
	UUID       string   `json:"uuid" validate:"required"`
	Ver        int64    `json:"ver"`
	ModifiedAt int64    `json:"modified_at"`
	Conns      *[]int64 `json:"conns,omitempty"`
}

// StrategyOptionsPayload HeartbeatResponse.strategy 载荷
// （config_options 为 Record<string,string>，值恒字符串——解析见
// service/device.ParseConfigOptions，脏数据防御为空 map）。
type StrategyOptionsPayload struct {
	ConfigOptions map[string]string `json:"config_options"`
}

// HeartbeatResponse POST /api/heartbeat 响应（条件键：无 pending 断连、
// 策略门槛未过时序列化为 {}）。modified_at 恒 >0 时才出现（门槛保证）。
type HeartbeatResponse struct {
	Disconnect []int64                 `json:"disconnect,omitempty"`
	Strategy   *StrategyOptionsPayload `json:"strategy,omitempty"`
	ModifiedAt int64                   `json:"modified_at,omitempty"`
}

// SysinfoRequest POST /api/sysinfo 请求体。kebab-case 预设键原样 tag
// 映射（红线：禁止转 camelCase/snake_case）；preset-address-book-* 五键
// M2 接受不处理（M3 通讯录联动）；version 接受不落库。
type SysinfoRequest struct {
	UUID     string `json:"uuid" validate:"required"`
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	CPU      string `json:"cpu"`
	Memory   string `json:"memory"`
	Version  string `json:"version"`

	PresetAddressBookName     string `json:"preset-address-book-name"`
	PresetAddressBookTag      string `json:"preset-address-book-tag"`
	PresetAddressBookAlias    string `json:"preset-address-book-alias"`
	PresetAddressBookPassword string `json:"preset-address-book-password"`
	PresetAddressBookNote     string `json:"preset-address-book-note"`

	PresetUsername        string `json:"preset-username"`
	PresetStrategyName    string `json:"preset-strategy-name"`
	PresetDeviceGroupName string `json:"preset-device-group-name"`
	PresetNote            string `json:"preset-note"`
}

// ==================== 设备视图（/peers 与 /devices 同表两视图） ====================

// PeerInfo /peers 与 /devices 共用的系统信息块（openapi PeerInfo）。
// DeviceName = sysinfos.hostname；IP 恒为空串（参考行为契约）。
type PeerInfo struct {
	DeviceName string `json:"device_name"`
	Username   string `json:"username"`
	OS         string `json:"os"`
	Version    string `json:"version"`
	CPU        string `json:"cpu"`
	Memory     string `json:"memory"`
	IP         string `json:"ip"`
}

// PeerView GET /api/peers 行视图（11 必需字段）。GUID = peer.uuid；
// User = userGuid 或空串；is_online = lastHeartbeat > now-60s。
type PeerView struct {
	ID              string     `json:"id"`
	GUID            string     `json:"guid"`
	Status          int        `json:"status"`
	IsOnline        bool       `json:"is_online"`
	LastOnline      *time.Time `json:"last_online"`
	User            string     `json:"user"`
	UserName        string     `json:"user_name"`
	Note            string     `json:"note"`
	DeviceGroupName string     `json:"device_group_name"`
	StrategyName    string     `json:"strategy_name"`
	Info            PeerInfo   `json:"info"`
}

// DeviceView GET /api/devices 行视图 = PeerView + 关联 guid 双键
// （openapi DeviceView allOf 第二段；键名 userGuid/deviceGroupGuid 为
// camelCase 契约，可空）。
type DeviceView struct {
	PeerView
	UserGuid        *string `json:"userGuid"`
	DeviceGroupGuid *string `json:"deviceGroupGuid"`
}

// ==================== 设备管理（/devices ×6） ====================

// DeviceStatusUpdateRequest PATCH /api/devices/status 请求体
// （guids 为 peer.uuid 数组；status 字符串枚举）。
type DeviceStatusUpdateRequest struct {
	Guids  []string `json:"guids" validate:"required,min=1"`
	Status string   `json:"status" validate:"required,oneof=enabled disabled"`
}

// DeviceStatusUpdateResult 批量启停结果（逐设备落库语义）。
type DeviceStatusUpdateResult struct {
	Succeeded      []string `json:"succeeded"`
	Failed         []string `json:"failed"`
	Total          int      `json:"total"`
	SucceededCount int      `json:"succeededCount"`
	FailedCount    int      `json:"failedCount"`
}

// UpdateDeviceRequest PATCH /api/devices/{guid} 请求体。
// note 任意 devices.edit 操作者可改；关联字段（userName/deviceGroupName/
// strategyName，按名称匹配）变更需 super administrator；空串=解绑；
// 指针 nil=不更新（三态语义）。
type UpdateDeviceRequest struct {
	Note            *string `json:"note"`
	UserName        *string `json:"userName"`
	DeviceGroupName *string `json:"deviceGroupName"`
	StrategyName    *string `json:"strategyName"`
}

// DisconnectRequest POST /api/devices/{uuid}/disconnect 请求体。
type DisconnectRequest struct {
	ConnIDs []int64 `json:"connIds" validate:"required,min=1"`
}

// DisconnectResult 断连入队结果：pending_disconnect_count 为当前
// pending 总数（含本次入队）。
type DisconnectResult struct {
	PendingDisconnectCount int `json:"pending_disconnect_count"`
}

// ==================== 列表查询参数（/peers 与 /devices 语义差异锁定） ====================

// PeerListQuery GET /api/peers 查询参数。
// 过滤语义（openapi /api/peers）：id/user_name/device_group_name/os 均
// LIKE；device_group_guid 精确；accessible 兼容字段忽略。
type PeerListQuery struct {
	PaginationQuery
	Status          *int
	IsOnline        *bool
	ID              string
	UserName        string
	DeviceGroupGuid string
	DeviceGroupName string
	OS              string
}

// ParsePeerListQuery 从 query 值构建（handler 入口一次性解析）。
func ParsePeerListQuery(q url.Values) PeerListQuery {
	return PeerListQuery{
		PaginationQuery: paginationQuery(q),
		Status:          statusOr(q, "status"),
		IsOnline:        boolOr(q, "is_online"),
		ID:              q.Get("id"),
		UserName:        q.Get("user_name"),
		DeviceGroupGuid: q.Get("device_group_guid"),
		DeviceGroupName: q.Get("device_group_name"),
		OS:              q.Get("os"),
	}
}

// DeviceListQuery GET /api/devices 查询参数。
// 过滤语义差异（对齐 openapi /api/devices，禁止与 /peers 混用）：
// id/user_name/os/device_group_name 精确；device_name LIKE
// sysinfos.hostname；device_username LIKE sysinfos.username；
// group_name LIKE 设备组名；device_group_guid 精确。
type DeviceListQuery struct {
	PaginationQuery
	Status          *int
	IsOnline        *bool
	ID              string
	DeviceName      string
	UserName        string
	DeviceUsername  string
	OS              string
	DeviceGroupName string
	DeviceGroupGuid string
	GroupName       string
}

// ParseDeviceListQuery 从 query 值构建。
func ParseDeviceListQuery(q url.Values) DeviceListQuery {
	return DeviceListQuery{
		PaginationQuery: paginationQuery(q),
		Status:          statusOr(q, "status"),
		IsOnline:        boolOr(q, "is_online"),
		ID:              q.Get("id"),
		DeviceName:      q.Get("device_name"),
		UserName:        q.Get("user_name"),
		DeviceUsername:  q.Get("device_username"),
		OS:              q.Get("os"),
		DeviceGroupName: q.Get("device_group_name"),
		DeviceGroupGuid: q.Get("device_group_guid"),
		GroupName:       q.Get("group_name"),
	}
}
