// Package dto 设备组域请求/响应载体（设计 §2 dto/devicegroup.go）。
//
// 契约红线（共享知识 4）：DeviceGroupView 行内 strategy_guid/device_count
// 为 snake_case；accessible 行仅 guid/name/note 三键。重名冲突为 400
// "Device group name already exists"（注意角色/用户组为 409，禁止对齐）。
package dto

import (
	"net/url"
	"time"
)

// DeviceGroupUpsertRequest POST/PATCH /api/device-groups 请求体。
// name 必填；note 指针三态：nil=PATCH 保持原值，提供即覆盖。
type DeviceGroupUpsertRequest struct {
	Name string  `json:"name" validate:"required"`
	Note *string `json:"note"`
}

// DeviceGroupView 设备组行视图（openapi DeviceGroupView，7 必需键）。
// strategy_guid 可空（未挂策略 → null）；device_count 为组内设备数。
type DeviceGroupView struct {
	Guid         string    `json:"guid"`
	Name         string    `json:"name"`
	Note         string    `json:"note"`
	StrategyGuid *string   `json:"strategy_guid"`
	DeviceCount  int64     `json:"device_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AccessibleGroupView GET /api/device-group/accessible 行视图
// （openapi AccessibleGroupView：仅 guid/name/note 三必需键）。
type AccessibleGroupView struct {
	Guid string `json:"guid"`
	Name string `json:"name"`
	Note string `json:"note"`
}

// DeviceGroupTargetView 策略指派的设备组候选行
// （openapi DeviceGroupTargetView：guid/name 两键，strategy 域共用）。
type DeviceGroupTargetView struct {
	Guid string `json:"guid"`
	Name string `json:"name"`
}

// AddDevicesResult POST /api/device-groups/{guid} 响应（body=peer.id[]
// 数字设备 ID 数组；added_count 为实际命中的设备数）。
type AddDevicesResult struct {
	AddedCount int64 `json:"added_count"`
}

// RemoveDevicesResult DELETE /api/device-groups/{guid}/devices 响应
// （removed_count 为实际移出该组的设备数）。
type RemoveDevicesResult struct {
	RemovedCount int64 `json:"removed_count"`
}

// DeviceGroupListQuery GET /api/device-groups 查询参数：
// name LIKE（openapi /api/device-groups）。
type DeviceGroupListQuery struct {
	PaginationQuery
	Name string
}

// ParseDeviceGroupListQuery 从 query 值构建。
func ParseDeviceGroupListQuery(q url.Values) DeviceGroupListQuery {
	return DeviceGroupListQuery{
		PaginationQuery: paginationQuery(q),
		Name:            q.Get("name"),
	}
}

// ParsePageQuery 解析纯分页参数（candidates/strategy-targets 等无
// 过滤键的列表端点共用）。
func ParsePageQuery(q url.Values) PaginationQuery {
	return paginationQuery(q)
}
