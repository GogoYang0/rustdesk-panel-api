// Package dto 策略域请求/响应载体（设计 §2 dto/strategy.go）。
//
// 契约红线（共享知识 4）：config_options 为 Record<string,string>
// （DB TEXT 存 JSON 串，读出解析，空串/坏数据 → {}）；assign 族请求体
// target_type/target_guids snake_case；重名 400
// "Strategy name already exists"（角色/用户组才是 409）。
package dto

import (
	"net/url"
	"time"
)

// StrategyUpsertRequest POST/PATCH /api/strategies 请求体。
// name 必填；note/config_options 指针三态：nil=PATCH 保持原值，
// 提供即覆盖（config_options 空对象 → 覆盖为 "{}"）。
type StrategyUpsertRequest struct {
	Name          string             `json:"name" validate:"required"`
	Note          *string            `json:"note"`
	ConfigOptions *map[string]string `json:"config_options"`
}

// StrategyView 策略行视图（openapi StrategyView，6 必需键）。
// ConfigOptions 恒非 nil（空解析为 {}）——map 为 nil 时 JSON 序列化成
// null 违反 additionalProperties 契约。
type StrategyView struct {
	Guid          string            `json:"guid"`
	Name          string            `json:"name"`
	Note          string            `json:"note"`
	ConfigOptions map[string]string `json:"config_options"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// StrategyCandidateView 策略候选行（openapi StrategyCandidateView：
// 指派界面下拉，仅 guid/name/note）。
type StrategyCandidateView struct {
	Guid string `json:"guid"`
	Name string `json:"name"`
	Note string `json:"note"`
}

// DeviceTargetView 指派目标候选/指派清单的设备形态行
// （openapi DeviceTargetView：uuid/id 两键，id 为数字设备 ID 字符串）。
type DeviceTargetView struct {
	UUID string `json:"uuid"`
	ID   string `json:"id"`
}

// UserTargetView 指派目标候选/指派清单的用户形态行
// （openapi UserTargetView：name = displayName || username）。
type UserTargetView struct {
	Guid        string `json:"guid"`
	Name        string `json:"name"`
	IsProtected bool   `json:"is_protected"`
}

// AssignRequest POST /api/strategies/{guid}/assign|unassign 请求体
// （openapi AssignRequest：target_guids ∈ [1,200]，上限由 spec 承担，
// 服务层防御性去重）。
type AssignRequest struct {
	TargetType  string   `json:"target_type" validate:"required,oneof=device user device_group"`
	TargetGuids []string `json:"target_guids" validate:"required,min=1,max=200"`
}

// AssignError 指派/解绑逐目标失败项（reason 为固定文案，
// 见 service/strategy 常量）。
type AssignError struct {
	TargetGuid string `json:"target_guid"`
	Reason     string `json:"reason"`
}

// AssignResult 指派/解绑结果：部分成功亦 200（{success, errors} 恒双键）。
type AssignResult struct {
	Success []string      `json:"success"`
	Errors  []AssignError `json:"errors"`
}

// StrategyListQuery GET /api/strategies 查询参数：name LIKE。
type StrategyListQuery struct {
	PaginationQuery
	Name string
}

// ParseStrategyListQuery 从 query 值构建。
func ParseStrategyListQuery(q url.Values) StrategyListQuery {
	return StrategyListQuery{
		PaginationQuery: paginationQuery(q),
		Name:            q.Get("name"),
	}
}

// TargetQuery 指派目标候选/指派清单查询参数
// （target_type 必填枚举；候选端点 ∈ device|user，清单端点
// 另含 device_group——服务层按端点校验，非法值统一 400）。
type TargetQuery struct {
	PaginationQuery
	TargetType string
}

// ParseTargetQuery 从 query 值构建。
func ParseTargetQuery(q url.Values) TargetQuery {
	return TargetQuery{
		PaginationQuery: paginationQuery(q),
		TargetType:      q.Get("target_type"),
	}
}
