// Package dto 用户组域请求/响应载体（设计 §2 dto/usergroup.go）。
//
// 契约红线（共享知识 4）：UserGroupView 行内 is_default/user_count 为
// snake_case；删除结果 deleted_rule_count M2 恒 0（address_book_rules
// 属 M3）。用户组重名冲突为 409 "User group name already exists"
// （与设备组/策略 400 区分）。
package dto

import "net/url"

// UserGroupUpsertRequest POST /api/user-groups、PUT /api/user-groups/{guid}
// 请求体。name 必填；note 指针三态：nil=PATCH/PUT 保持原值，提供即覆盖。
type UserGroupUpsertRequest struct {
	Name string  `json:"name" validate:"required"`
	Note *string `json:"note"`
}

// UserGroupView 用户组行视图（openapi UserGroupView，5 必需键）。
// user_count 为组内成员数（批量计数防 N+1）。
type UserGroupView struct {
	Guid      string `json:"guid"`
	Name      string `json:"name"`
	Note      string `json:"note"`
	IsDefault bool   `json:"is_default"`
	UserCount int64  `json:"user_count"`
}

// UserGroupPage GET /api/user-groups 响应。
type UserGroupPage struct {
	Data  []UserGroupView `json:"data"`
	Total int64           `json:"total"`
}

// MemberView 用户组成员行（openapi MemberView，4 必需键）。
type MemberView struct {
	Guid        string `json:"guid"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

// MemberPage GET /api/user-groups/{guid}/users 响应。
type MemberPage struct {
	Data  []MemberView `json:"data"`
	Total int64        `json:"total"`
}

// MoveUsersRequest POST /api/user-groups/{guid}/users 请求体
// （body {user_guids[]}，minItems 1）。
type MoveUsersRequest struct {
	UserGuids []string `json:"user_guids" validate:"required,min=1"`
}

// MoveUsersResult POST /api/user-groups/{guid}/users 响应：
// 实际移入本组的用户数。
type MoveUsersResult struct {
	MovedUserCount int64 `json:"moved_user_count"`
}

// DeleteUserGroupResult DELETE /api/user-groups/{guid} 响应：
// 成员回落默认组数 + 被删 address_book 规则数（M2 恒 0）。
type DeleteUserGroupResult struct {
	MovedUserCount   int64 `json:"moved_user_count"`
	DeletedRuleCount int64 `json:"deleted_rule_count"`
}

// UserGroupListQuery GET /api/user-groups 查询参数：name LIKE + 分页。
type UserGroupListQuery struct {
	PaginationQuery
	Name string
}

// ParseUserGroupListQuery 从 query 值构建。
func ParseUserGroupListQuery(q url.Values) UserGroupListQuery {
	return UserGroupListQuery{
		PaginationQuery: paginationQuery(q),
		Name:            q.Get("name"),
	}
}

// MemberListQuery GET /api/user-groups/{guid}/users 查询参数：
// search LIKE 匹配 username/email + 分页。
type MemberListQuery struct {
	PaginationQuery
	Search string
}

// ParseMemberListQuery 从 query 值构建。
func ParseMemberListQuery(q url.Values) MemberListQuery {
	return MemberListQuery{
		PaginationQuery: paginationQuery(q),
		Search:          q.Get("search"),
	}
}
