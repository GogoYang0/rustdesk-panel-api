// Package dto 本文件：通讯录域（M3 T05）查询参数结构。
// 请求/响应体复用 openapi 生成类型（internal/api），此处仅承载
// query 形态入参；解析失败的 HTTP 语义由 handler 层兜底。
package dto

// BookListQuery GET custom|shared profiles 分页查询（PaginationDto：
// current/pageSize/name/note，name/note LIKE）。
type BookListQuery struct {
	Current  *int   // 页码（1 起，非法 → handler 400）
	PageSize *int   // 页大小（1..200）
	Name     string // LIKE
	Note     string // LIKE
}

// PeersListQuery GET /api/ab/peers 查询参数（ab 必填；tags 逗号分隔
// tag guid 列表；tagMode union|intersection）。
type PeersListQuery struct {
	AB       string  // 地址簿 guid（必填）
	ID       string  // RustDesk ID LIKE（经 peers.id 反查 uuid 过滤）
	Alias    string  // LIKE
	Tags     string  // 逗号分隔 tag guid 列表
	TagMode  string  // union（默认）| intersection
	Current  *int    // 页码
	PageSize *int    // 页大小
}

// RuleListQuery GET /api/ab/rules 查询参数（ab 缺省=我的全部可见书）。
type RuleListQuery struct {
	AB string // 地址簿 guid（可选）
}
