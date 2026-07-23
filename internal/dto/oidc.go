package dto

// ProviderOption 登录选项对象形态（带图标时输出 [{name, icon}]）。
type ProviderOption struct {
	Name string `json:"name"`
	Icon string `json:"icon"`
}

// LoginOptionsResult GET /api/login-options 结果。
//
// 渲染规则（对齐参考 OidcController）：任一提供商带 icon 时输出 Items
// 对象数组，否则输出 Names 字符串数组（"oidc/{name}"）；
// 空列表输出 []。
type LoginOptionsResult struct {
	Names    []string
	Items    []ProviderOption
	HasIcons bool
}

// AuthURLResult POST /api/oidc/auth 响应：{url}。
type AuthURLResult struct {
	URL string `json:"url"`
}
