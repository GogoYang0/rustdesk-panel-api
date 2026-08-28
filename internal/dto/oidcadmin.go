// Package dto 本文件：OIDC 提供者管理域 DTO 与校验（设计事实⑧，M3 T07）。
//
// 视图类型别名至 oapi-codegen 产物；sort 请求体为 guid 数组（顺序即
// priority），故不建结构体而直接用 []string 承载。
package dto

import (
	"strings"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// 视图别名：与 openapi 组件一一对应。
type (
	// OidcProviderDtoView 单个提供者视图（clientSecret 明文可见——设计事实⑧）。
	OidcProviderDtoView = api.OidcProviderDto
	// OidcProviderDtoViewType 提供者类型视图枚举。
	OidcProviderDtoViewType = api.OidcProviderDtoType
	// OidcProviderPageView 提供者分页 {data,total}。
	OidcProviderPageView = api.OidcProviderPage
	// OidcProviderUpsertDto POST/PATCH 请求体。
	OidcProviderUpsertDto = api.OidcProviderUpsert
	// OidcProviderSortRequest PATCH /api/oidc-providers/sort 请求体（guid 数组）。
	OidcProviderSortRequest = []string
)

// 视图枚举常量（复用 oapi-codegen 生成值，保证与契约枚举零漂移）。
const (
	// ProviderTypeOIDCView 视图枚举 oidc。
	ProviderTypeOIDCView = api.OidcProviderDtoTypeOidc
	// ProviderTypeOAuth2View 视图枚举 oauth2。
	ProviderTypeOAuth2View = api.OidcProviderDtoTypeOauth2
)

// ProviderTypeOIDC / ProviderTypeOAuth2 提供者类型枚举（openapi enum）。
const (
	ProviderTypeOIDC   = "oidc"
	ProviderTypeOAuth2 = "oauth2"
)

// 缺省 scope（按 type 取值，设计事实⑧）。
const (
	defaultScopeOIDC   = "openid email profile"
	defaultScopeOAuth2 = "read:user user:email"
)

// DefaultScopeFor 按 type 返回缺省 scope；未知 type 归 oidc。
func DefaultScopeFor(providerType string) string {
	if providerType == ProviderTypeOAuth2 {
		return defaultScopeOAuth2
	}
	return defaultScopeOIDC
}

// IsValidProviderType 报告 type 是否为合法枚举值。
func IsValidProviderType(providerType string) bool {
	return providerType == ProviderTypeOIDC || providerType == ProviderTypeOAuth2
}

// ErrDuplicateProvider 重名（400，设计事实⑧）。
func ErrDuplicateProvider() error { return rbac.ErrBadRequest("Provider name already exists") }

// ValidateProviderCreate 校验创建请求体。
//
// name/issuer/clientId/clientSecret 必填（openapi required）；name 去空白后
// 非空；type 非空时须为合法枚举。违例统一 400。
func ValidateProviderCreate(d *OidcProviderUpsertDto) error {
	if strings.TrimSpace(d.Name) == "" {
		return rbac.ErrBadRequest("Provider name is required")
	}
	if strings.TrimSpace(d.Issuer) == "" {
		return rbac.ErrBadRequest("Issuer is required")
	}
	if strings.TrimSpace(d.ClientId) == "" {
		return rbac.ErrBadRequest("Client id is required")
	}
	if d.ClientSecret == "" {
		return rbac.ErrBadRequest("Client secret is required")
	}
	if d.Type != nil && !IsValidProviderType(string(*d.Type)) {
		return rbac.ErrBadRequest("Invalid provider type")
	}
	return nil
}

// ValidateProviderUpdate 校验部分更新请求体。
//
// name/issuer/clientId/clientSecret 在 openapi 中为 required（PATCH 亦复用
// 同一 schema），故形状校验与创建一致；另拒绝空串。
func ValidateProviderUpdate(d *OidcProviderUpsertDto) error {
	return ValidateProviderCreate(d)
}
