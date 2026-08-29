// Package dto 本文件：settings 域请求/视图 DTO 与校验（设计事实④，M3 T07）。
//
// 视图类型直接别名至 oapi-codegen 产物（internal/api），保证响应形状与
// openapi.yaml 零漂移；校验函数集中在此，handler 只做绑定与错误出包络。
package dto

import (
	"regexp"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// 视图别名：与 openapi 组件一一对应。
type (
	// FrontendSettingsView GET /api/settings/frontend 响应（Public 三键）。
	FrontendSettingsView = api.FrontendSettings
	// GeneralSettingsView GET/PUT /api/settings/general 响应（嵌套 DTO）。
	GeneralSettingsView = api.GeneralSettings
	// UpdateGeneralSettingsDto PUT /api/settings/general 请求体。
	UpdateGeneralSettingsDto = api.UpdateGeneralSettings
	// SmtpConfigDto GET/PUT /api/settings/smtp 请求/响应体。
	SmtpConfigDto = api.SmtpConfig
	// LdapConfigDto GET/PUT /api/settings/ldap 请求/响应体。
	LdapConfigDto = api.LdapConfig
	// SettingsTestResultView 连通性测试响应（smtp/ldap/oidc test 共用）。
	SettingsTestResultView = api.SettingsTestResult
)

// MaskedSecret 掩码值（共享知识 18）：密码类键回读恒此字面量，
// PUT 命中该值即跳过更新（空串不等于掩码，是显式清空）。
const MaskedSecret = "******"

// languageTagRe defaultLanguage 校验：`^[a-z]{2}-[A-Z]{2}$`（openapi）。
var languageTagRe = regexp.MustCompile(`^[a-z]{2}-[A-Z]{2}$`)

// ValidateUpdateGeneral 校验 PUT /api/settings/general 请求体。
//
// watermarkEnabled 必填（bool，无零值歧义，由 openapi required 保证）；
// defaultLanguage 非空时须匹配 `^[a-z]{2}-[A-Z]{2}$`；jwtExpiryDays 非空时
// 须 ≥1；auditRetentionDays 非空时须 ≥0。违例统一 400 固定文案。
func ValidateUpdateGeneral(d *UpdateGeneralSettingsDto) error {
	if d.DefaultLanguage != nil && !languageTagRe.MatchString(*d.DefaultLanguage) {
		return rbac.ErrBadRequest("Invalid defaultLanguage")
	}
	if d.JwtExpiryDays != nil && *d.JwtExpiryDays < 1 {
		return rbac.ErrBadRequest("jwtExpiryDays must be at least 1")
	}
	if d.AuditRetentionDays != nil && *d.AuditRetentionDays < 0 {
		return rbac.ErrBadRequest("auditRetentionDays must be at least 0")
	}
	return nil
}

// ValidateLdap 校验 LDAP 配置形状（PUT / test 共用）。
//
// urls 非空时逐项须为 ldap:// 或 ldaps:// 前缀；port 类数值由类型系统保证。
// 违例统一 400 固定文案。
func ValidateLdap(d *LdapConfigDto) error {
	if d.Urls != nil {
		for _, u := range *d.Urls {
			if !hasLdapScheme(u) {
				return rbac.ErrBadRequest("Invalid LDAP url")
			}
		}
	}
	return nil
}

// hasLdapScheme 报告 url 是否以 ldap:// 或 ldaps:// 起始。
func hasLdapScheme(u string) bool {
	return hasPrefixFold(u, "ldap://") || hasPrefixFold(u, "ldaps://")
}

// hasPrefixFold 大小写不敏感前缀判断（避免引入 strings 依赖的额外分支）。
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		p := prefix[i]
		if p >= 'A' && p <= 'Z' {
			p += 'a' - 'A'
		}
		if c != p {
			return false
		}
	}
	return true
}
