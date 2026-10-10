// Package settings 本文件：general.* 键目录与嵌套 DTO 组装
// （设计事实④，M3 T07）。
//
// 8 键：watermarkEnabled/defaultLanguage/jwtExpiryDays/auditRetentionDays/
// siteFrontendUrl/siteBackendUrl/webauthnEnabled/webauthnRpName。
// 响应为 camelCase 嵌套 DTO（site{frontendUrl,backendUrl} +
// webauthn{enabled,rpName}）；无 siteFrontendUrl 时 effectiveFrontendUrl
// 回退 http://localhost:3000。
package settings

import (
	"context"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
)

// general.* 键目录（共享知识 18）。
const (
	KeyGeneralWatermarkEnabled  = "general.watermarkEnabled"
	KeyGeneralDefaultLanguage   = "general.defaultLanguage"
	KeyGeneralJWTExpiryDays     = "general.jwtExpiryDays"
	KeyGeneralAuditRetentionDay = "general.auditRetentionDays"
	KeyGeneralSiteFrontendURL   = "general.siteFrontendUrl"
	KeyGeneralSiteBackendURL    = "general.siteBackendUrl"
	KeyGeneralWebauthnEnabled   = "general.webauthnEnabled"
	KeyGeneralWebauthnRpName    = "general.webauthnRpName"
)

// generalCategory system_settings.category 归段。
const generalCategory = "general"

// general 缺省值（与 M1 env 缺省对齐，作为库值缺失时的 fallback）。
const (
	defaultWatermarkEnabled   = false
	defaultLanguage           = "zh-CN"
	defaultJWTExpiryDays      = 30
	defaultAuditRetentionDays = 90
	defaultWebauthnEnabled    = false
	defaultWebauthnRpName     = "RustDesk Panel"
	defaultSiteFrontendURL    = "http://localhost:3000"
	defaultSiteBackendURL     = "http://localhost:8080"
)

// GeneralService general.* 设置读写。
type GeneralService struct {
	store *Store
}

// NewGeneralService 构建服务。
func NewGeneralService(store *Store) *GeneralService {
	return &GeneralService{store: store}
}

// Get 组装嵌套 DTO：库值缺失逐键回退缺省。
func (s *GeneralService) Get(ctx context.Context) (dto.GeneralSettingsView, error) {
	watermark, err := s.store.GetBool(ctx, KeyGeneralWatermarkEnabled, defaultWatermarkEnabled)
	if err != nil {
		return dto.GeneralSettingsView{}, err
	}
	language, err := s.store.GetString(ctx, KeyGeneralDefaultLanguage, defaultLanguage)
	if err != nil {
		return dto.GeneralSettingsView{}, err
	}
	jwtDays, err := s.store.GetInt(ctx, KeyGeneralJWTExpiryDays, defaultJWTExpiryDays)
	if err != nil {
		return dto.GeneralSettingsView{}, err
	}
	retention, err := s.store.GetInt(ctx, KeyGeneralAuditRetentionDay, defaultAuditRetentionDays)
	if err != nil {
		return dto.GeneralSettingsView{}, err
	}
	frontURL, err := s.store.GetString(ctx, KeyGeneralSiteFrontendURL, defaultSiteFrontendURL)
	if err != nil {
		return dto.GeneralSettingsView{}, err
	}
	backURL, err := s.store.GetString(ctx, KeyGeneralSiteBackendURL, defaultSiteBackendURL)
	if err != nil {
		return dto.GeneralSettingsView{}, err
	}
	webauthnEnabled, err := s.store.GetBool(ctx, KeyGeneralWebauthnEnabled, defaultWebauthnEnabled)
	if err != nil {
		return dto.GeneralSettingsView{}, err
	}
	rpName, err := s.store.GetString(ctx, KeyGeneralWebauthnRpName, defaultWebauthnRpName)
	if err != nil {
		return dto.GeneralSettingsView{}, err
	}
	out := dto.GeneralSettingsView{
		WatermarkEnabled:   watermark,
		DefaultLanguage:    language,
		JwtExpiryDays:      jwtDays,
		AuditRetentionDays: retention,
	}
	// effectiveFrontendUrl 回退语义：库值为空串时用 localhost:3000。
	if frontURL == "" {
		frontURL = defaultSiteFrontendURL
	}
	out.Site.FrontendUrl = frontURL
	out.Site.BackendUrl = backURL
	out.Webauthn.Enabled = webauthnEnabled
	out.Webauthn.RpName = rpName
	return out, nil
}

// Update 逐字段写入（仅写入请求中显式提供的可选字段），返回更新后视图。
func (s *GeneralService) Update(ctx context.Context, req *dto.UpdateGeneralSettingsDto) (dto.GeneralSettingsView, error) {
	if err := s.store.SetBool(ctx, KeyGeneralWatermarkEnabled, req.WatermarkEnabled, generalCategory); err != nil {
		return dto.GeneralSettingsView{}, err
	}
	if req.DefaultLanguage != nil {
		if err := s.store.Set(ctx, KeyGeneralDefaultLanguage, *req.DefaultLanguage, generalCategory); err != nil {
			return dto.GeneralSettingsView{}, err
		}
	}
	if req.JwtExpiryDays != nil {
		if err := s.store.SetInt(ctx, KeyGeneralJWTExpiryDays, *req.JwtExpiryDays, generalCategory); err != nil {
			return dto.GeneralSettingsView{}, err
		}
	}
	if req.AuditRetentionDays != nil {
		if err := s.store.SetInt(ctx, KeyGeneralAuditRetentionDay, *req.AuditRetentionDays, generalCategory); err != nil {
			return dto.GeneralSettingsView{}, err
		}
	}
	if req.SiteFrontendUrl != nil {
		if err := s.store.Set(ctx, KeyGeneralSiteFrontendURL, *req.SiteFrontendUrl, generalCategory); err != nil {
			return dto.GeneralSettingsView{}, err
		}
	}
	if req.SiteBackendUrl != nil {
		if err := s.store.Set(ctx, KeyGeneralSiteBackendURL, *req.SiteBackendUrl, generalCategory); err != nil {
			return dto.GeneralSettingsView{}, err
		}
	}
	if req.WebauthnEnabled != nil {
		if err := s.store.SetBool(ctx, KeyGeneralWebauthnEnabled, *req.WebauthnEnabled, generalCategory); err != nil {
			return dto.GeneralSettingsView{}, err
		}
	}
	if req.WebauthnRpName != nil {
		if err := s.store.Set(ctx, KeyGeneralWebauthnRpName, *req.WebauthnRpName, generalCategory); err != nil {
			return dto.GeneralSettingsView{}, err
		}
	}
	return s.Get(ctx)
}

// JWTExpiryDays 类型化读取（供 auth 域 settings 驱动切换，env fallback 由
// 调用方在库值缺失时兜底）。
func (s *GeneralService) JWTExpiryDays(ctx context.Context, fallback int) (int, error) {
	return s.store.GetInt(ctx, KeyGeneralJWTExpiryDays, fallback)
}

// WebauthnConfig 类型化读取 WebAuthn RP 配置（enabled + rpName），
// 库值缺失逐键回退 fallback（M1 批复 #7：env 降级为 fallback）。
func (s *GeneralService) WebauthnConfig(ctx context.Context, fallbackEnabled bool, fallbackRpName string) (bool, string, error) {
	enabled, err := s.store.GetBool(ctx, KeyGeneralWebauthnEnabled, fallbackEnabled)
	if err != nil {
		return fallbackEnabled, fallbackRpName, err
	}
	rpName, err := s.store.GetString(ctx, KeyGeneralWebauthnRpName, fallbackRpName)
	if err != nil {
		return fallbackEnabled, fallbackRpName, err
	}
	return enabled, rpName, nil
}
