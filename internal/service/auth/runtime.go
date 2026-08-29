// Package auth 本文件：settings 驱动运行时切换（M1 批复 #7，M3 T07）。
//
// 两级读取语义：库值（system_settings）优先 → 缺失/非法时回退 env 缺省。
// 本文件提供：
//   - RuntimeSettings 窄接口（由 service/settings 的 GeneralService 实现）；
//   - TokenService 的 JWT 过期天数动态解析；
//   - OIDC 提供者数据驱动解析（表内 enabled 记录优先，无则 env fallback）。
package auth

import (
	"context"
	"strings"
	"time"
)

// RuntimeSettings settings 驱动运行时读取口（窄接口，避免 auth 包直接
// 依赖 service/settings 造成循环）。
type RuntimeSettings interface {
	// JWTExpiryDays 返回生效 JWT 有效期（天）：库值优先，缺失回退 fallback。
	JWTExpiryDays(ctx context.Context, fallback int) (int, error)
	// WebauthnConfig 返回生效 WebAuthn 配置（enabled + rpName）。
	WebauthnConfig(ctx context.Context, fallbackEnabled bool, fallbackRpName string) (bool, string, error)
}

// EnvOidcFallback env OIDC 配置（M1 已交付形态）：表中无 enabled 记录时
// 降级启用（M1 批复 #7：env OIDC_* 降级为 fallback）。
type EnvOidcFallback struct {
	// Enabled 报告 env 是否配置了可用的 OIDC（issuer 非空即视为已配置）。
	Enabled bool
	// Name provider 名（env 形态固定 "oidc"）。
	Name string
	// Issuer 提供商 issuer。
	Issuer string
	// ClientID OAuth2 客户端 id。
	ClientID string
	// ClientSecret OAuth2 客户端密钥。
	ClientSecret string
	// Scope 授权 scope（空时由调用方取缺省）。
	Scope string
}

// applyExpiry 用 settings 驱动覆盖 token 有效期（库值合法时）。
//
// 库值 ≤0 视为非法，保留 env 缺省（fail-safe：不因脏库值把 token 置为
// 永不过期或立即过期）。
func (s *TokenService) applyExpiry(ctx context.Context) time.Duration {
	if s.settings == nil {
		return s.expiry
	}
	days, err := s.settings.JWTExpiryDays(ctx, s.defaultExpiryDays)
	if err != nil || days <= 0 {
		return s.expiry
	}
	return time.Duration(days) * 24 * time.Hour
}

// WithRuntimeSettings 注入 settings 驱动读取口（bootstrap 装配；
// nil 时保持 M1 纯 env 行为）。
func (s *TokenService) WithRuntimeSettings(settings RuntimeSettings, defaultExpiryDays int) *TokenService {
	s.settings = settings
	if defaultExpiryDays > 0 {
		s.defaultExpiryDays = defaultExpiryDays
	}
	return s
}

// normalizeScope 空 scope 回退缺省（与 oidcflow 的 scopeOrDefault 同语义）。
func normalizeScope(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return defaultScope
	}
	return scope
}
