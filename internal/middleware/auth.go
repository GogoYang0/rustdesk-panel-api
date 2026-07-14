package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
)

// Identity 鉴权通过后的请求身份（由 TokenService.Validate 产出，注入 context）。
type Identity struct {
	UserGuid string
	Username string
	Email    string
	IsAdmin  bool
	DeviceId string
	Jti      string
}

// TokenValidator 校验原始 token（签名 + exp + 撤销表）并返回身份。
// M1 由 service/auth.TokenService 经适配器实现。
type TokenValidator interface {
	Validate(ctx context.Context, rawToken string) (*Identity, error)
}

// ValidatorFunc 将函数适配为 TokenValidator。
type ValidatorFunc func(ctx context.Context, rawToken string) (*Identity, error)

// Validate 实现 TokenValidator。
func (f ValidatorFunc) Validate(ctx context.Context, rawToken string) (*Identity, error) {
	return f(ctx, rawToken)
}

// ErrTokenInvalid 表示 token 缺失/无效/已撤销（对外文案统一由中间件产出）。
var ErrTokenInvalid = errors.New("token invalid")

const (
	authorizationHeader = "Authorization"
	accessTokenCookie   = "access_token"
	// tokenRejectedMessage 与参考实现对齐的 401 固定文案。
	tokenRejectedMessage = "Token expired or revoked"
)

// JWTAuth Bearer 优先、回退 cookie access_token 双通道提取；
// 每个受保护请求经 TokenValidator 校验（含 user_tokens 撤销表查询），
// 校验通过后把 Identity 注入 context。失败统一 401。
func JWTAuth(validator TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearerToken(r)
			if raw == "" {
				if c, err := r.Cookie(accessTokenCookie); err == nil {
					raw = strings.TrimSpace(c.Value)
				}
			}
			if raw == "" {
				httpx.ErrUnauthorized(w, tokenRejectedMessage)
				return
			}
			ident, err := validator.Validate(r.Context(), raw)
			if err != nil || ident == nil {
				httpx.ErrUnauthorized(w, tokenRejectedMessage)
				return
			}
			next.ServeHTTP(w, r.WithContext(contextWithIdentity(r.Context(), ident)))
		})
	}
}

// bearerToken 从 Authorization 头提取 Bearer token。
func bearerToken(r *http.Request) string {
	h := strings.TrimSpace(r.Header.Get(authorizationHeader))
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// identityKey 是 context 中存放身份的私有键。
type identityKey struct{}

func contextWithIdentity(ctx context.Context, ident *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, ident)
}

// IdentityFromContext 读取当前请求身份；未鉴权路由返回 nil。
func IdentityFromContext(ctx context.Context) *Identity {
	if v, ok := ctx.Value(identityKey{}).(*Identity); ok {
		return v
	}
	return nil
}
