package rbac

import (
	"errors"
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	mwx "github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
)

// PolicyKind 路由授权策略类型（设计 §1.3：路由注册期策略声明）。
type PolicyKind uint8

// 策略类型。
const (
	// PolicyPublic 公开端点：跳过 JWTAuth（heartbeat/sysinfo 等）。
	PolicyPublic PolicyKind = iota
	// PolicyAuth 仅 JWT（handler 内按需做状态复核）。
	PolicyAuth
	// PolicyPerm JWT + 权限码决策（查库）。
	PolicyPerm
	// PolicyAdminGuard JWT + AdminGuard 语义（device-groups CRUD 路线文案）。
	PolicyAdminGuard
	// PolicySuperAdmin JWT + super administrator（roles CRUD 路线文案）。
	PolicySuperAdmin
)

// Policy 路由授权策略声明（HandlePolicy 注册参数；编译期不可漏配）。
type Policy struct {
	Kind PolicyKind
	Code string
}

// PublicPolicy 构造公开策略。
func PublicPolicy() Policy { return Policy{Kind: PolicyPublic} }

// AuthPolicy 构造仅认证策略。
func AuthPolicy() Policy { return Policy{Kind: PolicyAuth} }

// PermPolicy 构造权限码策略。
func PermPolicy(code string) Policy { return Policy{Kind: PolicyPerm, Code: code} }

// AdminGuardPolicy 构造 AdminGuard 策略。
func AdminGuardPolicy() Policy { return Policy{Kind: PolicyAdminGuard} }

// SuperAdminPolicy 构造 super administrator 策略。
func SuperAdminPolicy() Policy { return Policy{Kind: PolicySuperAdmin} }

// Middleware RBAC HTTP 中间件族（设计 §1.3）：
// 挂在 JWTAuth 之后，按路由 Policy 选择；403 包络与 denied 审计在此收口。
//
// 双 403 文案区分（共享知识 1）：
//   - RequireSuperAdmin → "Super administrator permission required"（roles 路线）
//   - RequireAdminGuard → "Access denied: administrator privileges required"
//     （device-groups 路线，AdminGuard 语义）
type Middleware struct {
	auth *AuthorizationService
}

// NewMiddleware 构建中间件族。
func NewMiddleware(auth *AuthorizationService) *Middleware {
	return &Middleware{auth: auth}
}

// RequirePermission 返回权限码中间件：401（被禁用户）→ 403
// （Unknown permission / Access denied，均记 denied 审计）→ 放行。
// scope 不经 context 传递，handler 经 AuthorizationService.GetPermissionScope
// 复取（设计 §1.3：避免重复查询语义分裂）。
func (m *Middleware) RequirePermission(code string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident := mwx.IdentityFromContext(r.Context())
			if ident == nil {
				// JWTAuth 未放行（理论不可达）；防御性 401。
				httpx.ErrUnauthorized(w, mwx.TokenRejectedMessage)
				return
			}
			if _, err := m.auth.RequirePermission(r.Context(), ident.UserGuid, code); err != nil {
				WriteStatusError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSuperAdmin 返回超管中间件（roles CRUD 路线）。
func (m *Middleware) RequireSuperAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident := mwx.IdentityFromContext(r.Context())
			if ident == nil {
				httpx.ErrUnauthorized(w, mwx.TokenRejectedMessage)
				return
			}
			if _, err := m.auth.RequireSuperAdmin(r.Context(), ident.UserGuid); err != nil {
				WriteStatusError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdminGuard 返回 AdminGuard 语义中间件（device-groups CRUD 路线）。
func (m *Middleware) RequireAdminGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident := mwx.IdentityFromContext(r.Context())
			if ident == nil {
				httpx.ErrUnauthorized(w, mwx.TokenRejectedMessage)
				return
			}
			if _, err := m.auth.RequireAdminGuard(r.Context(), ident.UserGuid); err != nil {
				WriteStatusError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WriteStatusError 将 rbac 错误映射为响应包络；非 StatusError 统一 500。
func WriteStatusError(w http.ResponseWriter, err error) {
	var se *StatusError
	if errors.As(err, &se) {
		httpx.Fail(w, se.Status, se.Message)
		return
	}
	httpx.ErrInternal(w)
}
