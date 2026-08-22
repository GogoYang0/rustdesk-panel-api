package server

import (
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/static"
)

// 路由授权策略档位（设计 §1.6；与 rbac.PolicyKind 一一对应，
// 以字符串暴露供三方一致性测试与运维内省比对）。
const (
	PolicyPublic     = "public"      // 公开白名单（无 JWT）
	PolicyAuth       = "auth"        // 仅 JWT（handler 内按需状态复核）
	PolicyPerm       = "perm"        // JWT + 权限码决策（查库）
	PolicyAdminGuard = "admin_guard" // JWT + 管理员守卫
	PolicySuperAdmin = "super_admin" // JWT + super administrator
)

// Route 描述一条已注册路由的授权声明。
//
// 注册期由 Handle/HandlePolicy（以及系统、设备协议端点的显式登记）
// 写入 Router.routes，经 Routes() 只读访问；是"路由表 ↔ openapi.yaml ↔
// 设计 §1.6 档位表"三方一致性测试与运维内省的数据源。
type Route struct {
	Method  string // HTTP 方法
	Pattern string // 路径模板（{param} 段），与 openapi paths 一一对应
	Policy  string // 授权策略档位（PolicyPublic 等常量）
	Code    string // PolicyPerm 对应的权限码；其余档位为空串
}

// Router 装配路由表与横切链。
//
// 全局链：RequestID → Recover → AccessLog → CORS（共享知识 9 前四层）；
// 单条路由内层按注册声明附加 RateLimit → JWTAuth → Handler，
// 即整链顺序与设计一致。public=true 的路由不包 JWTAuth
// （等效于公开白名单跳过），白名单数据源即注册声明本身。
type Router struct {
	mux           *http.ServeMux
	limiter       *middleware.RateLimiter
	deviceLimiter *middleware.DeviceRateLimiter
	validator     middleware.TokenValidator
	rbacMW        *rbac.Middleware
	handler       http.Handler
	domain        *Domain
	routes        []Route
}

// RouterDeps 路由装配依赖。
type RouterDeps struct {
	Logger *slog.Logger
	// Validator 覆盖注入的 token 校验器（测试桩）；nil 且 DB 非空时
	// 使用 Domain 内构建的真实 TokenService。
	Validator middleware.TokenValidator
	// RateLimitEnabled 对应 RATE_LIMIT_ENABLED。
	RateLimitEnabled bool
	// DB 非空时装配认证域（T04）；nil 仅注册系统端点（契约冒烟）。
	DB *gorm.DB
	// Config 认证域服务配置（JWT/WebAuthn）。
	Config config.Config
}

// NewRouter 构建路由器：系统端点 + （注入 DB 时）认证域路由。
func NewRouter(deps RouterDeps) *Router {
	rt := &Router{
		mux:           http.NewServeMux(),
		limiter:       middleware.NewRateLimiter(deps.RateLimitEnabled),
		deviceLimiter: middleware.NewDeviceRateLimiter(deps.RateLimitEnabled),
		validator:     deps.Validator,
	}
	rt.registerSystem()
	// 静态资源（M3 扩展点①）不依赖 Domain：embed SPA 与 /files 均为
	// 本地文件服务，DB 未注入（契约冒烟）时同样可用。
	rt.registerStatic(deps.Config.DataDir)
	if deps.DB != nil {
		domain, err := assembleDomain(deps)
		if err != nil {
			// 装配失败属启动期错误（如 WebAuthn 配置缺失），直接 panic。
			panic("server: assemble auth domain failed: " + err.Error())
		}
		rt.domain = domain
		if rt.validator == nil {
			rt.validator = domain.Tokens
		}
		rt.rbacMW = domain.RbacMW
		rt.registerDomainRoutes(domain)
	}
	rt.handler = middleware.Chain(rt.mux,
		middleware.RequestID,
		middleware.Recover(deps.Logger),
		middleware.AccessLog(deps.Logger),
		middleware.CORS,
	)
	return rt
}

// Handler 返回装配完成的根 handler。
func (rt *Router) Handler() http.Handler { return rt.handler }

// Domain 返回装配好的认证域容器（main 启动 cron 清理用；未装配时 nil）。
func (rt *Router) Domain() *Domain { return rt.domain }

// record 登记一条路由授权声明（注册期写入，与 mux 注册同处调用）。
func (rt *Router) record(r Route) { rt.routes = append(rt.routes, r) }

// Routes 返回已注册路由授权声明（注册顺序）的拷贝，供
// "路由表 ↔ openapi ↔ 设计档位表"三方一致性测试与运维内省使用。
// 返回切片为拷贝，调用方修改不影响路由器内部状态。
func (rt *Router) Routes() []Route {
	out := make([]Route, len(rt.routes))
	copy(out, rt.routes)
	return out
}

// Handle 注册一条路由。
//
//	method   HTTP 方法（net/http 方法路由）
//	pattern  路径模板（{param} 段），与 openapi paths 一一对应
//	public   true 时跳过 JWTAuth（公开白名单）
//	perMinute>0 时启用 per-IP per-route 限流（次/分钟）
func (rt *Router) Handle(method, pattern string, public bool, perMinute int, h http.Handler) {
	policy := PolicyAuth
	if public {
		policy = PolicyPublic
	}
	rt.record(Route{Method: method, Pattern: pattern, Policy: policy})
	if !public {
		h = middleware.JWTAuth(rt.validator)(h)
	}
	if perMinute > 0 {
		// 限流在 JWTAuth 之前（共享知识 9：... CORS → RateLimit → JWTAuth）。
		h = rt.limiter.Wrap(pattern, perMinute, h)
	}
	rt.mux.Handle(method+" "+pattern, h)
}

// hf 将方法转 handler（注册侧简化书写）。
func hf(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(h)
}

// HandlePolicy 注册一条带授权策略的路由（M2，设计 §1.3）。
//
//	method   HTTP 方法
//	pattern  路径模板（{param} 段），与 openapi paths 一一对应
//	policy   授权策略（Public 跳过 JWT；Auth 仅 JWT；
//	         Perm/AdminGuard/SuperAdmin 在 JWT 后执行查库决策）
//	perMinute>0 时启用 per-IP per-route 限流（次/分钟）
//
// 包装顺序（执行序）：限流 → JWTAuth → 策略决策 → handler——策略
// 中间件必须在 JWTAuth 内层，IdentityFromContext 才能读到已注入身份。
func (rt *Router) HandlePolicy(method, pattern string, policy rbac.Policy, perMinute int, h http.Handler) {
	// 注册声明（三方一致性数据源）：默认仅认证档，按 Kind 细化。
	declared := Route{Method: method, Pattern: pattern, Policy: PolicyAuth}
	if perMinute > 0 {
		h = rt.limiter.Wrap(pattern, perMinute, h)
	}
	if rt.rbacMW == nil {
		// 未装配 Domain 即注册策略路由属编程错误，启动期快速失败。
		panic("server: HandlePolicy requires rbac middleware (assemble Domain first)")
	}
	switch policy.Kind {
	case rbac.PolicyPublic:
		declared.Policy = PolicyPublic
	case rbac.PolicyPerm:
		declared.Policy = PolicyPerm
		declared.Code = policy.Code
		h = rt.rbacMW.RequirePermission(policy.Code)(h)
	case rbac.PolicyAdminGuard:
		declared.Policy = PolicyAdminGuard
		h = rt.rbacMW.RequireAdminGuard()(h)
	case rbac.PolicySuperAdmin:
		declared.Policy = PolicySuperAdmin
		h = rt.rbacMW.RequireSuperAdmin()(h)
	}
	if policy.Kind != rbac.PolicyPublic {
		h = middleware.JWTAuth(rt.validator)(h)
	}
	rt.record(declared)
	rt.mux.Handle(method+" "+pattern, h)
}

// DeviceRateLimit 包装设备维度限流（heartbeat/sysinfo 专用，tracker=
// body.id → body.uuid → IP），供注册处以显式组合方式前置到公开端点。
func (rt *Router) DeviceRateLimit(pattern string, perMinute int, h http.Handler) http.Handler {
	return rt.deviceLimiter.Wrap(pattern, perMinute, h)
}

// registerSystem 注册系统端点（M0 契约保持不变）。
func (rt *Router) registerSystem() {
	rt.record(Route{Method: http.MethodGet, Pattern: "/api/healthz", Policy: PolicyPublic})
	rt.mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, _ *http.Request) {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"status":  "ok",
			"version": Version,
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})
}

// registerStatic 注册静态资源路由（M3 扩展点①，设计事实⑨）：
//
//	GET /               —— SPA 兜底（embed dist；排除 /api /files /avatars）
//	GET /files/{path}   —— nexus 产物（DATA_DIR/nexus + safeJoin）
//
// 公开档显式登记（heartbeat/sysinfo 同款先例）；mux 模式用 net/http
// 尾部通配 {path...}（多段匹配），契约侧 Route.Pattern 保持与
// openapi paths 一致的 {path} 单段形态——三方一致性以声明键为准。
func (rt *Router) registerStatic(dataDir string) {
	rt.record(Route{Method: http.MethodGet, Pattern: "/", Policy: PolicyPublic})
	rt.mux.Handle(http.MethodGet+" /", static.SPAHandler())
	rt.record(Route{Method: http.MethodGet, Pattern: "/files/{path}", Policy: PolicyPublic})
	rt.mux.Handle(http.MethodGet+" /files/{path...}", static.FilesHandler(filepath.Join(dataDir, "nexus")))
}

// notImplemented M3-T01 契约骨架占位 handler：横切链（限流/JWT/RBAC
// 决策）按注册档位完整生效，handler 体为 501；T03~T07 逐域替换为
// 真实实现（占位路由存在的意义是让"契约↔路由表↔设计档位表"三方
// 一致性在本里程碑内全程可校验）。
func notImplemented(route string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpx.Fail(w, http.StatusNotImplemented, "Not implemented in M3 T01: "+route)
	})
}

// registerDomainRoutes 注册认证域路由（§2.1 #1~#19）。
// 公开白名单：login、login-options、passkey/auth/*、oidc/*（共享知识 9）；
// 限流参数表：login 5、login-options 20、passkey/auth 10、oidc/auth 5、
// auth-query 120（avatars 于 T05 接入，60）。
func (rt *Router) registerDomainRoutes(d *Domain) {
	// ---- 公开端点 ----
	rt.Handle(http.MethodPost, "/api/login", true, 5, hf(d.Auth.Login))
	rt.Handle(http.MethodGet, "/api/login-options", true, 20, hf(d.Oidc.LoginOptions))
	rt.Handle(http.MethodPost, "/api/passkey/auth/begin", true, 10, hf(d.Auth.PasskeyAuthBegin))
	rt.Handle(http.MethodPost, "/api/passkey/auth/verify", true, 10, hf(d.Auth.PasskeyAuthVerify))
	rt.Handle(http.MethodPost, "/api/oidc/auth", true, 5, hf(d.Oidc.RequestAuth))
	rt.Handle(http.MethodGet, "/api/oidc/auth-query", true, 120, hf(d.Oidc.QueryAuth))
	rt.Handle(http.MethodGet, "/api/oidc/callback", true, 0, hf(d.Oidc.Callback))

	// ---- 受保护端点（JWT）----
	rt.Handle(http.MethodPost, "/api/logout", false, 0, hf(d.Auth.Logout))
	rt.Handle(http.MethodPost, "/api/currentUser", false, 0, hf(d.Auth.CurrentUser))
	rt.Handle(http.MethodPost, "/api/2fa/setup", false, 0, hf(d.Auth.SetupTfa))
	rt.Handle(http.MethodPost, "/api/2fa/verify", false, 0, hf(d.Auth.VerifyTfa))
	rt.Handle(http.MethodDelete, "/api/2fa", false, 0, hf(d.Auth.DisableTfa))
	rt.Handle(http.MethodPost, "/api/passkey/register/begin", false, 0, hf(d.Auth.PasskeyRegisterBegin))
	rt.Handle(http.MethodPost, "/api/passkey/register/verify", false, 0, hf(d.Auth.PasskeyRegisterVerify))
	rt.Handle(http.MethodGet, "/api/passkey/list", false, 0, hf(d.Auth.PasskeyList))
	rt.Handle(http.MethodDelete, "/api/passkey/{guid}", false, 0, hf(d.Auth.PasskeyDelete))
	rt.Handle(http.MethodPost, "/api/passkey/tfa", false, 0, hf(d.Auth.PasskeyTfaToggle))
	rt.Handle(http.MethodGet, "/api/sessions", false, 0, hf(d.Auth.SessionsList))
	rt.Handle(http.MethodDelete, "/api/sessions/{jti}", false, 0, hf(d.Auth.SessionRevoke))

	// ---- 用户自身端点（JWT；#24 头像静态公开限流 60）----
	rt.Handle(http.MethodPatch, "/api/users/me", false, 0, hf(d.User.UpdateMe))
	rt.Handle(http.MethodPatch, "/api/users/me/password", false, 5, hf(d.User.ChangePassword))
	rt.Handle(http.MethodPost, "/api/users/me/avatar", false, 10, hf(d.User.UploadAvatar))
	rt.Handle(http.MethodDelete, "/api/users/me/avatar", false, 10, hf(d.User.DeleteAvatar))
	rt.Handle(http.MethodGet, "/api/avatars/{filename}", true, 60, hf(d.User.GetAvatar))

	// ---- 设备端协议（公开，§1.4）：不引入设备 token；设备维度限流
	// （tracker=id→uuid→IP 回退）以显式组合方式前置，不叠加 per-IP
	// 限流。直挂 mux：绕过 Handle 的 per-IP 限流与 JWT 包装；
	// 授权声明（公开档）显式登记，维持路由表完整性。
	rt.record(Route{Method: http.MethodPost, Pattern: "/api/heartbeat", Policy: PolicyPublic})
	rt.mux.Handle(http.MethodPost+" /api/heartbeat",
		rt.DeviceRateLimit("/api/heartbeat", 10, hf(d.Heartbeat.Heartbeat)))
	rt.record(Route{Method: http.MethodPost, Pattern: "/api/sysinfo", Policy: PolicyPublic})
	rt.mux.Handle(http.MethodPost+" /api/sysinfo",
		rt.DeviceRateLimit("/api/sysinfo", 5, hf(d.Heartbeat.Sysinfo)))

	// ---- 设备域（§1.6 device 档）：/peers 无权限码（Auth+状态复核），
	// /devices×5 走 Perm 策略（scope 决策查库）；资源级复核在服务层。
	rt.HandlePolicy(http.MethodGet, "/api/peers", rbac.AuthPolicy(), 0, hf(d.Devices.ListPeers))
	rt.HandlePolicy(http.MethodGet, "/api/devices", rbac.PermPolicy(rbac.CodeDevicesView), 0, hf(d.Devices.ListDevices))
	rt.HandlePolicy(http.MethodPatch, "/api/devices/status", rbac.PermPolicy(rbac.CodeDevicesStatus), 0, hf(d.Devices.UpdateDeviceStatus))
	rt.HandlePolicy(http.MethodPatch, "/api/devices/{guid}", rbac.PermPolicy(rbac.CodeDevicesEdit), 0, hf(d.Devices.UpdateDevice))
	rt.HandlePolicy(http.MethodDelete, "/api/devices/{guid}", rbac.PermPolicy(rbac.CodeDevicesDelete), 0, hf(d.Devices.DeleteDevice))
	rt.HandlePolicy(http.MethodPost, "/api/devices/{uuid}/disconnect", rbac.PermPolicy(rbac.CodeDevicesDisconnect), 0, hf(d.Devices.Disconnect))

	// ---- 设备组域（§1.6 device-group 档）：accessible 无权限码（Auth+
	// 状态复核）；列表/CRUD/加减设备 AdminGuard；strategy-targets 走
	// Perm(strategies.assign)。注意路径差异：accessible 在 /api/device-group
	// （单数），其余在 /api/device-groups（复数）——参考契约原样。
	rt.HandlePolicy(http.MethodGet, "/api/device-group/accessible", rbac.AuthPolicy(), 0, hf(d.DeviceGroups.Accessible))
	rt.HandlePolicy(http.MethodGet, "/api/device-groups", rbac.AdminGuardPolicy(), 0, hf(d.DeviceGroups.List))
	rt.HandlePolicy(http.MethodPost, "/api/device-groups", rbac.AdminGuardPolicy(), 0, hf(d.DeviceGroups.Create))
	rt.HandlePolicy(http.MethodGet, "/api/device-groups/strategy-targets", rbac.PermPolicy(rbac.CodeStrategiesAssign), 0, hf(d.DeviceGroups.StrategyTargets))
	rt.HandlePolicy(http.MethodPatch, "/api/device-groups/{guid}", rbac.AdminGuardPolicy(), 0, hf(d.DeviceGroups.Update))
	rt.HandlePolicy(http.MethodDelete, "/api/device-groups/{guid}", rbac.AdminGuardPolicy(), 0, hf(d.DeviceGroups.Delete))
	rt.HandlePolicy(http.MethodPost, "/api/device-groups/{guid}", rbac.AdminGuardPolicy(), 0, hf(d.DeviceGroups.AddDevices))
	rt.HandlePolicy(http.MethodDelete, "/api/device-groups/{guid}/devices", rbac.AdminGuardPolicy(), 0, hf(d.DeviceGroups.RemoveDevices))

	// ---- 策略域（§1.6 strategy 档）：CRUD 按 view/create/edit/delete
	// 分码；candidates/target-candidates/assignments/assign/unassign 均
	// Perm(strategies.assign)（scope 决策查库，资源复核在服务层）。
	rt.HandlePolicy(http.MethodGet, "/api/strategies", rbac.PermPolicy(rbac.CodeStrategiesView), 0, hf(d.Strategy.List))
	rt.HandlePolicy(http.MethodPost, "/api/strategies", rbac.PermPolicy(rbac.CodeStrategiesCreate), 0, hf(d.Strategy.Create))
	rt.HandlePolicy(http.MethodGet, "/api/strategies/candidates", rbac.PermPolicy(rbac.CodeStrategiesAssign), 0, hf(d.Strategy.Candidates))
	rt.HandlePolicy(http.MethodGet, "/api/strategies/target-candidates", rbac.PermPolicy(rbac.CodeStrategiesAssign), 0, hf(d.Strategy.TargetCandidates))
	rt.HandlePolicy(http.MethodGet, "/api/strategies/{guid}", rbac.PermPolicy(rbac.CodeStrategiesView), 0, hf(d.Strategy.Get))
	rt.HandlePolicy(http.MethodPatch, "/api/strategies/{guid}", rbac.PermPolicy(rbac.CodeStrategiesEdit), 0, hf(d.Strategy.Update))
	rt.HandlePolicy(http.MethodDelete, "/api/strategies/{guid}", rbac.PermPolicy(rbac.CodeStrategiesDelete), 0, hf(d.Strategy.Delete))
	rt.HandlePolicy(http.MethodGet, "/api/strategies/{guid}/assignments", rbac.PermPolicy(rbac.CodeStrategiesAssign), 0, hf(d.Strategy.Assignments))
	rt.HandlePolicy(http.MethodPost, "/api/strategies/{guid}/assign", rbac.PermPolicy(rbac.CodeStrategiesAssign), 0, hf(d.Strategy.Assign))
	rt.HandlePolicy(http.MethodPost, "/api/strategies/{guid}/unassign", rbac.PermPolicy(rbac.CodeStrategiesAssign), 0, hf(d.Strategy.Unassign))

	// ---- RBAC 域（§1.6 rbac 档）：目录只读/roles 读写走 roles.view；
	// roles 写路径 + protection-impact 走 super administrator（roles
	// 路线文案 "Super administrator permission required"）；用户角色
	// 指派三端点走 Perm(roles.assign)，防护链在服务层。
	rt.HandlePolicy(http.MethodGet, "/api/permissions", rbac.PermPolicy(rbac.CodeRolesView), 0, hf(d.RbacAPI.ListPermissions))
	rt.HandlePolicy(http.MethodGet, "/api/permissions/me", rbac.AuthPolicy(), 0, hf(d.RbacAPI.MyPermissions))
	rt.HandlePolicy(http.MethodGet, "/api/roles", rbac.PermPolicy(rbac.CodeRolesView), 0, hf(d.RbacAPI.ListRoles))
	rt.HandlePolicy(http.MethodPost, "/api/roles", rbac.SuperAdminPolicy(), 0, hf(d.RbacAPI.CreateRole))
	rt.HandlePolicy(http.MethodGet, "/api/roles/{guid}", rbac.PermPolicy(rbac.CodeRolesView), 0, hf(d.RbacAPI.GetRole))
	rt.HandlePolicy(http.MethodPatch, "/api/roles/{guid}", rbac.SuperAdminPolicy(), 0, hf(d.RbacAPI.UpdateRole))
	rt.HandlePolicy(http.MethodDelete, "/api/roles/{guid}", rbac.SuperAdminPolicy(), 0, hf(d.RbacAPI.DeleteRole))
	rt.HandlePolicy(http.MethodGet, "/api/roles/{guid}/protection-impact", rbac.SuperAdminPolicy(), 0, hf(d.RbacAPI.RoleProtectionImpact))
	rt.HandlePolicy(http.MethodGet, "/api/users/{guid}/roles", rbac.PermPolicy(rbac.CodeRolesAssign), 0, hf(d.RbacAPI.GetUserRoles))
	rt.HandlePolicy(http.MethodGet, "/api/users/{guid}/roles/eligibility", rbac.PermPolicy(rbac.CodeRolesAssign), 0, hf(d.RbacAPI.UserRoleEligibility))
	rt.HandlePolicy(http.MethodPut, "/api/users/{guid}/roles", rbac.PermPolicy(rbac.CodeRolesAssign), 0, hf(d.RbacAPI.ReplaceUserRoles))

	// ---- 用户组域（§1.6 user-group 档）：CRUD 按
	// view/create/edit/delete 分码；成员查询复用 view 码；成员移动走
	// membership 码（保护账号复核在服务层 AssertUsersMutation）。
	rt.HandlePolicy(http.MethodGet, "/api/user-groups", rbac.PermPolicy(rbac.CodeUserGroupsView), 0, hf(d.UserGroups.List))
	rt.HandlePolicy(http.MethodPost, "/api/user-groups", rbac.PermPolicy(rbac.CodeUserGroupsCreate), 0, hf(d.UserGroups.Create))
	rt.HandlePolicy(http.MethodPut, "/api/user-groups/{guid}", rbac.PermPolicy(rbac.CodeUserGroupsEdit), 0, hf(d.UserGroups.Update))
	rt.HandlePolicy(http.MethodDelete, "/api/user-groups/{guid}", rbac.PermPolicy(rbac.CodeUserGroupsDelete), 0, hf(d.UserGroups.Delete))
	rt.HandlePolicy(http.MethodGet, "/api/user-groups/{guid}/users", rbac.PermPolicy(rbac.CodeUserGroupsView), 0, hf(d.UserGroups.Members))
	rt.HandlePolicy(http.MethodPost, "/api/user-groups/{guid}/users", rbac.PermPolicy(rbac.CodeUserGroupsMembership), 0, hf(d.UserGroups.MoveUsers))

	// ---- 用户域（M3 T03 实现；M1 已有 5 条 me/avatar 端点不重复
	// 注册。/users/invite 走 users.create + 条件 membership；invite/
	// verify/accept 与批量族按设计 §1.3 档位表）----
	rt.HandlePolicy(http.MethodGet, "/api/users", rbac.PermPolicy(rbac.CodeUsersView), 0, hf(d.User.ListUsers))
	rt.HandlePolicy(http.MethodPost, "/api/users", rbac.PermPolicy(rbac.CodeUsersCreate), 0, hf(d.User.CreateUser))
	rt.HandlePolicy(http.MethodPost, "/api/users/invite", rbac.PermPolicy(rbac.CodeUsersCreate), 0, hf(d.User.InviteUser))
	rt.HandlePolicy(http.MethodPost, "/api/invitations/verify", rbac.PublicPolicy(), 0, hf(d.User.VerifyInvitation))
	rt.HandlePolicy(http.MethodPost, "/api/invitations/accept", rbac.PublicPolicy(), 0, hf(d.User.AcceptInvitation))
	rt.HandlePolicy(http.MethodPatch, "/api/users/batch/status", rbac.PermPolicy(rbac.CodeUsersStatus), 0, hf(d.User.BatchStatus))
	rt.HandlePolicy(http.MethodPatch, "/api/users/batch/security", rbac.PermPolicy(rbac.CodeUsersSecurity), 0, hf(d.User.BatchSecurity))
	rt.HandlePolicy(http.MethodDelete, "/api/users/batch/sessions", rbac.PermPolicy(rbac.CodeUsersForceLogout), 0, hf(d.User.BatchSessions))
	rt.HandlePolicy(http.MethodGet, "/api/users/{guid}", rbac.PermPolicy(rbac.CodeUsersView), 0, hf(d.User.GetUser))
	rt.HandlePolicy(http.MethodPatch, "/api/users/{guid}", rbac.AuthPolicy(), 0, hf(d.User.UpdateUser))
	rt.HandlePolicy(http.MethodDelete, "/api/users/{guid}", rbac.PermPolicy(rbac.CodeUsersDelete), 0, hf(d.User.DeleteUser))
	rt.HandlePolicy(http.MethodPatch, "/api/users/{guid}/security", rbac.PermPolicy(rbac.CodeUsersSecurity), 0, hf(d.User.UpdateUserSecurity))
	rt.HandlePolicy(http.MethodDelete, "/api/users/{guid}/sessions", rbac.PermPolicy(rbac.CodeUsersForceLogout), 0, hf(d.User.ForceLogout))
	rt.HandlePolicy(http.MethodGet, "/api/admin/users", rbac.PermPolicy(rbac.CodeUsersView), 0, hf(d.User.ListAdminUsers))

	// ---- 审计域（M3 T04 实现；★ 上报单数路径 Public + per-IP
	// 50/min——设备侧直连无 JWT；查询复数按 audit.view /
	// devices.disconnect 分档，PATCH note 走 super administrator）----
	rt.HandlePolicy(http.MethodPost, "/api/audit/conn", rbac.PublicPolicy(), 50, hf(d.Audit.ReportConn))
	rt.HandlePolicy(http.MethodPost, "/api/audit/file", rbac.PublicPolicy(), 50, hf(d.Audit.ReportFile))
	rt.HandlePolicy(http.MethodPost, "/api/audit/alarm", rbac.PublicPolicy(), 50, hf(d.Audit.ReportAlarm))
	rt.HandlePolicy(http.MethodGet, "/api/audits/conn/active", rbac.PermPolicy(rbac.CodeDevicesDisconnect), 0, hf(d.Audit.ListActiveConn))
	rt.HandlePolicy(http.MethodGet, "/api/audits/conn", rbac.PermPolicy(rbac.CodeAuditView), 0, hf(d.Audit.ListConn))
	rt.HandlePolicy(http.MethodPatch, "/api/audits/conn/{id}", rbac.SuperAdminPolicy(), 0, hf(d.Audit.UpdateConnNote))
	rt.HandlePolicy(http.MethodGet, "/api/audits/file", rbac.PermPolicy(rbac.CodeAuditView), 0, hf(d.Audit.ListFile))
	rt.HandlePolicy(http.MethodGet, "/api/audits/alarm", rbac.PermPolicy(rbac.CodeAuditView), 0, hf(d.Audit.ListAlarm))
	rt.HandlePolicy(http.MethodGet, "/api/audits/console", rbac.PermPolicy(rbac.CodeAuditView), 0, hf(d.Audit.ListConsole))

	// ---- 仪表盘域（M3 T04 实现；双端点 super administrator）----
	rt.HandlePolicy(http.MethodGet, "/api/dashboard", rbac.SuperAdminPolicy(), 0, hf(d.Dashboard.Overview))
	rt.HandlePolicy(http.MethodGet, "/api/dashboard/trends", rbac.SuperAdminPolicy(), 0, hf(d.Dashboard.Trends))

	// ---- M3 契约骨架（T01）：剩余 69 条 501 占位（notImplemented），
	// T05~T07 逐域替换（user 14 条 T03、审计 9 + 仪表盘 2 条 T04 已
	// 接真实实现；M3 全量 96 operation）。
	rt.registerM3Stubs()
}

// registerM3Stubs 注册 M3 剩余骨架端点（69 = 32 ab + 10 servers +
// 9 nexus + 9 settings + 8 oidc + 1 update；user 14 条 T03 已接真实
// 实现、审计 9 + 仪表盘 2 条 T04 已接真实实现，另有 2 条静态路由由
// registerStatic 登记——M3 全量 96）。档位与限流参数严格对齐设计
// §1.3 策略总表——三方一致性测试以本注册声明为路由侧数据源。
func (rt *Router) registerM3Stubs() {
	stub := notImplemented

	// ---- 通讯录域（24 端点仅 Auth；8 端点按 share/edit/view 分码）----
	rt.HandlePolicy(http.MethodGet, "/api/ab", rbac.AuthPolicy(), 0, stub("GET /api/ab"))
	rt.HandlePolicy(http.MethodPost, "/api/ab", rbac.AuthPolicy(), 0, stub("POST /api/ab"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/settings", rbac.AuthPolicy(), 0, stub("POST /api/ab/settings"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/personal", rbac.AuthPolicy(), 0, stub("GET /api/ab/personal"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/personal", rbac.AuthPolicy(), 0, stub("POST /api/ab/personal"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/custom/profiles", rbac.AuthPolicy(), 0, stub("GET /api/ab/custom/profiles"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/custom/add", rbac.AuthPolicy(), 0, stub("POST /api/ab/custom/add"))
	rt.HandlePolicy(http.MethodPut, "/api/ab/custom/update/profile", rbac.AuthPolicy(), 0, stub("PUT /api/ab/custom/update/profile"))
	rt.HandlePolicy(http.MethodDelete, "/api/ab/custom", rbac.AuthPolicy(), 0, stub("DELETE /api/ab/custom"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/shared/profiles", rbac.AuthPolicy(), 0, stub("GET /api/ab/shared/profiles"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/shared/profiles", rbac.AuthPolicy(), 0, stub("POST /api/ab/shared/profiles"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/shared/list", rbac.AuthPolicy(), 0, stub("GET /api/ab/shared/list"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/shared/{guid}/access", rbac.AuthPolicy(), 0, stub("GET /api/ab/shared/{guid}/access"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/shared/{guid}/share-candidates", rbac.PermPolicy(rbac.CodeAddressBooksShare), 0, stub("GET /api/ab/shared/{guid}/share-candidates"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/shared/add", rbac.PermPolicy(rbac.CodeAddressBooksShare), 0, stub("POST /api/ab/shared/add"))
	rt.HandlePolicy(http.MethodPut, "/api/ab/shared/update/profile", rbac.PermPolicy(rbac.CodeAddressBooksEdit), 0, stub("PUT /api/ab/shared/update/profile"))
	rt.HandlePolicy(http.MethodDelete, "/api/ab/shared", rbac.PermPolicy(rbac.CodeAddressBooksEdit), 0, stub("DELETE /api/ab/shared"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/peers", rbac.AuthPolicy(), 0, stub("GET /api/ab/peers"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/peers", rbac.AuthPolicy(), 0, stub("POST /api/ab/peers"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/tags/{guid}", rbac.AuthPolicy(), 0, stub("GET /api/ab/tags/{guid}"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/tags/{guid}", rbac.AuthPolicy(), 0, stub("POST /api/ab/tags/{guid}"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/peer/add/{guid}", rbac.AuthPolicy(), 0, stub("POST /api/ab/peer/add/{guid}"))
	rt.HandlePolicy(http.MethodPut, "/api/ab/peer/update/{guid}", rbac.AuthPolicy(), 0, stub("PUT /api/ab/peer/update/{guid}"))
	rt.HandlePolicy(http.MethodDelete, "/api/ab/peer/{guid}", rbac.AuthPolicy(), 0, stub("DELETE /api/ab/peer/{guid}"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/tag/add/{guid}", rbac.AuthPolicy(), 0, stub("POST /api/ab/tag/add/{guid}"))
	rt.HandlePolicy(http.MethodPut, "/api/ab/tag/rename/{guid}", rbac.AuthPolicy(), 0, stub("PUT /api/ab/tag/rename/{guid}"))
	rt.HandlePolicy(http.MethodPut, "/api/ab/tag/update/{guid}", rbac.AuthPolicy(), 0, stub("PUT /api/ab/tag/update/{guid}"))
	rt.HandlePolicy(http.MethodDelete, "/api/ab/tag/{guid}", rbac.AuthPolicy(), 0, stub("DELETE /api/ab/tag/{guid}"))
	rt.HandlePolicy(http.MethodGet, "/api/ab/rules", rbac.PermPolicy(rbac.CodeAddressBooksView), 0, stub("GET /api/ab/rules"))
	rt.HandlePolicy(http.MethodPost, "/api/ab/rule", rbac.PermPolicy(rbac.CodeAddressBooksShare), 0, stub("POST /api/ab/rule"))
	rt.HandlePolicy(http.MethodPatch, "/api/ab/rule", rbac.PermPolicy(rbac.CodeAddressBooksShare), 0, stub("PATCH /api/ab/rule"))
	rt.HandlePolicy(http.MethodDelete, "/api/ab/rules", rbac.PermPolicy(rbac.CodeAddressBooksShare), 0, stub("DELETE /api/ab/rules"))

	// ---- 服务器域（经 agent 转发，五码分档）----
	rt.HandlePolicy(http.MethodGet, "/api/servers", rbac.PermPolicy(rbac.CodeServersView), 0, stub("GET /api/servers"))
	rt.HandlePolicy(http.MethodGet, "/api/servers/{node}/peers", rbac.PermPolicy(rbac.CodeServersView), 0, stub("GET /api/servers/{node}/peers"))
	rt.HandlePolicy(http.MethodGet, "/api/servers/{node}/sessions", rbac.PermPolicy(rbac.CodeServersView), 0, stub("GET /api/servers/{node}/sessions"))
	rt.HandlePolicy(http.MethodDelete, "/api/servers/{node}/sessions/{uuid}", rbac.PermPolicy(rbac.CodeServersDisconnect), 0, stub("DELETE /api/servers/{node}/sessions/{uuid}"))
	rt.HandlePolicy(http.MethodGet, "/api/servers/{node}/services/{service}/config", rbac.PermPolicy(rbac.CodeServersConfig), 0, stub("GET /api/servers/{node}/services/{service}/config"))
	rt.HandlePolicy(http.MethodPut, "/api/servers/{node}/services/{service}/config", rbac.PermPolicy(rbac.CodeServersConfig), 0, stub("PUT /api/servers/{node}/services/{service}/config"))
	rt.HandlePolicy(http.MethodGet, "/api/servers/{node}/services/{service}/logs", rbac.PermPolicy(rbac.CodeServersView), 0, stub("GET /api/servers/{node}/services/{service}/logs"))
	rt.HandlePolicy(http.MethodPost, "/api/servers/{node}/services/{service}/{action}", rbac.PermPolicy(rbac.CodeServersControl), 0, stub("POST /api/servers/{node}/services/{service}/{action}"))
	rt.HandlePolicy(http.MethodGet, "/api/servers/{node}/bans", rbac.PermPolicy(rbac.CodeServersBan), 0, stub("GET /api/servers/{node}/bans"))
	rt.HandlePolicy(http.MethodPut, "/api/servers/{node}/bans", rbac.PermPolicy(rbac.CodeServersBan), 0, stub("PUT /api/servers/{node}/bans"))

	// ---- nexus 域（绑定与构建；POST builds=201 / DELETE=204 特例在 handler 层）----
	rt.HandlePolicy(http.MethodPost, "/api/nexus/auth/login", rbac.AuthPolicy(), 0, stub("POST /api/nexus/auth/login"))
	rt.HandlePolicy(http.MethodGet, "/api/nexus/auth/status", rbac.AuthPolicy(), 0, stub("GET /api/nexus/auth/status"))
	rt.HandlePolicy(http.MethodGet, "/api/nexus/auth/bind-status", rbac.AuthPolicy(), 0, stub("GET /api/nexus/auth/bind-status"))
	rt.HandlePolicy(http.MethodDelete, "/api/nexus/auth/bind", rbac.AuthPolicy(), 0, stub("DELETE /api/nexus/auth/bind"))
	rt.HandlePolicy(http.MethodPost, "/api/nexus/builds", rbac.AuthPolicy(), 0, stub("POST /api/nexus/builds"))
	rt.HandlePolicy(http.MethodGet, "/api/nexus/builds", rbac.AuthPolicy(), 0, stub("GET /api/nexus/builds"))
	rt.HandlePolicy(http.MethodDelete, "/api/nexus/builds/{uuid}", rbac.AuthPolicy(), 0, stub("DELETE /api/nexus/builds/{uuid}"))
	rt.HandlePolicy(http.MethodGet, "/api/nexus/builds/{uuid}/files", rbac.AuthPolicy(), 0, stub("GET /api/nexus/builds/{uuid}/files"))
	rt.HandlePolicy(http.MethodGet, "/api/nexus/builds/{uuid}/files/{filename}", rbac.AuthPolicy(), 0, stub("GET /api/nexus/builds/{uuid}/files/{filename}"))

	// ---- 设置域（frontend 公开；general/smtp/ldap Admin；test 5/min）----
	rt.HandlePolicy(http.MethodGet, "/api/settings/frontend", rbac.PublicPolicy(), 0, stub("GET /api/settings/frontend"))
	rt.HandlePolicy(http.MethodGet, "/api/settings/general", rbac.AdminGuardPolicy(), 0, stub("GET /api/settings/general"))
	rt.HandlePolicy(http.MethodPut, "/api/settings/general", rbac.AdminGuardPolicy(), 0, stub("PUT /api/settings/general"))
	rt.HandlePolicy(http.MethodGet, "/api/settings/smtp", rbac.AdminGuardPolicy(), 0, stub("GET /api/settings/smtp"))
	rt.HandlePolicy(http.MethodPut, "/api/settings/smtp", rbac.AdminGuardPolicy(), 0, stub("PUT /api/settings/smtp"))
	rt.HandlePolicy(http.MethodPost, "/api/settings/smtp/test", rbac.AdminGuardPolicy(), 5, stub("POST /api/settings/smtp/test"))
	rt.HandlePolicy(http.MethodGet, "/api/settings/ldap", rbac.AdminGuardPolicy(), 0, stub("GET /api/settings/ldap"))
	rt.HandlePolicy(http.MethodPut, "/api/settings/ldap", rbac.AdminGuardPolicy(), 0, stub("PUT /api/settings/ldap"))
	rt.HandlePolicy(http.MethodPost, "/api/settings/ldap/test", rbac.AdminGuardPolicy(), 5, stub("POST /api/settings/ldap/test"))

	// ---- OIDC 提供者域（全 Admin）----
	rt.HandlePolicy(http.MethodGet, "/api/oidc-providers", rbac.AdminGuardPolicy(), 0, stub("GET /api/oidc-providers"))
	rt.HandlePolicy(http.MethodPost, "/api/oidc-providers", rbac.AdminGuardPolicy(), 0, stub("POST /api/oidc-providers"))
	rt.HandlePolicy(http.MethodPatch, "/api/oidc-providers/sort", rbac.AdminGuardPolicy(), 0, stub("PATCH /api/oidc-providers/sort"))
	rt.HandlePolicy(http.MethodGet, "/api/oidc-providers/{guid}", rbac.AdminGuardPolicy(), 0, stub("GET /api/oidc-providers/{guid}"))
	rt.HandlePolicy(http.MethodPatch, "/api/oidc-providers/{guid}", rbac.AdminGuardPolicy(), 0, stub("PATCH /api/oidc-providers/{guid}"))
	rt.HandlePolicy(http.MethodDelete, "/api/oidc-providers/{guid}", rbac.AdminGuardPolicy(), 0, stub("DELETE /api/oidc-providers/{guid}"))
	rt.HandlePolicy(http.MethodPatch, "/api/oidc-providers/{guid}/toggle", rbac.AdminGuardPolicy(), 0, stub("PATCH /api/oidc-providers/{guid}/toggle"))
	rt.HandlePolicy(http.MethodPost, "/api/oidc-providers/{guid}/test", rbac.AdminGuardPolicy(), 0, stub("POST /api/oidc-providers/{guid}/test"))

	// ---- 更新检查（Admin）----
	rt.HandlePolicy(http.MethodGet, "/api/update-check", rbac.AdminGuardPolicy(), 0, stub("GET /api/update-check"))
}
