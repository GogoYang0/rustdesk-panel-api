// 外部测试包：全栈路由装配依赖 internal/testutil/apptest（其又依赖
// internal/server），内部测试包会构成 import cycle，故用 server_test 挂载。
//
// 本文件是三方一致性回归（M2 T06 建立，M3 T01 起扩至全量口径）：
//
//	路由表（Router.Routes 注册声明）
//	↔ openapi.yaml（operation 集合 + security 公开性 + operationId 唯一）
//	↔ 设计档位表（§2.1 认证域 / §1.4 设备协议 / §1.6 M2 各域 /
//	  M3 设计 §1.3 策略总表，本文件硬编码）
//
// 任何一侧单点改动——新增或删除端点、漏标 security、策略档位漂移、
// 权限码改名、复制 operationId——都会被另外两方指认。
package server_test

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil/apptest"
)

// expectedOperations 是契约规模门槛：openapi.yaml 必须恰好覆盖
// 164 个 operation（M2 收口 68 + M3 T01 骨架 96；M3 设计 §1.3 策略
// 总表逐行勾稽，其中 settings 域设计合计栏"6"为笔误、实为 9——
// 本常量以逐行清单为准）。
const expectedOperations = 172

// m2SecuredOpenapiOperations openapi.yaml 中声明了 security 块的 operation
// 集合（契约现状约定）：仅 M1 认证域的 16 个 JWT 端点标注
// security: [bearerAuth, cookieAuth]；M1 公开端点与 M2 全部端点不标注
// （M2 授权语义记录于各 operation 的 summary/description 与路由档位表）。
// 三方一致性据此锁定该集合——给公开端点加 security、给 M2 端点补/删
// security、或漏掉这 16 个之一，都会被指认。
var m2SecuredOpenapiOperations = []string{
	http.MethodPost + " /api/logout",
	http.MethodPost + " /api/currentUser",
	http.MethodPost + " /api/2fa/setup",
	http.MethodPost + " /api/2fa/verify",
	http.MethodDelete + " /api/2fa",
	http.MethodPost + " /api/passkey/register/begin",
	http.MethodPost + " /api/passkey/register/verify",
	http.MethodGet + " /api/passkey/list",
	http.MethodDelete + " /api/passkey/{guid}",
	http.MethodPost + " /api/passkey/tfa",
	http.MethodGet + " /api/sessions",
	http.MethodDelete + " /api/sessions/{jti}",
	http.MethodPatch + " /api/users/me",
	http.MethodPatch + " /api/users/me/password",
	http.MethodPost + " /api/users/me/avatar",
	http.MethodDelete + " /api/users/me/avatar",
}

// routeTable 设计档位期望表：键 "METHOD pattern" → 授权声明。
type routeTable map[string]server.Route

// add 登记一条期望声明；重复键属测试代码自身缺陷，立即 panic。
func (tb routeTable) add(method, pattern, policy, code string) {
	key := method + " " + pattern
	if _, dup := tb[key]; dup {
		panic("router_m2_policy_test: duplicate expected route " + key)
	}
	tb[key] = server.Route{Method: method, Pattern: pattern, Policy: policy, Code: code}
}

// expectedRouteTable 设计档位期望表（共 68 条）。
//
// 权限码用设计文档字面量（如 "devices.view"）而非 rbac 常量——三方
// 一致性的价值正在于让"常量值漂移"也被指认。档位命名与 §1.6 一致。
func expectedRouteTable() routeTable {
	tb := routeTable{}

	// —— 系统（M0）——
	tb.add(http.MethodGet, "/api/healthz", server.PolicyPublic, "")

	// —— 认证域（§2.1 #1~#19）：公开白名单 7 条，其余仅 JWT ——
	tb.add(http.MethodPost, "/api/login", server.PolicyPublic, "")
	tb.add(http.MethodGet, "/api/login-options", server.PolicyPublic, "")
	tb.add(http.MethodPost, "/api/passkey/auth/begin", server.PolicyPublic, "")
	tb.add(http.MethodPost, "/api/passkey/auth/verify", server.PolicyPublic, "")
	tb.add(http.MethodPost, "/api/oidc/auth", server.PolicyPublic, "")
	tb.add(http.MethodGet, "/api/oidc/auth-query", server.PolicyPublic, "")
	tb.add(http.MethodGet, "/api/oidc/callback", server.PolicyPublic, "")
	tb.add(http.MethodPost, "/api/logout", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/currentUser", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/2fa/setup", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/2fa/verify", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/2fa", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/passkey/register/begin", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/passkey/register/verify", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/passkey/list", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/passkey/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/passkey/tfa", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/sessions", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/sessions/{jti}", server.PolicyAuth, "")

	// —— 用户自身（§2.1 #20~#24）；头像静态服务公开 ——
	tb.add(http.MethodPatch, "/api/users/me", server.PolicyAuth, "")
	tb.add(http.MethodPatch, "/api/users/me/password", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/users/me/avatar", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/users/me/avatar", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/avatars/{filename}", server.PolicyPublic, "")

	// —— 设备端协议（§1.4）：公开 + 设备维度限流，无权限码 ——
	tb.add(http.MethodPost, "/api/heartbeat", server.PolicyPublic, "")
	tb.add(http.MethodPost, "/api/sysinfo", server.PolicyPublic, "")

	// —— 设备域（§1.6 device 档）：/peers 无权限码（Auth+状态复核），
	// /devices×5 走 Perm(devices.*) ——
	tb.add(http.MethodGet, "/api/peers", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/devices", server.PolicyPerm, "devices.view")
	tb.add(http.MethodPatch, "/api/devices/status", server.PolicyPerm, "devices.status")
	tb.add(http.MethodPatch, "/api/devices/{guid}", server.PolicyPerm, "devices.edit")
	tb.add(http.MethodDelete, "/api/devices/{guid}", server.PolicyPerm, "devices.delete")
	tb.add(http.MethodPost, "/api/devices/{uuid}/disconnect", server.PolicyPerm, "devices.disconnect")

	// —— 设备组域（§1.6 device-group 档）：accessible 无权限码；列表/
	// CRUD/加减设备 AdminGuard；strategy-targets 走 Perm(strategies.assign) ——
	tb.add(http.MethodGet, "/api/device-group/accessible", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/device-groups", server.PolicyAdminGuard, "")
	tb.add(http.MethodPost, "/api/device-groups", server.PolicyAdminGuard, "")
	tb.add(http.MethodGet, "/api/device-groups/strategy-targets", server.PolicyPerm, "strategies.assign")
	tb.add(http.MethodPatch, "/api/device-groups/{guid}", server.PolicyAdminGuard, "")
	tb.add(http.MethodDelete, "/api/device-groups/{guid}", server.PolicyAdminGuard, "")
	tb.add(http.MethodPost, "/api/device-groups/{guid}", server.PolicyAdminGuard, "")
	tb.add(http.MethodDelete, "/api/device-groups/{guid}/devices", server.PolicyAdminGuard, "")

	// —— 策略域（§1.6 strategy 档）：CRUD 按 view/create/edit/delete
	// 分码；candidates/target-candidates/assignments/assign/unassign 均
	// Perm(strategies.assign) ——
	tb.add(http.MethodGet, "/api/strategies", server.PolicyPerm, "strategies.view")
	tb.add(http.MethodPost, "/api/strategies", server.PolicyPerm, "strategies.create")
	tb.add(http.MethodGet, "/api/strategies/candidates", server.PolicyPerm, "strategies.assign")
	tb.add(http.MethodGet, "/api/strategies/target-candidates", server.PolicyPerm, "strategies.assign")
	tb.add(http.MethodGet, "/api/strategies/{guid}", server.PolicyPerm, "strategies.view")
	tb.add(http.MethodPatch, "/api/strategies/{guid}", server.PolicyPerm, "strategies.edit")
	tb.add(http.MethodDelete, "/api/strategies/{guid}", server.PolicyPerm, "strategies.delete")
	tb.add(http.MethodGet, "/api/strategies/{guid}/assignments", server.PolicyPerm, "strategies.assign")
	tb.add(http.MethodPost, "/api/strategies/{guid}/assign", server.PolicyPerm, "strategies.assign")
	tb.add(http.MethodPost, "/api/strategies/{guid}/unassign", server.PolicyPerm, "strategies.assign")

	// —— RBAC 域（§1.6 rbac 档）：目录只读与 roles 读走 roles.view；
	// roles 写路径 + protection-impact 走 super administrator；用户角色
	// 指派三端点走 Perm(roles.assign)；permissions/me 仅 JWT ——
	tb.add(http.MethodGet, "/api/permissions", server.PolicyPerm, "roles.view")
	tb.add(http.MethodGet, "/api/permissions/me", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/roles", server.PolicyPerm, "roles.view")
	tb.add(http.MethodPost, "/api/roles", server.PolicySuperAdmin, "")
	tb.add(http.MethodGet, "/api/roles/{guid}", server.PolicyPerm, "roles.view")
	tb.add(http.MethodPatch, "/api/roles/{guid}", server.PolicySuperAdmin, "")
	tb.add(http.MethodDelete, "/api/roles/{guid}", server.PolicySuperAdmin, "")
	tb.add(http.MethodGet, "/api/roles/{guid}/protection-impact", server.PolicySuperAdmin, "")
	tb.add(http.MethodGet, "/api/users/{guid}/roles", server.PolicyPerm, "roles.assign")
	tb.add(http.MethodGet, "/api/users/{guid}/roles/eligibility", server.PolicyPerm, "roles.assign")
	tb.add(http.MethodPut, "/api/users/{guid}/roles", server.PolicyPerm, "roles.assign")

	// —— 用户组域（§1.6 user-group 档）：CRUD 与成员查询分码，成员移动
	// 走 membership 码（保护账号复核在服务层）——
	tb.add(http.MethodGet, "/api/user-groups", server.PolicyPerm, "user_groups.view")
	tb.add(http.MethodPost, "/api/user-groups", server.PolicyPerm, "user_groups.create")
	tb.add(http.MethodPut, "/api/user-groups/{guid}", server.PolicyPerm, "user_groups.edit")
	tb.add(http.MethodDelete, "/api/user-groups/{guid}", server.PolicyPerm, "user_groups.delete")
	tb.add(http.MethodGet, "/api/user-groups/{guid}/users", server.PolicyPerm, "user_groups.view")
	tb.add(http.MethodPost, "/api/user-groups/{guid}/users", server.PolicyPerm, "user_groups.membership")

	// —— M3 用户域（设计 §1.3 user 档；M1 已有 5 条 me/avatar 不重复
	// 列出）：PATCH /users/{guid} 按字段分权故仅 Auth；invite/verify/
	// accept 公开与 Perm(users.create) 分档 ——
	tb.add(http.MethodGet, "/api/users", server.PolicyPerm, "users.view")
	tb.add(http.MethodPost, "/api/users", server.PolicyPerm, "users.create")
	tb.add(http.MethodPost, "/api/users/invite", server.PolicyPerm, "users.create")
	tb.add(http.MethodPost, "/api/invitations/verify", server.PolicyPublic, "")
	tb.add(http.MethodPost, "/api/invitations/accept", server.PolicyPublic, "")
	tb.add(http.MethodPatch, "/api/users/batch/status", server.PolicyPerm, "users.status")
	tb.add(http.MethodPatch, "/api/users/batch/security", server.PolicyPerm, "users.security")
	tb.add(http.MethodDelete, "/api/users/batch/sessions", server.PolicyPerm, "users.force_logout")
	tb.add(http.MethodGet, "/api/users/{guid}", server.PolicyPerm, "users.view")
	tb.add(http.MethodPatch, "/api/users/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/users/{guid}", server.PolicyPerm, "users.delete")
	tb.add(http.MethodPatch, "/api/users/{guid}/security", server.PolicyPerm, "users.security")
	tb.add(http.MethodDelete, "/api/users/{guid}/sessions", server.PolicyPerm, "users.force_logout")
	tb.add(http.MethodGet, "/api/admin/users", server.PolicyPerm, "users.view")

	// —— M3 通讯录域（设计 §1.3 ab 档）：24 端点仅 Auth（owner/规则
	// 在 service 内复核）；share-candidates/shared add/share 写路径
	// Perm(address_books.share)；shared edit 路径 Perm(address_books.edit)；
	// rules 查询 Perm(address_books.view) ——
	tb.add(http.MethodGet, "/api/ab", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab/settings", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/ab/personal", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab/personal", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/ab/custom/profiles", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab/custom/add", server.PolicyAuth, "")
	tb.add(http.MethodPut, "/api/ab/custom/update/profile", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/ab/custom", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/ab/shared/profiles", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab/shared/profiles", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/ab/shared/list", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/ab/shared/{guid}/access", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/ab/shared/{guid}/share-candidates", server.PolicyPerm, "address_books.share")
	tb.add(http.MethodPost, "/api/ab/shared/add", server.PolicyPerm, "address_books.share")
	tb.add(http.MethodPut, "/api/ab/shared/update/profile", server.PolicyPerm, "address_books.edit")
	tb.add(http.MethodDelete, "/api/ab/shared", server.PolicyPerm, "address_books.edit")
	tb.add(http.MethodGet, "/api/ab/peers", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab/peers", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/ab/tags/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab/tags/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab/peer/add/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodPut, "/api/ab/peer/update/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/ab/peer/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/ab/tag/add/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodPut, "/api/ab/tag/rename/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodPut, "/api/ab/tag/update/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/ab/tag/{guid}", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/ab/rules", server.PolicyPerm, "address_books.view")
	tb.add(http.MethodPost, "/api/ab/rule", server.PolicyPerm, "address_books.share")
	tb.add(http.MethodPatch, "/api/ab/rule", server.PolicyPerm, "address_books.share")
	tb.add(http.MethodDelete, "/api/ab/rules", server.PolicyPerm, "address_books.share")

	// —— M3 审计域（设计 §1.3 audit 档，★ 退出标准载体）：上报单数
	// Public + per-IP 50/min；active 走 devices.disconnect（scope∩
	// can_disconnect）；查询复数 audit.view；conn note PATCH SuperAdmin ——
	tb.add(http.MethodPost, "/api/audit/conn", server.PolicyPublic, "")
	tb.add(http.MethodPost, "/api/audit/file", server.PolicyPublic, "")
	tb.add(http.MethodPost, "/api/audit/alarm", server.PolicyPublic, "")
	tb.add(http.MethodGet, "/api/audits/conn/active", server.PolicyPerm, "devices.disconnect")
	tb.add(http.MethodGet, "/api/audits/conn", server.PolicyPerm, "audit.view")
	tb.add(http.MethodPatch, "/api/audits/conn/{id}", server.PolicySuperAdmin, "")
	tb.add(http.MethodGet, "/api/audits/file", server.PolicyPerm, "audit.view")
	tb.add(http.MethodGet, "/api/audits/alarm", server.PolicyPerm, "audit.view")
	tb.add(http.MethodGet, "/api/audits/console", server.PolicyPerm, "audit.view")

	// —— M3 仪表盘域：双端点 SuperAdmin ——
	tb.add(http.MethodGet, "/api/dashboard", server.PolicySuperAdmin, "")
	tb.add(http.MethodGet, "/api/dashboard/trends", server.PolicySuperAdmin, "")

	// —— M3 服务器域（设计 §1.3 servers 档）：view/disconnect/config/
	// control/ban 五码分档 ——
	tb.add(http.MethodGet, "/api/servers", server.PolicyPerm, "servers.view")
	tb.add(http.MethodGet, "/api/servers/{node}/peers", server.PolicyPerm, "servers.view")
	tb.add(http.MethodGet, "/api/servers/{node}/sessions", server.PolicyPerm, "servers.view")
	tb.add(http.MethodDelete, "/api/servers/{node}/sessions/{uuid}", server.PolicyPerm, "servers.disconnect")
	tb.add(http.MethodGet, "/api/servers/{node}/services/{service}/config", server.PolicyPerm, "servers.config")
	tb.add(http.MethodPut, "/api/servers/{node}/services/{service}/config", server.PolicyPerm, "servers.config")
	tb.add(http.MethodGet, "/api/servers/{node}/services/{service}/logs", server.PolicyPerm, "servers.view")
	tb.add(http.MethodPost, "/api/servers/{node}/services/{service}/{action}", server.PolicyPerm, "servers.control")
	tb.add(http.MethodGet, "/api/servers/{node}/bans", server.PolicyPerm, "servers.ban")
	tb.add(http.MethodPut, "/api/servers/{node}/bans", server.PolicyPerm, "servers.ban")

	// —— M3 nexus 域：全部 Auth（构建归属 user 校验在 service 层）——
	tb.add(http.MethodPost, "/api/nexus/auth/login", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/nexus/auth/status", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/nexus/auth/bind-status", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/nexus/auth/bind", server.PolicyAuth, "")
	tb.add(http.MethodPost, "/api/nexus/builds", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/nexus/builds", server.PolicyAuth, "")
	tb.add(http.MethodDelete, "/api/nexus/builds/{uuid}", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/nexus/builds/{uuid}/files", server.PolicyAuth, "")
	tb.add(http.MethodGet, "/api/nexus/builds/{uuid}/files/{filename}", server.PolicyAuth, "")

	// —— M3 设置域：frontend 公开；general/smtp/ldap AdminGuard；
	// smtp/ldap test 限流 5/min（限流不改变授权档位）——
	tb.add(http.MethodGet, "/api/settings/frontend", server.PolicyPublic, "")
	tb.add(http.MethodGet, "/api/settings/general", server.PolicyAdminGuard, "")
	tb.add(http.MethodPut, "/api/settings/general", server.PolicyAdminGuard, "")
	tb.add(http.MethodGet, "/api/settings/smtp", server.PolicyAdminGuard, "")
	tb.add(http.MethodPut, "/api/settings/smtp", server.PolicyAdminGuard, "")
	tb.add(http.MethodPost, "/api/settings/smtp/test", server.PolicyAdminGuard, "")
	tb.add(http.MethodGet, "/api/settings/ldap", server.PolicyAdminGuard, "")
	tb.add(http.MethodPut, "/api/settings/ldap", server.PolicyAdminGuard, "")
	tb.add(http.MethodPost, "/api/settings/ldap/test", server.PolicyAdminGuard, "")

	// —— M3 OIDC 提供者域：全 AdminGuard ——
	tb.add(http.MethodGet, "/api/oidc-providers", server.PolicyAdminGuard, "")
	tb.add(http.MethodPost, "/api/oidc-providers", server.PolicyAdminGuard, "")
	tb.add(http.MethodPatch, "/api/oidc-providers/sort", server.PolicyAdminGuard, "")
	tb.add(http.MethodGet, "/api/oidc-providers/{guid}", server.PolicyAdminGuard, "")
	tb.add(http.MethodPatch, "/api/oidc-providers/{guid}", server.PolicyAdminGuard, "")
	tb.add(http.MethodDelete, "/api/oidc-providers/{guid}", server.PolicyAdminGuard, "")
	tb.add(http.MethodPatch, "/api/oidc-providers/{guid}/toggle", server.PolicyAdminGuard, "")
	tb.add(http.MethodPost, "/api/oidc-providers/{guid}/test", server.PolicyAdminGuard, "")

	// —— M3 更新检查：AdminGuard ——
	tb.add(http.MethodGet, "/api/update-check", server.PolicyAdminGuard, "")

	// —— M3 静态资源（设计 §1.3 静态档）：SPA 兜底与 /files 公开 ——
	tb.add(http.MethodGet, "/", server.PolicyPublic, "")
	tb.add(http.MethodGet, "/files/{path}", server.PolicyPublic, "")

	return tb
}

// loadM2Spec 加载并校验 openapi.yaml（契约单一源；与 contract 包同一惯例）。
func loadM2Spec(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("../../openapi.yaml")
	if err != nil {
		t.Fatalf("load openapi.yaml: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("validate openapi.yaml: %v", err)
	}
	return doc
}

// specOperations 展开 doc 全部 operation，键 "METHOD path"（大写方法，
// 与路由注册声明同构）。
func specOperations(doc *openapi3.T) map[string]*openapi3.Operation {
	ops := make(map[string]*openapi3.Operation)
	for _, path := range doc.Paths.Keys() {
		pathItem := doc.Paths.Value(path)
		if pathItem == nil {
			continue
		}
		for method, op := range pathItem.Operations() {
			ops[strings.ToUpper(method)+" "+path] = op
		}
	}
	return ops
}

// opHasSecurity 判断 operation 是否声明 security 块（nil 与空数组均视为
// 未声明，与 OpenAPI 语义一致）。声明集合由 m2SecuredOpenapiOperations 锁定。
func opHasSecurity(op *openapi3.Operation) bool {
	return op.Security != nil && len(*op.Security) > 0
}

// TestM2OperationCountRegression M2 收口回归门槛：openapi.yaml 必须
// 恰好 68 个 operation 且 operationId 非空唯一。新增端点漏同步契约、
// 误删端点或复制 operationId 都会在此失败。
func TestM2OperationCountRegression(t *testing.T) {
	ops := specOperations(loadM2Spec(t))
	if len(ops) != expectedOperations {
		t.Fatalf("openapi operation count = %d, want %d", len(ops), expectedOperations)
	}
	seen := make(map[string]string, len(ops))
	for key, op := range ops {
		if op.OperationID == "" {
			t.Errorf("operation %s missing operationId", key)
			continue
		}
		if prev, dup := seen[op.OperationID]; dup {
			t.Errorf("duplicate operationId %q: %s and %s", op.OperationID, prev, key)
		}
		seen[op.OperationID] = key
	}
}

// TestM2RouterOpenapiThreeWayConsistency 三方一致性（M2 收口核心回归）。
//
// 三方数据源：
//  1. 设计档位表：本文件 expectedRouteTable()（§2.1/§1.4/§1.6 硬编码）；
//  2. 路由表：apptest 装配完整路由后 Router.Routes() 的注册声明；
//  3. openapi.yaml：operation 集合、operationId 唯一性、security 标注集。
//
// 断言链条：设计 ↔ 路由（端点集合与档位/权限码逐一相等）→
// openapi ↔ 路由（端点集合双向覆盖）→ security 标注集 ↔ 契约约定
// （m2SecuredOpenapiOperations 的 16 个端点必须带 security，其余 52 个
// 必须不带——标注漂移即失败）。
func TestM2RouterOpenapiThreeWayConsistency(t *testing.T) {
	as := apptest.NewAppServer(t, nil)

	// ---- 路由表：注册声明收集与去重 ----
	actual := make(map[string]server.Route)
	for _, r := range as.Router.Routes() {
		key := r.Method + " " + r.Pattern
		if _, dup := actual[key]; dup {
			t.Errorf("duplicate route registration: %s", key)
		}
		actual[key] = r
	}
	if len(actual) != expectedOperations {
		t.Errorf("router registered routes = %d, want %d", len(actual), expectedOperations)
	}

	// ---- 设计 ↔ 路由：端点集合相等，档位与权限码逐一比对 ----
	expected := expectedRouteTable()
	if len(expected) != expectedOperations {
		t.Fatalf("design route table = %d entries, want %d", len(expected), expectedOperations)
	}
	var missing, drifted, undeclared []string
	for key, want := range expected {
		got, ok := actual[key]
		if !ok {
			missing = append(missing, key)
			continue
		}
		if got.Policy != want.Policy || got.Code != want.Code {
			drifted = append(drifted, fmt.Sprintf(
				"%s: registered policy=(%s,%q), design wants (%s,%q)",
				key, got.Policy, got.Code, want.Policy, want.Code))
		}
	}
	for key := range actual {
		if _, ok := expected[key]; !ok {
			undeclared = append(undeclared, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		t.Errorf("route %s missing from router registration", key)
	}
	sort.Strings(drifted)
	for _, msg := range drifted {
		t.Error(msg)
	}
	sort.Strings(undeclared)
	for _, key := range undeclared {
		t.Errorf("route %s registered but absent from design table", key)
	}

	// ---- openapi ↔ 路由：operation 集合双向覆盖 ----
	ops := specOperations(loadM2Spec(t))
	if len(ops) != expectedOperations {
		t.Fatalf("openapi operation count = %d, want %d", len(ops), expectedOperations)
	}
	var noRoute, noSpec []string
	for key := range ops {
		if _, ok := actual[key]; !ok {
			noRoute = append(noRoute, key)
		}
	}
	for key := range actual {
		if _, ok := ops[key]; !ok {
			noSpec = append(noSpec, key)
		}
	}
	sort.Strings(noRoute)
	for _, key := range noRoute {
		t.Errorf("openapi operation %s has no registered route", key)
	}
	sort.Strings(noSpec)
	for _, key := range noSpec {
		t.Errorf("route %s not declared in openapi.yaml", key)
	}

	// ---- security 标注集 ↔ 契约约定：双向精确锁定 ----
	secured := make(map[string]bool, len(m2SecuredOpenapiOperations))
	for _, key := range m2SecuredOpenapiOperations {
		secured[key] = true
		if _, ok := ops[key]; !ok {
			t.Errorf("security-annotated operation %s not found in openapi.yaml", key)
		}
	}
	for key, op := range ops {
		has, want := opHasSecurity(op), secured[key]
		switch {
		case has && !want:
			t.Errorf("%s: openapi declares security but contract convention does not annotate it", key)
		case !has && want:
			t.Errorf("%s: contract convention requires security block but openapi.yaml lacks it", key)
		}
	}
	if len(secured) != len(m2SecuredOpenapiOperations) {
		t.Errorf("secured operation set has duplicates: len=%d, want=%d",
			len(secured), len(m2SecuredOpenapiOperations))
	}
}
