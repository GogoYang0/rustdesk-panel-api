// Package handler 本文件：RBAC 域 handler（设计 §1.6 rbac 档 11 端点）：
// permissions 目录/生效权限（Auth）、roles 列表/详情（roles.view）与
// 创建/更新/删除/保护影响（super administrator）、users/{guid}/roles
// 三端点（roles.assign）。
package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	rbacsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/rbac"
)

// RbacHandler RBAC 域端点。
type RbacHandler struct {
	authz     *rbac.AuthorizationService
	roles     *rbacsvc.RoleService
	userRoles *rbacsvc.UserRoleService
}

// NewRbacHandler 构建 handler。
func NewRbacHandler(
	authz *rbac.AuthorizationService,
	roles *rbacsvc.RoleService,
	userRoles *rbacsvc.UserRoleService,
) *RbacHandler {
	return &RbacHandler{authz: authz, roles: roles, userRoles: userRoles}
}

// ListPermissions GET /api/permissions：权限目录只读（目录顺序稳定）。
func (h *RbacHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, dto.PermissionsResult{Data: rbac.Catalog()})
}

// MyPermissions GET /api/permissions/me：当前用户生效权限（依赖过滤后
// 码集 + scopes 映射）。
func (h *RbacHandler) MyPermissions(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	perms, err := h.authz.GetEffectivePermissions(r.Context(), ident.UserGuid)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, perms)
}

// ListRoles GET /api/roles（roles.view）。
func (h *RbacHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	page, err := h.roles.List(r.Context(), dto.ParseRoleListQuery(r.URL.Query()))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// CreateRole POST /api/roles（super administrator）。
func (h *RbacHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.RoleCreateRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	view, err := h.roles.Create(r.Context(), ident.UserGuid, *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// GetRole GET /api/roles/{guid}（roles.view；uuid v4 校验 400）。
func (h *RbacHandler) GetRole(w http.ResponseWriter, r *http.Request) {
	detail, err := h.roles.Get(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, detail)
}

// UpdateRole PATCH /api/roles/{guid}（super administrator）。
func (h *RbacHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.RoleUpdateRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	view, err := h.roles.Update(r.Context(), ident.UserGuid, r.PathValue("guid"), *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// DeleteRole DELETE /api/roles/{guid}（super administrator）。成功响应空对象。
func (h *RbacHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	if err := h.roles.Delete(r.Context(), ident.UserGuid, r.PathValue("guid")); err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct{}{})
}

// RoleProtectionImpact GET /api/roles/{guid}/protection-impact
// （super administrator）。
func (h *RbacHandler) RoleProtectionImpact(w http.ResponseWriter, r *http.Request) {
	impact, err := h.roles.ProtectionImpact(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, impact)
}

// GetUserRoles GET /api/users/{guid}/roles（roles.assign）。
func (h *RbacHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	res, err := h.userRoles.GetUserRoles(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// UserRoleEligibility GET /api/users/{guid}/roles/eligibility
// （roles.assign）。
func (h *RbacHandler) UserRoleEligibility(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.userRoles.Eligibility(r.Context(), ident.UserGuid, r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ReplaceUserRoles PUT /api/users/{guid}/roles（roles.assign）。
func (h *RbacHandler) ReplaceUserRoles(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.ReplaceRolesRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.userRoles.ReplaceUserRoles(r.Context(), ident.UserGuid, r.PathValue("guid"), *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
