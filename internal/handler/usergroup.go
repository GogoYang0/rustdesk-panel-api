// Package handler 本文件：用户组域 handler（设计 §1.6 user-group 档
// 6 端点）：列表/成员查询（user_groups.view）、创建/更新/删除
// （create/edit/delete 分码）、成员移动（user_groups.membership）。
package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	usergroupsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/usergroup"
)

// UserGroupHandler 用户组域端点。
type UserGroupHandler struct {
	svc *usergroupsvc.Service
}

// NewUserGroupHandler 构建 handler。
func NewUserGroupHandler(svc *usergroupsvc.Service) *UserGroupHandler {
	return &UserGroupHandler{svc: svc}
}

// List GET /api/user-groups（user_groups.view）。
func (h *UserGroupHandler) List(w http.ResponseWriter, r *http.Request) {
	page, err := h.svc.List(r.Context(), dto.ParseUserGroupListQuery(r.URL.Query()))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// Create POST /api/user-groups（user_groups.create）。
func (h *UserGroupHandler) Create(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.UserGroupUpsertRequest](w, r)
	if !ok {
		return
	}
	view, err := h.svc.Create(r.Context(), *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// Update PUT /api/user-groups/{guid}（user_groups.edit）。
func (h *UserGroupHandler) Update(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.UserGroupUpsertRequest](w, r)
	if !ok {
		return
	}
	view, err := h.svc.Update(r.Context(), r.PathValue("guid"), *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// Delete DELETE /api/user-groups/{guid}（user_groups.delete；默认组
// 禁删 400，成员回落默认组）。
func (h *UserGroupHandler) Delete(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Delete(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// Members GET /api/user-groups/{guid}/users（user_groups.view）。
func (h *UserGroupHandler) Members(w http.ResponseWriter, r *http.Request) {
	page, err := h.svc.Members(r.Context(), r.PathValue("guid"), dto.ParseMemberListQuery(r.URL.Query()))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// MoveUsers POST /api/user-groups/{guid}/users（user_groups.membership）。
func (h *UserGroupHandler) MoveUsers(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.MoveUsersRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.MoveUsers(r.Context(), ident.UserGuid, r.PathValue("guid"), *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
