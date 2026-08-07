// Package handler 本文件：设备域 handler（设计 §2）——
// GET /api/peers（Auth+状态复核，无权限码）与 /devices×5
// （Perm(devices.*) 路由策略由注册处声明，资源级复核在服务层）。
package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	devicesvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/device"
)

// DeviceHandler 设备域端点。
type DeviceHandler struct {
	authz *rbac.AuthorizationService
	query *devicesvc.QueryService
	admin *devicesvc.AdminService
}

// NewDeviceHandler 构建 handler。
func NewDeviceHandler(authz *rbac.AuthorizationService, query *devicesvc.QueryService, admin *devicesvc.AdminService) *DeviceHandler {
	return &DeviceHandler{authz: authz, query: query, admin: admin}
}

// ListPeers GET /api/peers：Auth 路由无 RBAC 中间件，被禁用户 401
// 固定文案的状态复核在此收口（GetCurrentUser 实时查库，不信任 JWT）。
func (h *DeviceHandler) ListPeers(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	viewer, err := h.authz.GetCurrentUser(r.Context(), ident.UserGuid)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	q := dto.ParsePeerListQuery(r.URL.Query())
	page, err := h.query.GetAccessiblePeers(r.Context(), viewer, q)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// ListDevices GET /api/devices（Perm(devices.view)；scope 复取与
// 边界过滤在 AdminService.GetDevices 内完成）。
func (h *DeviceHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	q := dto.ParseDeviceListQuery(r.URL.Query())
	page, err := h.admin.GetDevices(r.Context(), ident.UserGuid, q)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// UpdateDeviceStatus PATCH /api/devices/status（Perm(devices.status)）。
func (h *DeviceHandler) UpdateDeviceStatus(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.DeviceStatusUpdateRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.admin.UpdateStatus(r.Context(), ident.UserGuid, *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// UpdateDevice PATCH /api/devices/{guid}（Perm(devices.edit)；
// guid = peer.uuid）。返回更新后的 DeviceView。
func (h *DeviceHandler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.UpdateDeviceRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	view, err := h.admin.UpdateDevice(r.Context(), ident.UserGuid, r.PathValue("guid"), *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// DeleteDevice DELETE /api/devices/{guid}（Perm(devices.delete)）。
// 成功响应空对象。
func (h *DeviceHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	err := h.admin.DeleteDevice(r.Context(), ident.UserGuid, r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct{}{})
}

// Disconnect POST /api/devices/{uuid}/disconnect（Perm(devices.disconnect)）。
func (h *DeviceHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.DisconnectRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.admin.Disconnect(r.Context(), ident.UserGuid, r.PathValue("uuid"), req.ConnIDs)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
