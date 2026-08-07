// Package handler 本文件：设备组域 handler（设计 §1.6 device-group 档
// 8 端点）：accessible（Auth+状态复核，scope 语义在服务层）、列表/CRUD
// （AdminGuard）、strategy-targets（Perm(strategies.assign)）、批量
// 加入/移出设备（body 为裸数组 peer.id[]）。
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	devicegroupsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/devicegroup"
)

// DeviceGroupHandler 设备组域端点。
type DeviceGroupHandler struct {
	svc *devicegroupsvc.GroupService
}

// NewDeviceGroupHandler 构建 handler。
func NewDeviceGroupHandler(svc *devicegroupsvc.GroupService) *DeviceGroupHandler {
	return &DeviceGroupHandler{svc: svc}
}

// Accessible GET /api/device-group/accessible（Auth；被禁用户 401
// 固定文案的状态复核在服务层 GetCurrentUser 收口）。
func (h *DeviceGroupHandler) Accessible(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	page, err := h.svc.Accessible(r.Context(), ident.UserGuid, r.URL.Query().Get("name"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// List GET /api/device-groups（AdminGuard）。
func (h *DeviceGroupHandler) List(w http.ResponseWriter, r *http.Request) {
	q := dto.ParseDeviceGroupListQuery(r.URL.Query())
	page, err := h.svc.List(r.Context(), q)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// Create POST /api/device-groups（AdminGuard）。
func (h *DeviceGroupHandler) Create(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.DeviceGroupUpsertRequest](w, r)
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

// StrategyTargets GET /api/device-groups/strategy-targets
// （Perm(strategies.assign)；scope 复取在服务层）。
func (h *DeviceGroupHandler) StrategyTargets(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	page, err := h.svc.StrategyTargets(r.Context(), ident.UserGuid, dto.ParsePageQuery(r.URL.Query()))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// Update PATCH /api/device-groups/{guid}（AdminGuard）。
func (h *DeviceGroupHandler) Update(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.DeviceGroupUpsertRequest](w, r)
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

// Delete DELETE /api/device-groups/{guid}（AdminGuard）。成功响应空对象。
func (h *DeviceGroupHandler) Delete(w http.ResponseWriter, r *http.Request) {
	err := h.svc.Delete(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct{}{})
}

// AddDevices POST /api/device-groups/{guid}（AdminGuard；body 为裸数组
// peer.id[]，openapi minItems:1）。
func (h *DeviceGroupHandler) AddDevices(w http.ResponseWriter, r *http.Request) {
	ids, ok := decodeStringArray(w, r)
	if !ok {
		return
	}
	res, err := h.svc.AddDevices(r.Context(), r.PathValue("guid"), ids)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// RemoveDevices DELETE /api/device-groups/{guid}/devices（AdminGuard；
// body 为裸数组 peer.id[]）。
func (h *DeviceGroupHandler) RemoveDevices(w http.ResponseWriter, r *http.Request) {
	ids, ok := decodeStringArray(w, r)
	if !ok {
		return
	}
	res, err := h.svc.RemoveDevices(r.Context(), r.PathValue("guid"), ids)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// decodeStringArray 解析裸数组请求体（add/remove devices 的 body 为
// peer.id[]；httpx.DecodeJSON 的 Struct 校验仅适用于结构体，数组体
// 在此单独收口：JSON 解析失败统一 400 "Invalid request body"）。
func decodeStringArray(w http.ResponseWriter, r *http.Request) ([]string, bool) {
	var ids []string
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ids); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "Invalid request body")
		return nil, false
	}
	return ids, true
}
