// Package handler 本文件：设备端协议 handler（设计 §2）——
// POST /api/heartbeat（JSON 条件键响应）与 POST /api/sysinfo
// （text/plain 恒 200：SYSINFO_UPDATED / ID_NOT_FOUND）。
// 两端点均为公开路由（无 JWT），设备维度限流在路由注册处前置。
package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	devicesvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/device"
)

// HeartbeatHandler 设备端协议端点。
type HeartbeatHandler struct {
	heartbeat *devicesvc.HeartbeatService
	sysinfo   *devicesvc.SysinfoService
}

// NewHeartbeatHandler 构建 handler。
func NewHeartbeatHandler(heartbeat *devicesvc.HeartbeatService, sysinfo *devicesvc.SysinfoService) *HeartbeatHandler {
	return &HeartbeatHandler{heartbeat: heartbeat, sysinfo: sysinfo}
}

// Heartbeat POST /api/heartbeat（公开 + 设备维度限流 10/min）。
// 未知字段 400（DisallowUnknownFields = forbidNonWhitelisted 语义）。
func (h *HeartbeatHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.HeartbeatRequest](w, r)
	if !ok {
		return
	}
	resp, err := h.heartbeat.Handle(r.Context(), *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Sysinfo POST /api/sysinfo（公开 + 设备维度限流 5/min）。
// 响应恒为 text/plain 且 HTTP 200：SYSINFO_UPDATED（已注册并更新）或
// ID_NOT_FOUND（设备未注册，不自动注册）。
func (h *HeartbeatHandler) Sysinfo(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.SysinfoRequest](w, r)
	if !ok {
		return
	}
	found, err := h.sysinfo.Upsert(r.Context(), *req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	if found {
		httpx.WriteText(w, http.StatusOK, devicesvc.SysinfoUpdated)
		return
	}
	httpx.WriteText(w, http.StatusOK, devicesvc.SysinfoNotFound)
}
