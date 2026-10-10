// Package handler 本文件：update-check 域 handler（设计事实④，M3 T07）。
//
// 1 端点（AdminGuard）：GET /api/update-check；查询参数 frontend_version
// 仅影响响应 frontend 分支比对。
package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	updatechecksvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/updatecheck"
)

// UpdateCheckHandler 版本更新检查 handler。
type UpdateCheckHandler struct {
	service *updatechecksvc.Service
}

// NewUpdateCheckHandler 构建 handler。
func NewUpdateCheckHandler(service *updatechecksvc.Service) *UpdateCheckHandler {
	return &UpdateCheckHandler{service: service}
}

// Get GET /api/update-check（AdminGuard）。
func (h *UpdateCheckHandler) Get(w http.ResponseWriter, r *http.Request) {
	frontendVersion := r.URL.Query().Get("frontend_version")
	view, err := h.service.Get(r.Context(), frontendVersion)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}
