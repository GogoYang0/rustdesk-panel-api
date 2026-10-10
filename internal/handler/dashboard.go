package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	dashboardsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/dashboard"
)

// DashboardHandler 仪表盘域端点（M3 T04）：overview 聚合与 trends
// 逐日序列；双端点 SuperAdmin 档在路由（403 文案由 rbac 中间件统一）。
type DashboardHandler struct {
	svc *dashboardsvc.Service
}

// NewDashboardHandler 构建 handler。
func NewDashboardHandler(svc *dashboardsvc.Service) *DashboardHandler {
	return &DashboardHandler{svc: svc}
}

// Overview GET /api/dashboard（SuperAdmin）：设计事实⑥口径聚合。
func (h *DashboardHandler) Overview(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.Overview(r.Context())
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// Trends GET /api/dashboard/trends（SuperAdmin）：range ∈ 7d|30d|90d
// （spec enum；非法值 → 400，缺省 7d 由服务层承担）。
func (h *DashboardHandler) Trends(w http.ResponseWriter, r *http.Request) {
	var rangeParam *string
	if v := r.URL.Query().Get("range"); v != "" {
		switch v {
		case "7d", "30d", "90d":
			rangeParam = &v
		default:
			httpx.Fail(w, http.StatusBadRequest, "Invalid request parameters")
			return
		}
	}
	res, err := h.svc.Trends(r.Context(), rangeParam)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
