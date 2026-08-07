// Package handler 本文件：策略域 handler（设计 §1.6 strategy 档 10
// 端点）：CRUD（Perm(strategies.view/create/edit/delete)）、candidates/
// target-candidates/assignments/assign/unassign（Perm(strategies.assign)；
// 路由策略由注册处声明，scope/资源复核在服务层）。
package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	strategysvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/strategy"
)

// StrategyHandler 策略域端点。
type StrategyHandler struct {
	svc *strategysvc.Service
}

// NewStrategyHandler 构建 handler。
func NewStrategyHandler(svc *strategysvc.Service) *StrategyHandler {
	return &StrategyHandler{svc: svc}
}

// List GET /api/strategies（Perm(strategies.view)）。
func (h *StrategyHandler) List(w http.ResponseWriter, r *http.Request) {
	q := dto.ParseStrategyListQuery(r.URL.Query())
	page, err := h.svc.List(r.Context(), q)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// Get GET /api/strategies/{guid}（Perm(strategies.view)）。
func (h *StrategyHandler) Get(w http.ResponseWriter, r *http.Request) {
	view, err := h.svc.Get(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// Create POST /api/strategies（Perm(strategies.create)）。
func (h *StrategyHandler) Create(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.StrategyUpsertRequest](w, r)
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

// Update PATCH /api/strategies/{guid}（Perm(strategies.edit)）。
func (h *StrategyHandler) Update(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.StrategyUpsertRequest](w, r)
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

// Delete DELETE /api/strategies/{guid}（Perm(strategies.delete)）。
// 成功响应空对象。
func (h *StrategyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	err := h.svc.Delete(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, struct{}{})
}

// Candidates GET /api/strategies/candidates（Perm(strategies.assign)）。
func (h *StrategyHandler) Candidates(w http.ResponseWriter, r *http.Request) {
	page, err := h.svc.Candidates(r.Context(), dto.ParsePageQuery(r.URL.Query()))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// TargetCandidates GET /api/strategies/target-candidates
// （Perm(strategies.assign)；target_type 必填，device/user 两形态）。
func (h *StrategyHandler) TargetCandidates(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	q := dto.ParseTargetQuery(r.URL.Query())
	page, err := h.svc.TargetCandidates(r.Context(), ident.UserGuid, q.TargetType, q.PaginationQuery)
	h.writeTargetPage(w, page, err)
}

// Assignments GET /api/strategies/{guid}/assignments
// （Perm(strategies.assign)；target_type 必填，三形态）。
func (h *StrategyHandler) Assignments(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	q := dto.ParseTargetQuery(r.URL.Query())
	page, err := h.svc.Assignments(r.Context(), ident.UserGuid, r.PathValue("guid"), q.TargetType, q.PaginationQuery)
	h.writeTargetPage(w, page, err)
}

// Assign POST /api/strategies/{guid}/assign（Perm(strategies.assign)）。
// 部分成功亦 200 {success, errors}。
func (h *StrategyHandler) Assign(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.AssignRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.Assign(r.Context(), ident.UserGuid, r.PathValue("guid"), req.TargetType, req.TargetGuids)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// Unassign POST /api/strategies/{guid}/unassign（Perm(strategies.assign)）。
func (h *StrategyHandler) Unassign(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.AssignRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.Unassign(r.Context(), ident.UserGuid, r.PathValue("guid"), req.TargetType, req.TargetGuids)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// writeTargetPage 目标形态 oneOf 序列化（恰好一个成员非 nil）。
func (h *StrategyHandler) writeTargetPage(w http.ResponseWriter, page strategysvc.TargetPage, err error) {
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	switch {
	case page.Devices != nil:
		httpx.WriteJSON(w, http.StatusOK, page.Devices)
	case page.Users != nil:
		httpx.WriteJSON(w, http.StatusOK, page.Users)
	default:
		httpx.WriteJSON(w, http.StatusOK, page.Groups)
	}
}
