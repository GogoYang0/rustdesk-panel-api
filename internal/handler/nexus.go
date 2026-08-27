// Package handler 本文件：nexus 域 handler（设计事实⑤，M3 T06）。
//
// 9 端点：GitHub 设备码绑定（login/status/bind-status/bind）+ 定制构建
// （builds 提交/列表/取消 + 产物清单/下载）。POST builds → 201、DELETE
// builds/:uuid → 204 为 M1 "POST 恒 200" 的两处例外（共享知识 17）；
// 产物下载经 safeJoin 防穿越（rel 含 .. → 400 Invalid path，批复 #8）。
package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	panelDTO "github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/service/nexus"
)

// 固定文案（共享知识 16，逐字节禁改）。
const (
	// msgInvalidPath safeJoin 穿越面 / 文件名白名单未通过 → 400。
	msgInvalidPath = "Invalid path"
)

// NexusHandler nexus 域 handler。
type NexusHandler struct {
	svc *nexus.NexusService
}

// NewNexusHandler 构建 handler。
func NewNexusHandler(svc *nexus.NexusService) *NexusHandler {
	return &NexusHandler{svc: svc}
}

// ident 当前请求身份（JWT 中间件保证非 nil；防御兜底 401）。
func (h *NexusHandler) ident(w http.ResponseWriter, r *http.Request) (string, bool) {
	ident := middleware.IdentityFromContext(r.Context())
	if ident == nil {
		httpx.ErrUnauthorized(w, "authentication required")
		return "", false
	}
	return ident.UserGuid, true
}

// Login POST /api/nexus/auth/login：发起设备码登录。
func (h *NexusHandler) Login(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	payload, err := h.svc.Login(r.Context(), actor)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// Status GET /api/nexus/auth/status?login_id=...：轮询授权态（授权完成落库）。
func (h *NexusHandler) Status(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	loginID := r.URL.Query().Get("login_id")
	if loginID == "" {
		httpx.ErrBadRequest(w, "login_id is required")
		return
	}
	payload, err := h.svc.PollStatus(r.Context(), actor, loginID)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// BindStatus GET /api/nexus/auth/bind-status：读取绑定态（未绑定 {bound:false}）。
func (h *NexusHandler) BindStatus(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	bs, err := h.svc.BindStatus(r.Context(), actor)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, bs)
}

// Unbind DELETE /api/nexus/auth/bind：解绑（删 nexus_tokens 行）。
func (h *NexusHandler) Unbind(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	if err := h.svc.Unbind(r.Context(), actor); err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: "Unbound successfully"})
}

// CreateBuild POST /api/nexus/builds：提交构建（特例 201）。
func (h *NexusHandler) CreateBuild(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	var dto api.NexusGenerateDto
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		httpx.ErrBadRequest(w, "Invalid JSON body")
		return
	}
	// 形状复核（openapi enum）：违例在上游调用前即 400。
	if err := panelDTO.ValidateGenerate(&dto); err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	view, err := h.svc.CreateBuild(r.Context(), actor, dto)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, view)
}

// ListBuilds GET /api/nexus/builds：当前用户构建列表。
func (h *NexusHandler) ListBuilds(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	views, err := h.svc.ListBuilds(r.Context(), actor)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, views)
}

// CancelBuild DELETE /api/nexus/builds/{uuid}：取消构建（特例 204）。
func (h *NexusHandler) CancelBuild(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	buildUuid := r.PathValue("uuid")
	if err := h.svc.CancelBuild(r.Context(), actor, buildUuid); err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListFiles GET /api/nexus/builds/{uuid}/files：产物清单（跨用户 404）。
func (h *NexusHandler) ListFiles(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	buildUuid := r.PathValue("uuid")
	files, err := h.svc.ListFiles(r.Context(), actor, buildUuid)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, files)
}

// Download GET /api/nexus/builds/{uuid}/files/{filename}：产物下载（safeJoin）。
//
// 文件名白名单（批复 #8）：先经 panelDTO.SanitizeFilename 精确过滤，仅接受
// ^[A-Za-z0-9._-]{1,255}$ 的字面量——从构造上排除 ".."、绝对路径、
// CR/LF/引号等首部注入字符。未通过 → 400 Invalid path（固定文案，
// 共享知识 16）。storage.SafeJoin 仍为第二道防线（纵深防御）。
func (h *NexusHandler) Download(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	buildUuid := r.PathValue("uuid")
	safeName := panelDTO.SanitizeFilename(r.PathValue("filename"))
	if safeName == "" {
		httpx.Fail(w, http.StatusBadRequest, msgInvalidPath)
		return
	}
	data, err := h.svc.DownloadFile(r.Context(), actor, buildUuid, safeName)
	if err != nil {
		if errors.Is(err, nexus.ErrInvalidPath) {
			httpx.Fail(w, http.StatusBadRequest, msgInvalidPath)
			return
		}
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteBinary(w, safeName, data)
}
