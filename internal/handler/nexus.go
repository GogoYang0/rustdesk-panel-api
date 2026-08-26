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
	"path/filepath"
	"strings"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/service/nexus"
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
	uuid := r.PathValue("uuid")
	if err := h.svc.CancelBuild(r.Context(), actor, uuid); err != nil {
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
	uuid := r.PathValue("uuid")
	files, err := h.svc.ListFiles(r.Context(), actor, uuid)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, files)
}

// Download GET /api/nexus/builds/{uuid}/files/{filename}：产物下载（safeJoin）。
func (h *NexusHandler) Download(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	uuid := r.PathValue("uuid")
	filename := r.PathValue("filename")
	// safeJoin 防穿越：文件名含 .. 段或绝对路径 → 400 Invalid path（批复 #8）。
	if filename == "" || strings.Contains(filename, "..") || filepath.IsAbs(filename) {
		httpx.Fail(w, http.StatusBadRequest, "Invalid path")
		return
	}
	data, err := h.svc.DownloadFile(r.Context(), actor, uuid, filename)
	if err != nil {
		if errors.Is(err, nexus.ErrInvalidPath) {
			httpx.Fail(w, http.StatusBadRequest, "Invalid path")
			return
		}
		rbac.WriteStatusError(w, err)
		return
	}
	// 文件名白名单剥离 CR/LF/引号（批复 #8：消除 header 注入面）。
	httpx.WriteBinary(w, sanitizeHeaderFilename(filename), data)
}

// sanitizeHeaderFilename 剥离响应头注入字符（CR/LF/引号/控制字符）。
func sanitizeHeaderFilename(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch r {
		case '\r', '\n', '"', '\\', '/', ';':
			continue
		default:
			if r < 0x20 {
				continue
			}
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return "download"
	}
	return out
}
