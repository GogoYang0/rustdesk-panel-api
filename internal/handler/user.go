package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	usersvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/user"
)

// UserHandler 用户自身端点：资料、改密、头像与静态头像服务。
type UserHandler struct {
	profile *usersvc.ProfileService
	avatar  *usersvc.AvatarService
}

// NewUserHandler 构建 handler。
func NewUserHandler(profile *usersvc.ProfileService, avatar *usersvc.AvatarService) *UserHandler {
	return &UserHandler{profile: profile, avatar: avatar}
}

// UpdateMe PATCH /api/users/me（JWT）。
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.UpdateMeRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	payload, err := h.profile.UpdateMe(r.Context(), ident.UserGuid, *req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// ChangePassword PATCH /api/users/me/password（JWT，限流 5）。
func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.ChangePasswordRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.profile.ChangePassword(r.Context(), ident.UserGuid, *req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// UploadAvatar POST /api/users/me/avatar（JWT，限流 10）。
// multipart 字段 avatar；≤2MB、仅 webp。
func (h *UserHandler) UploadAvatar(w http.ResponseWriter, r *http.Request) {
	// MaxBytesReader 兜底请求体总量（2MB + multipart 开销余量）。
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20+64<<10)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		httpx.ErrBadRequest(w, "Avatar must be at most 2MB and multipart encoded")
		return
	}
	file, header, err := r.FormFile("avatar")
	if err != nil {
		httpx.ErrBadRequest(w, "Avatar file is required")
		return
	}
	defer func() { _ = file.Close() }()

	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.avatar.Upload(r.Context(), ident.UserGuid, file, header.Size)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// DeleteAvatar DELETE /api/users/me/avatar（JWT，限流 10）。
func (h *UserHandler) DeleteAvatar(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.avatar.Delete(r.Context(), ident.UserGuid)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// GetAvatar GET /api/avatars/{filename}（公开，限流 60）。
// 白名单正则 + resolve 双重防穿越；不存在输出 404 包络。
func (h *UserHandler) GetAvatar(w http.ResponseWriter, r *http.Request) {
	if !h.avatar.Serve(w, r.PathValue("filename")) {
		httpx.ErrNotFound(w, "Avatar not found")
	}
}
