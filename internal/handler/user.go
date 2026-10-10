package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	usersvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/user"
)

// UserHandler 用户域端点：M1 自身资料/头像（profile/avatar）+
// M3 管理端用户 CRUD/批量/邀请/安全（svc）。
type UserHandler struct {
	profile *usersvc.ProfileService
	avatar  *usersvc.AvatarService
	svc     *usersvc.Service
}

// NewUserHandler 构建 handler。
func NewUserHandler(profile *usersvc.ProfileService, avatar *usersvc.AvatarService, svc *usersvc.Service) *UserHandler {
	return &UserHandler{profile: profile, avatar: avatar, svc: svc}
}

// writeUserError 用户域错误出口：业务错误（ServiceError，message 为
// 对象/纯文本形态）与 RBAC 决策错误（StatusError，纯文本形态）双源。
func writeUserError(w http.ResponseWriter, err error) {
	var se *authsvc.ServiceError
	if errors.As(err, &se) {
		httpx.Fail(w, se.Status, se.Message)
		return
	}
	rbac.WriteStatusError(w, err)
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

// ---- M3 管理端用户域（T03）----

// ListUsers GET /api/users（users.view）：admin 分支 status 缺省 '1'。
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	var statusParam *string
	if q := r.URL.Query(); q.Has("status") {
		v := q.Get("status")
		statusParam = &v
	}
	res, err := h.svc.ListUsers(r.Context(), ident.UserGuid, ident.IsAdmin, statusParam)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// CreateUser POST /api/users（users.create）。
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.CreateUserRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.CreateUser(r.Context(), ident.UserGuid, *req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// InviteUser POST /api/users/invite（users.create + 条件 membership）。
func (h *UserHandler) InviteUser(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.InviteUserRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.Invite(r.Context(), ident.UserGuid, *req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// VerifyInvitation POST /api/invitations/verify（Public，无身份）。
func (h *UserHandler) VerifyInvitation(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.InvitationTokenRequest](w, r)
	if !ok {
		return
	}
	res, err := h.svc.Verify(r.Context(), req.Token)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// AcceptInvitation POST /api/invitations/accept（Public，无身份）。
func (h *UserHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.InvitationAcceptRequest](w, r)
	if !ok {
		return
	}
	res, err := h.svc.Accept(r.Context(), *req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// BatchStatus PATCH /api/users/batch/status（users.status）。
func (h *UserHandler) BatchStatus(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.BatchStatusRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.BatchStatus(r.Context(), ident.UserGuid, *req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// BatchSecurity PATCH /api/users/batch/security（users.security）。
func (h *UserHandler) BatchSecurity(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.BatchSecurityRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.BatchSecurity(r.Context(), ident.UserGuid, *req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// BatchSessions DELETE /api/users/batch/sessions（users.force_logout，
// DELETE 携 body）。
func (h *UserHandler) BatchSessions(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.BatchSessionsRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.BatchSessions(r.Context(), ident.UserGuid, *req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// GetUser GET /api/users/{guid}（users.view）。
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	res, err := h.svc.GetUser(r.Context(), r.PathValue("guid"))
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// UpdateUser PATCH /api/users/{guid}（无顶层权限码，按字段分权）。
func (h *UserHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.UpdateUserRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.UpdateUser(r.Context(), ident.UserGuid, r.PathValue("guid"), *req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// DeleteUser DELETE /api/users/{guid}（users.delete）。
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.DeleteUser(r.Context(), ident.UserGuid, r.PathValue("guid"))
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// UpdateUserSecurity PATCH /api/users/{guid}/security（users.security）。
func (h *UserHandler) UpdateUserSecurity(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.UpdateUserSecurityRequest](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.UpdateUserSecurity(r.Context(), ident.UserGuid, r.PathValue("guid"), *req)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ForceLogout DELETE /api/users/{guid}/sessions（users.force_logout）。
func (h *UserHandler) ForceLogout(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.svc.ForceLogout(r.Context(), ident.UserGuid, r.PathValue("guid"))
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ListAdminUsers GET /api/admin/users（users.view；十过滤分页，
// current/pageSize 契约缺省 1/20，非法整数 → 400）。
func (h *UserHandler) ListAdminUsers(w http.ResponseWriter, r *http.Request) {
	p := api.ListAdminUsersParams{}
	q := r.URL.Query()
	parsePos := func(key string) (*int, bool) {
		v := q.Get(key)
		if v == "" {
			return nil, true
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			httpx.Fail(w, http.StatusBadRequest, "Invalid request parameters")
			return nil, false
		}
		return &n, true
	}
	var ok bool
	if p.Current, ok = parsePos("current"); !ok {
		return
	}
	if p.PageSize, ok = parsePos("pageSize"); !ok {
		return
	}
	strPtr := func(key string) *string {
		if !q.Has(key) {
			return nil
		}
		v := q.Get(key)
		return &v
	}
	p.Status = strPtr("status")
	p.Name = strPtr("name")
	p.Email = strPtr("email")
	if v := q.Get("is_admin"); v != "" {
		ia := api.ListAdminUsersParamsIsAdmin(v)
		p.IsAdmin = &ia
	}
	p.ThirdAuthType = strPtr("third_auth_type")
	p.StrategyName = strPtr("strategy_name")
	p.UserGroupGuid = strPtr("user_group_guid")
	p.UserGroupName = strPtr("user_group_name")

	res, err := h.svc.ListAdminUsers(r.Context(), p)
	if err != nil {
		writeUserError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
