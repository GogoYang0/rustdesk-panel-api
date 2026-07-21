// Package handler HTTP 出入口层：绑定 → 服务编排 → 包络输出。
//
// 约定：成功直接 WriteJSON（POST 一律 200）；错误经 writeServiceError
// 统一映射为 NestJS 兼容包络（共享知识 1/13）。
package handler

import (
	"errors"
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// AuthHandler 认证域端点：login/logout/currentUser、2FA、passkey、sessions。
type AuthHandler struct {
	login   *authsvc.AuthService
	tfa     *authsvc.TfaService
	passkey *authsvc.PasskeyService
	tokens  *authsvc.TokenService
}

// NewAuthHandler 构建 handler。
func NewAuthHandler(login *authsvc.AuthService, tfa *authsvc.TfaService,
	passkey *authsvc.PasskeyService, tokens *authsvc.TokenService) *AuthHandler {
	return &AuthHandler{login: login, tfa: tfa, passkey: passkey, tokens: tokens}
}

// Login POST /api/login（公开，限流 5/min）。
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.LoginJSONRequestBody](w, r)
	if !ok {
		return
	}
	resp, err := h.login.Login(r.Context(), req)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// Logout POST /api/logout（JWT）。
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	var req *api.LogoutJSONRequestBody
	if r.Body != nil && r.ContentLength != 0 {
		body, ok := httpx.DecodeJSON[api.LogoutJSONRequestBody](w, r)
		if !ok {
			return
		}
		req = body
	}
	if err := h.login.Logout(r.Context(), ident, req); err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: "Logged out"})
}

// CurrentUser POST /api/currentUser（JWT）。
func (h *AuthHandler) CurrentUser(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	payload, err := h.login.CurrentUser(r.Context(), ident.UserGuid)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// SetupTfa POST /api/2fa/setup（JWT）。
func (h *AuthHandler) SetupTfa(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.tfa.Setup(r.Context(), ident.UserGuid)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// VerifyTfa POST /api/2fa/verify（JWT）。
func (h *AuthHandler) VerifyTfa(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.VerifyTfaJSONRequestBody](w, r)
	if !ok {
		return
	}
	if len(req.TfaCode) != 6 {
		httpx.ErrBadRequest(w, "tfaCode must be 6 characters")
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.tfa.VerifyAndBind(r.Context(), ident.UserGuid, req.TfaCode)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// DisableTfa DELETE /api/2fa（JWT）。
func (h *AuthHandler) DisableTfa(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.DisableTfaJSONRequestBody](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.tfa.Disable(r.Context(), ident.UserGuid, req.TfaCode)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// PasskeyRegisterBegin POST /api/passkey/register/begin（JWT）。
func (h *AuthHandler) PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	options, err := h.passkey.BeginRegistration(r.Context(), ident.UserGuid)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, options)
}

// PasskeyRegisterVerify POST /api/passkey/register/verify（JWT）。
func (h *AuthHandler) PasskeyRegisterVerify(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.PasskeyRegisterVerifyJSONRequestBody](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.passkey.VerifyRegistration(r.Context(), ident.UserGuid, req.Response, deref(req.Name))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// PasskeyAuthBegin POST /api/passkey/auth/begin（公开，限流 10/min）。
func (h *AuthHandler) PasskeyAuthBegin(w http.ResponseWriter, r *http.Request) {
	res, err := h.passkey.BeginAuthLogin(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// PasskeyAuthVerify POST /api/passkey/auth/verify（公开，限流 10/min）。
func (h *AuthHandler) PasskeyAuthVerify(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.PasskeyAuthVerifyJSONRequestBody](w, r)
	if !ok {
		return
	}
	res, err := h.passkey.VerifyAuthLogin(r.Context(), dto.VerifyAuthRequest{
		Secret:   req.Secret,
		Response: req.Response,
		Device:   dto.DeviceFromRequest(deref(req.Id), deref(req.Uuid), req.DeviceInfo),
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// PasskeyList GET /api/passkey/list（JWT）。
func (h *AuthHandler) PasskeyList(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	views, err := h.passkey.List(r.Context(), ident.UserGuid)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, views)
}

// PasskeyDelete DELETE /api/passkey/{guid}（JWT）。
func (h *AuthHandler) PasskeyDelete(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	if err := h.passkey.Delete(r.Context(), ident.UserGuid, r.PathValue("guid")); err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: "Passkey deleted"})
}

// PasskeyTfaToggle POST /api/passkey/tfa（JWT）。
func (h *AuthHandler) PasskeyTfaToggle(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.PasskeyTfaToggleJSONRequestBody](w, r)
	if !ok {
		return
	}
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.passkey.ToggleTfa(r.Context(), ident.UserGuid, req.Enabled)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// SessionsList GET /api/sessions（JWT，createdAt 倒序）。
func (h *AuthHandler) SessionsList(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	sessions, err := h.tokens.ListSessions(r.Context(), ident.UserGuid)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sessions)
}

// SessionRevoke DELETE /api/sessions/{jti}（JWT）。
func (h *AuthHandler) SessionRevoke(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	if err := h.tokens.RevokeSession(r.Context(), ident.UserGuid, r.PathValue("jti")); err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: "Session revoked"})
}

// deref 安全解引用字符串指针。
func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// writeServiceError 服务错误 → 包络映射：
// ServiceError 按语义输出；未知错误固定 500 不泄内部细节（共享知识 13）。
func writeServiceError(w http.ResponseWriter, err error) {
	if err == nil {
		return
	}
	var se *authsvc.ServiceError
	if errors.As(err, &se) {
		httpx.Fail(w, se.Status, se.Message)
		return
	}
	httpx.ErrInternal(w)
}
