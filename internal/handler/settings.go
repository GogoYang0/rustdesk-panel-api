// Package handler 本文件：settings 域 handler（设计事实④，M3 T07）。
//
// 6 端点：frontend 公开三键（Public）；general/smtp/ldap 读写（AdminGuard）；
// smtp/ldap test（AdminGuard + 5/min，路由层限流）恒 200。掩码约定与
// 404 固定文案由 service/settings 承担。
package handler

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	settingssvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/settings"
)

// SettingsHandler settings 域 handler。
type SettingsHandler struct {
	general  *settingssvc.GeneralService
	smtp     *settingssvc.SmtpService
	ldap     *settingssvc.LdapService
	frontend *settingssvc.FrontendService
}

// NewSettingsHandler 构建 handler。
func NewSettingsHandler(general *settingssvc.GeneralService, smtp *settingssvc.SmtpService,
	ldap *settingssvc.LdapService, frontend *settingssvc.FrontendService) *SettingsHandler {
	return &SettingsHandler{general: general, smtp: smtp, ldap: ldap, frontend: frontend}
}

// writeSettingsError 统一错误出口（业务 StatusError）。
func writeSettingsError(w http.ResponseWriter, err error) {
	rbac.WriteStatusError(w, err)
}

// Frontend GET /api/settings/frontend（Public）。
func (h *SettingsHandler) Frontend(w http.ResponseWriter, r *http.Request) {
	view, err := h.frontend.Get(r.Context())
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// GeneralGet GET /api/settings/general。
func (h *SettingsHandler) GeneralGet(w http.ResponseWriter, r *http.Request) {
	view, err := h.general.Get(r.Context())
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// GeneralPut PUT /api/settings/general：形状校验（defaultLanguage/
// jwtExpiryDays/auditRetentionDays）违例 400。
func (h *SettingsHandler) GeneralPut(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.UpdateGeneralSettingsDto](w, r)
	if !ok {
		return
	}
	if err := dto.ValidateUpdateGeneral(req); err != nil {
		writeSettingsError(w, err)
		return
	}
	view, err := h.general.Update(r.Context(), req)
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// SmtpGet GET /api/settings/smtp：无配置 404 固定文案；pass 恒掩码。
func (h *SettingsHandler) SmtpGet(w http.ResponseWriter, r *http.Request) {
	view, err := h.smtp.Get(r.Context())
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// SmtpPut PUT /api/settings/smtp：pass 命中掩码跳过更新。
func (h *SettingsHandler) SmtpPut(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.SmtpConfigDto](w, r)
	if !ok {
		return
	}
	view, err := h.smtp.Update(r.Context(), req)
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// SmtpTest POST /api/settings/smtp/test：body 可省略；恒 200
// {success,message}（连接失败也是 200 + success:false）。
func (h *SettingsHandler) SmtpTest(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSONOptional[dto.SmtpConfigDto](w, r)
	if !ok {
		return
	}
	view, err := h.smtp.Test(r.Context(), req)
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// LdapGet GET /api/settings/ldap：bindCredentials 恒掩码。
func (h *SettingsHandler) LdapGet(w http.ResponseWriter, r *http.Request) {
	view, err := h.ldap.Get(r.Context())
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// LdapPut PUT /api/settings/ldap：形状校验 + bindCredentials 掩码跳更。
func (h *SettingsHandler) LdapPut(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.LdapConfigDto](w, r)
	if !ok {
		return
	}
	if err := dto.ValidateLdap(req); err != nil {
		writeSettingsError(w, err)
		return
	}
	view, err := h.ldap.Update(r.Context(), req)
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// LdapTest POST /api/settings/ldap/test：body 可省略；恒 200。
func (h *SettingsHandler) LdapTest(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSONOptional[dto.LdapConfigDto](w, r)
	if !ok {
		return
	}
	if req != nil {
		if err := dto.ValidateLdap(req); err != nil {
			writeSettingsError(w, err)
			return
		}
	}
	view, err := h.ldap.Test(r.Context(), req)
	if err != nil {
		writeSettingsError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}
