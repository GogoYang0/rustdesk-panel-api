// Package handler 本文件：oidc-providers 域 handler（设计事实⑧，M3 T07）。
//
// 8 端点（全 AdminGuard）：列表分页、创建（POST=200）、详情、部分更新、
// 删除、sort（body=guid 数组）、toggle、test（discovery）。
// 响应含 clientSecret 明文——参考即如此，复刻。
package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	oidcadmin "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/oidcadmin"
)

// 固定文案（共享知识 16，逐字节禁改）。
const msgOidcProviderDeleted = "OIDC provider deleted"

// msgOidcProviderSorted sort 成功文案（MessageResponse 契约）。
const msgOidcProviderSorted = "Updated successfully"

// OidcAdminHandler oidc-providers 域 handler。
type OidcAdminHandler struct {
	providers *oidcadmin.ProviderService
}

// NewOidcAdminHandler 构建 handler。
func NewOidcAdminHandler(providers *oidcadmin.ProviderService) *OidcAdminHandler {
	return &OidcAdminHandler{providers: providers}
}

// List GET /api/oidc-providers：分页 {data,total}，priority ASC + name ASC。
func (h *OidcAdminHandler) List(w http.ResponseWriter, r *http.Request) {
	current := queryIntDefault(r, "current", 1)
	pageSize := queryIntDefault(r, "pageSize", 0)
	view, err := h.providers.List(r.Context(), current, pageSize)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// Create POST /api/oidc-providers：创建（HTTP 200，非 201）；重名 400。
func (h *OidcAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.OidcProviderUpsertDto](w, r)
	if !ok {
		return
	}
	view, err := h.providers.Create(r.Context(), req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// GetOne GET /api/oidc-providers/{guid}。
func (h *OidcAdminHandler) GetOne(w http.ResponseWriter, r *http.Request) {
	view, err := h.providers.Get(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// Update PATCH /api/oidc-providers/{guid}：issuer 变更清 provider 缓存。
func (h *OidcAdminHandler) Update(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[dto.OidcProviderUpsertDto](w, r)
	if !ok {
		return
	}
	view, err := h.providers.Update(r.Context(), r.PathValue("guid"), req)
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// Delete DELETE /api/oidc-providers/{guid} → {message:"OIDC provider deleted"}。
func (h *OidcAdminHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.providers.Delete(r.Context(), r.PathValue("guid")); err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: msgOidcProviderDeleted})
}

// Sort PATCH /api/oidc-providers/sort：body = guid 数组，顺序即 priority。
//
// 数组请求体不走 httpx.DecodeJSON（validator.Struct 对切片无意义且会
// 误报），改由本方法直接解码（未知字段语义对数组体不适用）。
func (h *OidcAdminHandler) Sort(w http.ResponseWriter, r *http.Request) {
	var guids []string
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&guids); err != nil {
		httpx.Fail(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if err := h.providers.Sort(r.Context(), guids); err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: msgOidcProviderSorted})
}

// Toggle PATCH /api/oidc-providers/{guid}/toggle。
func (h *OidcAdminHandler) Toggle(w http.ResponseWriter, r *http.Request) {
	view, err := h.providers.Toggle(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// Test POST /api/oidc-providers/{guid}/test：discovery 验证，恒 200
// {success,message,endpoints?}；404 仅用于 provider 不存在。
func (h *OidcAdminHandler) Test(w http.ResponseWriter, r *http.Request) {
	view, err := h.providers.Test(r.Context(), r.PathValue("guid"))
	if err != nil {
		rbac.WriteStatusError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// queryIntDefault 读取可选整数查询参数（解析失败或缺失返回 def）。
func queryIntDefault(r *http.Request, name string, def int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return parsed
}
