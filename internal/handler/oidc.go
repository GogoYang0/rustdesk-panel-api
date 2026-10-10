package handler

import (
	"html/template"
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// OidcHandler OIDC 授权域端点：login-options、auth、auth-query、callback。
type OidcHandler struct {
	flow        *authsvc.OidcFlowService
	successTmpl *template.Template
	errorTmpl   *template.Template
}

// NewOidcHandler 构建 handler（模板解析失败返回错误，装配期暴露）。
func NewOidcHandler(flow *authsvc.OidcFlowService) (*OidcHandler, error) {
	return &OidcHandler{
		flow:        flow,
		successTmpl: mustParseTemplate("callback-success.html"),
		errorTmpl:   mustParseTemplate("callback-error.html"),
	}, nil
}

// LoginOptions GET /api/login-options（公开，限流 20/min）。
// 返回形态对齐参考 OidcController：带 icon 输出对象数组，否则字符串数组。
func (h *OidcHandler) LoginOptions(w http.ResponseWriter, r *http.Request) {
	res, err := h.flow.LoginOptions(r.Context())
	if err != nil {
		writeServiceError(w, err)
		return
	}
	if res.HasIcons {
		httpx.WriteJSON(w, http.StatusOK, res.Items)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res.Names)
}

// RequestAuth POST /api/oidc/auth（公开，限流 5/min）。
func (h *OidcHandler) RequestAuth(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.OidcAuthJSONRequestBody](w, r)
	if !ok {
		return
	}
	res, err := h.flow.RequestAuth(r.Context(), req, h.callbackURL(r))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// QueryAuth GET /api/oidc/auth-query（公开，限流 120/min）。
func (h *OidcHandler) QueryAuth(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		httpx.ErrBadRequest(w, "code is required")
		return
	}
	res, err := h.flow.QueryAuth(r.Context(), code)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// Callback GET /api/oidc/callback（公开）：渲染 HTML 页面
// （客户端模式静态结果页；web 模式带脚本自动跳转，token 走 fragment）。
func (h *OidcHandler) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res, err := h.flow.HandleCallback(r.Context(), dto.CallbackQuery{
		Code:  q.Get("code"),
		State: q.Get("state"),
		Error: q.Get("error"),
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	tmpl := h.errorTmpl
	if res.OK {
		tmpl = h.successTmpl
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := tmpl.Execute(w, res); err != nil {
		// 头部已发出，降级为纯文本错误提示。
		_, _ = w.Write([]byte("<html><body><h1>Render error</h1></body></html>"))
	}
}

// callbackURL 从请求推导对外回调地址（反代场景优先 X-Forwarded-Proto）。
func (h *OidcHandler) callbackURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host + "/api/oidc/callback"
}
