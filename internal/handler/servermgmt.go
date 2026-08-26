// Package handler 本文件：服务器管理域 handler（设计事实③，M3 T06）。
//
// 10 端点：列表握手 + 经 agent 转发的 peers/sessions/服务配置/日志/动作/
// 封禁。转发结果与错误映射矩阵由 service/servermgmt 统一收口；handler 仅
// 做身份抽取、请求体透传、JSON 回写与 mutate 审计。
package handler

import (
	"io"
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	mgmt "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/servermgmt"
)

// ServerMGMTHandler 服务器管理域 handler。
type ServerMGMTHandler struct {
	client *mgmt.Client
	audit  *rbac.AuditService
}

// NewServerMGMTHandler 构建 handler（audit 可为 nil，nil 时跳过审计）。
func NewServerMGMTHandler(client *mgmt.Client, audit *rbac.AuditService) *ServerMGMTHandler {
	return &ServerMGMTHandler{client: client, audit: audit}
}

// ident 当前请求身份（JWT 中间件保证非 nil；防御兜底 401）。
func (h *ServerMGMTHandler) ident(w http.ResponseWriter, r *http.Request) (string, bool) {
	ident := middleware.IdentityFromContext(r.Context())
	if ident == nil {
		httpx.ErrUnauthorized(w, "authentication required")
		return "", false
	}
	return ident.UserGuid, true
}

// forward 通用转发：读请求体（如需）→ 调 Client.Forward → 写回或出包络；
// mutate 端点记录审计。
func (h *ServerMGMTHandler) forward(w http.ResponseWriter, r *http.Request, nodeID, path string, mutate bool, action string) {
	actor, ok := h.ident(w, r)
	if !ok {
		return
	}
	var body []byte
	if r.Body != nil && r.ContentLength != 0 {
		b, err := io.ReadAll(io.LimitReader(r.Body, int64(mgmt.MaxForwardBody())+1))
		if err != nil {
			httpx.ErrBadRequest(w, "Invalid request body")
			return
		}
		body = b
	}
	status, raw, err := h.client.Forward(r.Context(), r.Method, nodeID, path, body)
	if err != nil {
		if mutate && h.audit != nil {
			h.audit.RecordDenied(r.Context(), rbac.AuditRecord{
				ActorUserGuid: actor, TargetType: "server", TargetGuid: nodeID,
				Action: action, Reason: err.Error(), AfterState: string(body),
			})
		}
		rbac.WriteStatusError(w, err)
		return
	}
	if mutate && h.audit != nil {
		h.audit.Record(r.Context(), rbac.AuditRecord{
			ActorUserGuid: actor, TargetType: "server", TargetGuid: nodeID,
			Action: action, Result: rbac.AuditResultAllowed, AfterState: string(body),
		})
	}
	writeForward(w, status, raw)
}

// writeForward 回写上游转发结果：204 无体；其余按上游状态码 + JSON 字节。
func writeForward(w http.ResponseWriter, status int, body []byte) {
	if status == http.StatusNoContent {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

// List GET /api/servers：并发 /v1/status 握手（不可达节点单独标记）。
func (h *ServerMGMTHandler) List(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.ident(w, r); !ok {
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.client.ListStatus(r.Context()))
}

// Peers GET /api/servers/{node}/peers。
func (h *ServerMGMTHandler) Peers(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, r.PathValue("node"), "/v1/peers", false, "list-peers")
}

// Sessions GET /api/servers/{node}/sessions。
func (h *ServerMGMTHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, r.PathValue("node"), "/v1/sessions", false, "list-sessions")
}

// Disconnect DELETE /api/servers/{node}/sessions/{uuid}。
func (h *ServerMGMTHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	node := r.PathValue("node")
	h.forward(w, r, node, "/v1/sessions/"+r.PathValue("uuid"), true, "disconnect-session")
}

// ServiceConfig GET|PUT /api/servers/{node}/services/{service}/config。
func (h *ServerMGMTHandler) ServiceConfig(w http.ResponseWriter, r *http.Request) {
	path := "/v1/services/" + r.PathValue("service") + "/config"
	h.forward(w, r, r.PathValue("node"), path, r.Method == http.MethodPut, "service-config")
}

// ServiceLogs GET /api/servers/{node}/services/{service}/logs。
func (h *ServerMGMTHandler) ServiceLogs(w http.ResponseWriter, r *http.Request) {
	path := "/v1/services/" + r.PathValue("service") + "/logs"
	h.forward(w, r, r.PathValue("node"), path, false, "service-logs")
}

// ServiceAction POST /api/servers/{node}/services/{service}/{action}。
func (h *ServerMGMTHandler) ServiceAction(w http.ResponseWriter, r *http.Request) {
	path := "/v1/services/" + r.PathValue("service") + "/" + r.PathValue("action")
	h.forward(w, r, r.PathValue("node"), path, true, "service-action")
}

// Bans GET|PUT /api/servers/{node}/bans。
func (h *ServerMGMTHandler) Bans(w http.ResponseWriter, r *http.Request) {
	h.forward(w, r, r.PathValue("node"), "/v1/bans", r.Method == http.MethodPut, "bans")
}
