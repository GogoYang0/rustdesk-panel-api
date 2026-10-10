package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	auditsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/audit"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// AuditHandler 审计域端点（M3 T04）：上报三端（Public + per-IP
// 50/min，档位在路由）与查询六端（audit.view / devices.disconnect /
// SuperAdmin，档位在路由）。固定文案契约由服务层承担。
type AuditHandler struct {
	report *auditsvc.ReportService
	query  *auditsvc.QueryService
}

// NewAuditHandler 构建 handler。
func NewAuditHandler(report *auditsvc.ReportService, query *auditsvc.QueryService) *AuditHandler {
	return &AuditHandler{report: report, query: query}
}

// writeAuditError 审计域错误出口（同用户域双源组合）：业务错误
// （ServiceError，404 纯文本 / 400 对象）与 RBAC 决策错误（StatusError）。
func writeAuditError(w http.ResponseWriter, err error) {
	var se *authsvc.ServiceError
	if errors.As(err, &se) {
		httpx.Fail(w, se.Status, se.Message)
		return
	}
	rbac.WriteStatusError(w, err)
}

// ---- 上报端（Public；设备侧直连，无 JWT）----

// ReportConn POST /api/audit/conn：conn upsert 状态机 / note-only
// 定位改备注（设计 §4.2，参考 audit.service.ts 行为基线）。
func (h *AuditHandler) ReportConn(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.ConnAuditReport](w, r)
	if !ok {
		return
	}
	msg, err := h.report.ReportConn(r.Context(), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: msg})
}

// ReportFile POST /api/audit/file：nonce 幂等 + info JSON 解析。
func (h *AuditHandler) ReportFile(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.FileAuditReport](w, r)
	if !ok {
		return
	}
	msg, err := h.report.ReportFile(r.Context(), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: msg})
}

// ReportAlarm POST /api/audit/alarm：nonce 幂等 + info JSON 解析。
func (h *AuditHandler) ReportAlarm(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.AlarmAuditReport](w, r)
	if !ok {
		return
	}
	msg, err := h.report.ReportAlarm(r.Context(), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: msg})
}

// ---- 查询端 ----

// ListActiveConn GET /api/audits/conn/active（devices.disconnect）：
// scope 过滤 + 行内 can_disconnect（actor 身份传入 scope 计算）。
func (h *AuditHandler) ListActiveConn(w http.ResponseWriter, r *http.Request) {
	ident := middleware.IdentityFromContext(r.Context())
	res, err := h.query.ListActive(r.Context(), ident.UserGuid)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ListConn GET /api/audits/conn（audit.view）：过滤 + 分页。
func (h *AuditHandler) ListConn(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := api.ListConnectionAuditsParams{}
	pageOK := parseAuditPage(w, q, &p.Current, &p.PageSize)
	if !pageOK {
		return
	}
	p.PeerId = auditStrFilter(q, "peer_id")
	p.Uuid = auditStrFilter(q, "uuid")
	typeOK := parseAuditInt(w, q, "type", &p.Type)
	if !typeOK {
		return
	}
	startOK := parseAuditTime(w, q, "start", &p.Start)
	if !startOK {
		return
	}
	endOK := parseAuditTime(w, q, "end", &p.End)
	if !endOK {
		return
	}
	res, err := h.query.ListConn(r.Context(), p)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// UpdateConnNote PATCH /api/audits/conn/{id}（SuperAdmin）：仅 note。
func (h *AuditHandler) UpdateConnNote(w http.ResponseWriter, r *http.Request) {
	req, ok := httpx.DecodeJSON[api.ConnNoteUpdate](w, r)
	if !ok {
		return
	}
	msg, err := h.query.UpdateNote(r.Context(), r.PathValue("id"), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, api.MessageResponse{Message: msg})
}

// ListFile GET /api/audits/file（audit.view）：过滤 + 分页。
func (h *AuditHandler) ListFile(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := api.ListFileAuditsParams{}
	if !parseAuditPage(w, q, &p.Current, &p.PageSize) {
		return
	}
	p.PeerId = auditStrFilter(q, "peer_id")
	p.Uuid = auditStrFilter(q, "uuid")
	if !parseAuditInt(w, q, "type", &p.Type) {
		return
	}
	res, err := h.query.ListFile(r.Context(), p)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ListAlarm GET /api/audits/alarm（audit.view）：typ 过滤 + 分页。
func (h *AuditHandler) ListAlarm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := api.ListAlarmAuditsParams{}
	if !parseAuditPage(w, q, &p.Current, &p.PageSize) {
		return
	}
	if !parseAuditInt(w, q, "typ", &p.Typ) {
		return
	}
	p.Uuid = auditStrFilter(q, "uuid")
	res, err := h.query.ListAlarm(r.Context(), p)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ListConsole GET /api/audits/console（audit.view）：result/user_guid
// 过滤 + 分页（M2 console_audits 表查询端）。
func (h *AuditHandler) ListConsole(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := api.ListConsoleAuditsParams{}
	if !parseAuditPage(w, q, &p.Current, &p.PageSize) {
		return
	}
	if v := auditStrFilter(q, "result"); v != nil {
		p.Result = (*api.ListConsoleAuditsParamsResult)(v)
	}
	p.UserGuid = auditStrFilter(q, "user_guid")
	res, err := h.query.ListConsole(r.Context(), p)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ---- 查询参数解析 helper（非法整数/时间 → 400 契约文案）----

// parseAuditPage current/pageSize 解析（CurrentParam/PageSizeParam 为
// int 类型别名——与 *int 同一类型，非法整数 → 400 契约文案）。
func parseAuditPage(w http.ResponseWriter, q url.Values, current, pageSize **int) bool {
	return parseAuditInt(w, q, "current", current) && parseAuditInt(w, q, "pageSize", pageSize)
}

// parseAuditInt 整数查询参数取值（缺失 → 目标保持 nil；非法 → 400
// 写响应并返回 false）。
func parseAuditInt(w http.ResponseWriter, q url.Values, key string, target **int) bool {
	v := q.Get(key)
	if v == "" {
		return true
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "Invalid request parameters")
		return false
	}
	*target = &n
	return true
}

// parseAuditTime RFC3339 时间查询参数取值（缺失 → nil；非法 → 400）。
func parseAuditTime(w http.ResponseWriter, q url.Values, key string, target **time.Time) bool {
	v := q.Get(key)
	if v == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		httpx.Fail(w, http.StatusBadRequest, "Invalid request parameters")
		return false
	}
	*target = &t
	return true
}

// auditStrFilter 字符串查询过滤取值（缺失 → nil）。
func auditStrFilter(q url.Values, key string) *string {
	if !q.Has(key) {
		return nil
	}
	v := q.Get(key)
	return &v
}

// ListLogin GET /api/audits/login（audit.view；GAP2 新表 login_audits
// 查询端）：result/username/start/end 过滤 + 分页。
func (h *AuditHandler) ListLogin(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := api.ListLoginAuditsParams{}
	if !parseAuditPage(w, q, &p.Current, &p.PageSize) {
		return
	}
	if v := auditStrFilter(q, "result"); v != nil {
		p.Result = (*api.ListLoginAuditsParamsResult)(v)
	}
	p.Username = auditStrFilter(q, "username")
	startOK := parseAuditTime(w, q, "start", &p.Start)
	if !startOK {
		return
	}
	endOK := parseAuditTime(w, q, "end", &p.End)
	if !endOK {
		return
	}
	res, err := h.query.ListLogin(r.Context(), p)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}
