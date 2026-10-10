// Package handler 本文件：AddressBookHandler——通讯录域 32 端点
// （M3 T05，事实⑦）。兼容怪癖三件套在 legacy 双端点逐字节落位：
// GET 空数据 → 字符串 'null'；POST 失败 → {error} 且 HTTP 仍 200
// （仅此端点 try/catch 语义）；settings 恒 max_peer_one_ab=0。
package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	absvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/addressbook"
)

// 固定文案（共享知识 16，逐字节禁改）。
const (
	msgUpdatedSuccessfully = "Updated successfully"
	msgDeletedSuccessfully = "Deleted successfully"
)

// AddressBookHandler 通讯录域 handler（聚合书/规则/设备/标签/
// legacy 五服务，路由 32 条）。
type AddressBookHandler struct {
	book  *absvc.BookService
	rule  *absvc.RuleService
	peer  *absvc.PeerService
	tag   *absvc.TagService
	legacy *absvc.LegacyService
}

// NewAddressBookHandler 构建通讯录域 handler。
func NewAddressBookHandler(
	book *absvc.BookService,
	rule *absvc.RuleService,
	peer *absvc.PeerService,
	tag *absvc.TagService,
	legacy *absvc.LegacyService,
) *AddressBookHandler {
	return &AddressBookHandler{book: book, rule: rule, peer: peer, tag: tag, legacy: legacy}
}

// ident 当前请求身份（JWT 中间件保证非 nil；防御兜底 401）。
func (h *AddressBookHandler) ident(w http.ResponseWriter, r *http.Request) (string, bool) {
	ident := middleware.IdentityFromContext(r.Context())
	if ident == nil {
		httpx.ErrUnauthorized(w, "authentication required")
		return "", false
	}
	return ident.UserGuid, true
}

// pathGuid 路径参数提取（{guid} 命名段）。
func (h *AddressBookHandler) pathGuid(r *http.Request) string {
	return r.PathValue("guid")
}

// bookQuery 分页书列表查询参数解析（current/pageSize/name/note）。
func (h *AddressBookHandler) bookQuery(w http.ResponseWriter, r *http.Request) (dto.BookListQuery, bool) {
	q := r.URL.Query()
	var out dto.BookListQuery
	out.Name = q.Get("name")
	out.Note = q.Get("note")
	if !parseAuditPage(w, q, &out.Current, &out.PageSize) {
		return dto.BookListQuery{}, false
	}
	return out, true
}

// writeMessage 固定文案响应（{message: "..."}）。
func writeMessage(w http.ResponseWriter, text string) {
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"message": text})
}

// ---- legacy 双端点（兼容怪癖三件套）----

// GetLegacy GET /api/ab：空数据 → 字符串 'null'；非空 →
// {licensed_devices:100, data:"<双重 JSON 编码>"}。
func (h *AddressBookHandler) GetLegacy(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	payload, err := h.legacy.GetLegacy(r.Context(), userGuid)
	if errors.Is(err, absvc.ErrLegacyNull) {
		// 兼容怪癖第一件：空数据返回裸 JSON null 字节（RustDesk 客户端
		// 硬依赖，字节级锁定），不可经 WriteJSON 二次编码为 "null" 字符串。
		httpx.WriteRawString(w, http.StatusOK, "application/json; charset=utf-8", "null")
		return
	}
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// UpdateLegacy POST /api/ab：仅此端点 try/catch——业务失败返回
// {error: msg} 且 HTTP 仍 200；成功返回 'null'。body 缺 data 视为
// 无操作（参考 @Body('data') undefined 语义）。
func (h *AddressBookHandler) UpdateLegacy(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	var req api.LegacyAbSaveRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, legacyBodyLimit))
	if err != nil || (len(body) > 0 && json.Unmarshal(body, &req) != nil) {
		// body 语法错误走标准 400 包络（参考 body-parser 行为）；
		// 合法 JSON 但缺 data → 空串无操作。
		httpx.ErrBadRequest(w, "Invalid JSON data")
		return
	}
	if err := h.legacy.UpdateLegacy(r.Context(), userGuid, req.Data); err != nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"error": errTextOf(err)})
		return
	}
	// 兼容怪癖第二件：成功返回裸 JSON null 字节（与 GET 空数据形态一致）。
	httpx.WriteRawString(w, http.StatusOK, "application/json; charset=utf-8", "null")
}

// legacyBodyLimit legacy 全量保存 body 上限（8MB 与 agent 转发上限
// 对齐；客户端地址簿极端规模下充裕）。
const legacyBodyLimit = 8 << 20

// errTextOf 错误文本提取（{error} 载荷：StatusError 取 Message）。
func errTextOf(err error) string {
	var se interface{ Error() string }
	if errors.As(err, &se) {
		return se.Error()
	}
	return err.Error()
}

// ---- settings / personal ----

// Settings POST /api/ab/settings：恒 {max_peer_one_ab:0}。
func (h *AddressBookHandler) Settings(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, h.book.Settings())
}

// PersonalGet GET /api/ab/personal。
func (h *AddressBookHandler) PersonalGet(w http.ResponseWriter, r *http.Request) {
	h.personal(w, r)
}

// PersonalPost POST /api/ab/personal（同义 GET）。
func (h *AddressBookHandler) PersonalPost(w http.ResponseWriter, r *http.Request) {
	h.personal(w, r)
}

func (h *AddressBookHandler) personal(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	ref, err := h.book.Personal(r.Context(), userGuid)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ref)
}

// ---- custom profiles ----

// CustomProfilesGet GET /api/ab/custom/profiles。
func (h *AddressBookHandler) CustomProfilesGet(w http.ResponseWriter, r *http.Request) {
	h.customProfiles(w, r)
}

func (h *AddressBookHandler) customProfiles(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	q, ok := h.bookQuery(w, r)
	if !ok {
		return
	}
	page, err := h.book.CustomProfiles(r.Context(), userGuid, q)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// CustomAdd POST /api/ab/custom/add：{guid} 引用。
func (h *AddressBookHandler) CustomAdd(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.CreateBookProfileRequest](w, r)
	if !ok {
		return
	}
	ref, err := h.rule.AddCustom(r.Context(), userGuid, *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ref)
}

// CustomUpdate PUT /api/ab/custom/update/profile。
func (h *AddressBookHandler) CustomUpdate(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.UpdateBookProfileRequest](w, r)
	if !ok {
		return
	}
	if err := h.rule.UpdateCustom(r.Context(), userGuid, *req); err != nil {
		writeAuditError(w, err)
		return
	}
	writeMessage(w, msgUpdatedSuccessfully)
}

// CustomDelete DELETE /api/ab/custom（body {guids[]}）。
func (h *AddressBookHandler) CustomDelete(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.BookGuidsRequest](w, r)
	if !ok {
		return
	}
	if err := h.rule.DeleteCustom(r.Context(), userGuid, req.Guids); err != nil {
		writeAuditError(w, err)
		return
	}
	writeMessage(w, msgDeletedSuccessfully)
}

// ---- shared profiles ----

// SharedProfilesGet GET /api/ab/shared/profiles。
func (h *AddressBookHandler) SharedProfilesGet(w http.ResponseWriter, r *http.Request) {
	h.sharedProfilesGet(w, r)
}

func (h *AddressBookHandler) sharedProfilesGet(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	q, ok := h.bookQuery(w, r)
	if !ok {
		return
	}
	page, err := h.book.SharedProfiles(r.Context(), userGuid, q)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// SharedProfilesPost POST /api/ab/shared/profiles（body 分页，同义 GET）。
// 官方客户端（ab_model.dart _getSharedAbProfiles）以空体 POST +
// query 传参——空体走查询参数（v0.2.1）。
func (h *AddressBookHandler) SharedProfilesPost(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	if r.ContentLength == 0 {
		h.sharedProfilesGet(w, r)
		return
	}
	req, ok := httpx.DecodeJSON[api.BookPaginationRequest](w, r)
	if !ok {
		return
	}
	q := dto.BookListQuery{}
	if req.Name != nil {
		q.Name = *req.Name
	}
	if req.Note != nil {
		q.Note = *req.Note
	}
	q.Current = req.Current
	q.PageSize = req.PageSize
	page, err := h.book.SharedProfiles(r.Context(), userGuid, q)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

// SharedList GET /api/ab/shared/list（sharedOnly 形态，无分页）。
func (h *AddressBookHandler) SharedList(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	list, err := h.book.SharedList(r.Context(), userGuid)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list)
}

// SharedAccess GET /api/ab/shared/{guid}/access：无权 403、非共享
// 形态 404（服务层 rbac.StatusError 文案即响应 message）。
func (h *AddressBookHandler) SharedAccess(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	row, err := h.book.SharedAccess(r.Context(), h.pathGuid(r), userGuid)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, row)
}

// ShareCandidates GET /api/ab/shared/{guid}/share-candidates。
func (h *AddressBookHandler) ShareCandidates(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	out, err := h.rule.ShareCandidates(r.Context(), h.pathGuid(r), userGuid, r.URL.Query().Get("name"))
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// SharedAdd POST /api/ab/shared/add。
func (h *AddressBookHandler) SharedAdd(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.CreateBookProfileRequest](w, r)
	if !ok {
		return
	}
	ref, err := h.rule.AddShared(r.Context(), userGuid, *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ref)
}

// SharedUpdate PUT /api/ab/shared/update/profile。
func (h *AddressBookHandler) SharedUpdate(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.UpdateSharedBookRequest](w, r)
	if !ok {
		return
	}
	if err := h.rule.UpdateShared(r.Context(), userGuid, *req); err != nil {
		writeAuditError(w, err)
		return
	}
	writeMessage(w, msgUpdatedSuccessfully)
}

// SharedDelete DELETE /api/ab/shared（body {guids[]}）。
func (h *AddressBookHandler) SharedDelete(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.BookGuidsRequest](w, r)
	if !ok {
		return
	}
	if err := h.rule.DeleteShared(r.Context(), userGuid, req.Guids); err != nil {
		writeAuditError(w, err)
		return
	}
	writeMessage(w, msgDeletedSuccessfully)
}

// ---- peers ----

// PeersGet GET /api/ab/peers（ab 必填；tags 逗号分隔；tagMode 枚举）。
func (h *AddressBookHandler) PeersGet(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	parsed := dto.PeersListQuery{
		AB:      q.Get("ab"),
		ID:      q.Get("id"),
		Alias:   q.Get("alias"),
		Tags:    q.Get("tags"),
		TagMode: q.Get("tagMode"),
	}
	if !parseAuditPage(w, q, &parsed.Current, &parsed.PageSize) {
		return
	}
	if parsed.TagMode != "" && parsed.TagMode != "union" && parsed.TagMode != "intersection" {
		httpx.ErrBadRequest(w, "Invalid request parameters")
		return
	}
	list, err := h.peer.Peers(r.Context(), userGuid, parsed)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list)
}

// PeersPost POST /api/ab/peers（body 传参；分页参数仍走 query——
// 参考 @Query() 同源语义）。官方客户端（ab_model.dart _fetchPeers）
// 以 Content-Length:0 空体 POST + query 传参——空体视为零值查询（v0.2.1）。
func (h *AddressBookHandler) PeersPost(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSONOptional[api.AbPeersQueryRequest](w, r)
	if !ok {
		return
	}
	empty := api.AbPeersQueryRequest{}
	if req == nil {
		req = &empty
	}
	// 官方客户端筛选与 ab 均经 query 传参（_fetchPeers）：body 缺省
	// 字段回填 query 值（body 优先，兼容本仓 web 封装）。
	q := r.URL.Query()
	if req.Ab == "" && q.Has("ab") {
		req.Ab = q.Get("ab")
	}
	if req.Id == nil && q.Has("id") {
		v := q.Get("id")
		req.Id = &v
	}
	if req.Alias == nil && q.Has("alias") {
		v := q.Get("alias")
		req.Alias = &v
	}
	if req.TagMode == nil && q.Has("tagMode") {
		v := api.AbPeersQueryRequestTagMode(q.Get("tagMode"))
		req.TagMode = &v
	}
	if req.Tags == nil && q.Has("tags") {
		values := []string{}
		for _, t := range strings.Split(q.Get("tags"), ",") {
			if t != "" {
				values = append(values, t)
			}
		}
		req.Tags = &values
	}
	var current, pageSize *int
	if !parseAuditPage(w, q, &current, &pageSize) {
		return
	}
	list, err := h.peer.PeersQuery(r.Context(), userGuid, *req, current, pageSize)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list)
}

// PeerAdd POST /api/ab/peer/add/{guid}。
func (h *AddressBookHandler) PeerAdd(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.AbPeerUpsertRequest](w, r)
	if !ok {
		return
	}
	row, err := h.peer.AddPeer(r.Context(), userGuid, h.pathGuid(r), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, row)
}

// PeerUpdate PUT /api/ab/peer/update/{guid}。
func (h *AddressBookHandler) PeerUpdate(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.AbPeerUpsertRequest](w, r)
	if !ok {
		return
	}
	row, err := h.peer.UpdatePeer(r.Context(), userGuid, h.pathGuid(r), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, row)
}

// PeerDelete DELETE /api/ab/peer/{guid}。
func (h *AddressBookHandler) PeerDelete(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	if err := h.peer.DeletePeer(r.Context(), userGuid, h.pathGuid(r)); err != nil {
		writeAuditError(w, err)
		return
	}
	writeMessage(w, msgDeletedSuccessfully)
}

// ---- tags ----

// TagsGet GET /api/ab/tags/{guid}（全量 + tag_colors）。
func (h *AddressBookHandler) TagsGet(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	list, err := h.tag.Tags(r.Context(), userGuid, h.pathGuid(r))
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list)
}

// TagsReplace POST /api/ab/tags/{guid}：官方客户端（ab_model.dart
// _fetchTags）以 Content-Length:0 空体 POST 此路径"拉取"标签——空体
// 等价 GET（返回当前标签列表，v0.2.1）；非空体 = 全量替换（契约）。
func (h *AddressBookHandler) TagsReplace(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	if r.ContentLength == 0 {
		h.TagsGet(w, r)
		return
	}
	req, ok := httpx.DecodeJSON[api.AbTagsReplaceRequest](w, r)
	if !ok {
		return
	}
	list, err := h.tag.ReplaceTags(r.Context(), userGuid, h.pathGuid(r), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list)
}

// TagAdd POST /api/ab/tag/add/{guid}。
func (h *AddressBookHandler) TagAdd(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.AbTagUpsertRequest](w, r)
	if !ok {
		return
	}
	row, err := h.tag.AddTag(r.Context(), userGuid, h.pathGuid(r), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, row)
}

// TagRename PUT /api/ab/tag/rename/{guid}。
func (h *AddressBookHandler) TagRename(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.AbTagRenameRequest](w, r)
	if !ok {
		return
	}
	row, err := h.tag.RenameTag(r.Context(), userGuid, h.pathGuid(r), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, row)
}

// TagUpdate PUT /api/ab/tag/update/{guid}（颜色）。
func (h *AddressBookHandler) TagUpdate(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.AbTagUpsertRequest](w, r)
	if !ok {
		return
	}
	row, err := h.tag.UpdateTag(r.Context(), userGuid, h.pathGuid(r), *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, row)
}

// TagDelete DELETE /api/ab/tag/{guid}（级联清 peer_tags）。
func (h *AddressBookHandler) TagDelete(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	if err := h.tag.DeleteTag(r.Context(), userGuid, h.pathGuid(r)); err != nil {
		writeAuditError(w, err)
		return
	}
	writeMessage(w, msgDeletedSuccessfully)
}

// ---- rules ----

// RulesList GET /api/ab/rules（ab 缺省=我的全部可见书）。
func (h *AddressBookHandler) RulesList(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	list, err := h.rule.ListRules(r.Context(), userGuid, r.URL.Query().Get("ab"))
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list)
}

// RuleCreate POST /api/ab/rule：返回规则行。
func (h *AddressBookHandler) RuleCreate(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.AbRuleUpsertRequest](w, r)
	if !ok {
		return
	}
	row, err := h.rule.CreateRule(r.Context(), userGuid, *req)
	if err != nil {
		writeAuditError(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, row)
}

// RuleUpdate PATCH /api/ab/rule。
func (h *AddressBookHandler) RuleUpdate(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.AbRuleUpdateRequest](w, r)
	if !ok {
		return
	}
	if err := h.rule.UpdateRule(r.Context(), userGuid, *req); err != nil {
		writeAuditError(w, err)
		return
	}
	writeMessage(w, msgUpdatedSuccessfully)
}

// RulesDelete DELETE /api/ab/rules（body {guids[]}，逐条 FULL_CONTROL）。
func (h *AddressBookHandler) RulesDelete(w http.ResponseWriter, r *http.Request) {
	userGuid, ok := h.ident(w, r)
	if !ok {
		return
	}
	req, ok := httpx.DecodeJSON[api.RuleGuidsRequest](w, r)
	if !ok {
		return
	}
	if err := h.rule.DeleteRules(r.Context(), userGuid, req.Guids); err != nil {
		writeAuditError(w, err)
		return
	}
	writeMessage(w, msgDeletedSuccessfully)
}
