package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// QueryService 查询端服务：conn/file/alarm 分页过滤、active（scope
// 过滤 + 行内 can_disconnect）、conn note PATCH（超管档在路由）、
// console 查询（M2 console_audits 表查询端）。
type QueryService struct {
	authz   *rbac.AuthorizationService
	conns   *repository.ConnectionAuditRepo
	files   *repository.FileAuditRepo
	alarms  *repository.AlarmAuditRepo
	console *repository.ConsoleAuditRepo
	peers   *repository.PeerRepo
	// logins 登录审计仓储（GAP2 新表查询端；GAP2 设计 §3.4）。
	logins *repository.LoginAuditRepo
}

// NewQueryService 构建查询服务。
func NewQueryService(
	authz *rbac.AuthorizationService,
	conns *repository.ConnectionAuditRepo,
	files *repository.FileAuditRepo,
	alarms *repository.AlarmAuditRepo,
	console *repository.ConsoleAuditRepo,
	peers *repository.PeerRepo,
	logins *repository.LoginAuditRepo,
) *QueryService {
	return &QueryService{
		authz: authz, conns: conns, files: files,
		alarms: alarms, console: console, peers: peers, logins: logins,
	}
}

// ListConn 连接审计分页（GET /api/audits/conn；audit.view 档在路由）。
// 过滤 peer_id/uuid/type 精确 + start/end requestedAt 闭区间（T01
// 契约参数；参考用 deviceId 模糊 + createdAt 锚点，以本仓契约为准）。
func (s *QueryService) ListConn(ctx context.Context, p api.ListConnectionAuditsParams) (api.ConnAuditPage, error) {
	current, pageSize := pageParams(p.Current, p.PageSize)
	rows, total, err := s.conns.ListPaged(ctx, repository.ConnAuditFilter{
		PeerId:   derefStr(p.PeerId),
		Uuid:     derefStr(p.Uuid),
		Type:     p.Type,
		Start:    p.Start,
		End:      p.End,
		Current:  current,
		PageSize: pageSize,
	})
	if err != nil {
		return api.ConnAuditPage{}, err
	}
	page := api.ConnAuditPage{
		Data:  make([]api.ConnAuditRow, 0, len(rows)),
		Total: int(total),
	}
	for i := range rows {
		page.Data = append(page.Data, connRowOf(rows[i]))
	}
	return page, nil
}

// ListActive 活跃连接（GET /api/audits/conn/active；devices.disconnect
// 档在路由）：scope 全局直查未关闭行；scope 组集经 peers 表换算设备
// uuid 白名单后过滤；行内 can_disconnect = scope ∩ active（global 直
// true；非全局按 uuid 命中判定，设计事实②）。
func (s *QueryService) ListActive(ctx context.Context, actorGuid string) (api.ConnActiveList, error) {
	scope, err := s.authz.GetPermissionScope(ctx, actorGuid, rbac.CodeDevicesDisconnect)
	if err != nil {
		return api.ConnActiveList{}, err
	}

	var allowed []string // nil = 全局视图（不过滤）
	uuidSet := make(map[string]struct{})
	if !scope.Global {
		guids := make([]string, 0, len(scope.DeviceGroupGuids))
		for g := range scope.DeviceGroupGuids {
			guids = append(guids, g)
		}
		peers, _, err := s.peers.ListScoped(ctx, repository.GuidSet{Guids: guids}, repository.DeviceFilter{})
		if err != nil {
			return api.ConnActiveList{}, err
		}
		allowed = make([]string, 0, len(peers))
		for i := range peers {
			allowed = append(allowed, peers[i].UUID)
			uuidSet[peers[i].UUID] = struct{}{}
		}
	}

	rows, err := s.conns.ListActive(ctx, allowed)
	if err != nil {
		return api.ConnActiveList{}, err
	}
	list := api.ConnActiveList{
		Data: make([]api.ConnActiveRow, 0, len(rows)),
	}
	for i := range rows {
		canDisconnect := scope.Global
		if !canDisconnect {
			_, canDisconnect = uuidSet[derefStr(rows[i].DeviceUuid)]
		}
		list.Data = append(list.Data, connActiveRowOf(rows[i], canDisconnect))
	}
	return list, nil
}

// UpdateNote 超管改备注（PATCH /api/audits/conn/{id}；id 路径参数
// 非整数 → 400，行不存在 → 404 参考格式串）。
func (s *QueryService) UpdateNote(ctx context.Context, idParam string, req api.ConnNoteUpdate) (string, error) {
	id, err := strconv.Atoi(idParam)
	if err != nil || id <= 0 {
		return "", authsvc.BadRequest("Invalid request parameters")
	}
	if _, err := s.conns.FindByID(ctx, uint(id)); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", authsvc.NotFound(sprintfIDMiss(id))
		}
		return "", err
	}
	if err := s.conns.UpdateNote(ctx, uint(id), req.Note); err != nil {
		return "", err
	}
	return msgConnNoteUpdated, nil
}

// ListFile 文件审计分页（GET /api/audits/file）。
func (s *QueryService) ListFile(ctx context.Context, p api.ListFileAuditsParams) (api.FileAuditPage, error) {
	current, pageSize := pageParams(p.Current, p.PageSize)
	rows, total, err := s.files.ListPaged(ctx, repository.FileAuditFilter{
		PeerId:   derefStr(p.PeerId),
		Uuid:     derefStr(p.Uuid),
		Type:     p.Type,
		Current:  current,
		PageSize: pageSize,
	})
	if err != nil {
		return api.FileAuditPage{}, err
	}
	page := api.FileAuditPage{
		Data:  make([]api.FileAuditRow, 0, len(rows)),
		Total: int(total),
	}
	for i := range rows {
		row := &rows[i]
		view := api.FileAuditRow{
			Id:         int(row.Id),
			DeviceId:   row.DeviceId,
			DeviceUuid: row.DeviceUuid,
			PeerId:     row.PeerId,
			ConnId:     row.ConnId,
			Type:       row.Type,
			Path:       strPtrVal(row.Path),
			IsFile:     row.IsFile,
			Info:       &row.Files,
			ClientIp:   row.ClientIp,
			ClientName: row.ClientName,
			FileCount:  &row.FileCount,
			Nonce:      row.Nonce,
			CreatedAt:  optTime(row.CreatedAt),
		}
		page.Data = append(page.Data, view)
	}
	return page, nil
}

// ListAlarm 告警审计分页（GET /api/audits/alarm）。info 由
// infoId/infoIp/infoName 三列重建为 JSON 串（T01 契约行形状；
// 参考直接回实体三列，以本仓契约为准）。
func (s *QueryService) ListAlarm(ctx context.Context, p api.ListAlarmAuditsParams) (api.AlarmAuditPage, error) {
	current, pageSize := pageParams(p.Current, p.PageSize)
	rows, total, err := s.alarms.ListPaged(ctx, repository.AlarmAuditFilter{
		Typ:      p.Typ,
		Uuid:     derefStr(p.Uuid),
		Current:  current,
		PageSize: pageSize,
	})
	if err != nil {
		return api.AlarmAuditPage{}, err
	}
	page := api.AlarmAuditPage{
		Data:  make([]api.AlarmAuditRow, 0, len(rows)),
		Total: int(total),
	}
	for i := range rows {
		row := &rows[i]
		info := alarmInfoOf(*row)
		page.Data = append(page.Data, api.AlarmAuditRow{
			Id:           int(row.Id),
			DeviceId:     row.DeviceId,
			DeviceUuid:   row.DeviceUuid,
			Typ:          row.Typ,
			Info:         info,
			ConnId:       row.ConnId,
			Nonce:        row.Nonce,
			ConnAuditRef: row.ConnAuditRef,
			CreatedAt:    optTime(row.CreatedAt),
		})
	}
	return page, nil
}

// ListConsole 控制台审计分页（GET /api/audits/console；M2 表查询端）。
// before_state/after_state 以原始 JSON 直出（非法/空 → null）。
func (s *QueryService) ListConsole(ctx context.Context, p api.ListConsoleAuditsParams) (api.ConsoleAuditPage, error) {
	current, pageSize := pageParams(p.Current, p.PageSize)
	rows, total, err := s.console.ListPaged(ctx, repository.ConsoleAuditFilter{
		Result:   derefStr((*string)(p.Result)),
		UserGuid: derefStr(p.UserGuid),
		Current:  current,
		PageSize: pageSize,
	})
	if err != nil {
		return api.ConsoleAuditPage{}, err
	}
	page := api.ConsoleAuditPage{
		Data:  make([]api.ConsoleAuditRow, 0, len(rows)),
		Total: int(total),
	}
	for i := range rows {
		row := &rows[i]
		page.Data = append(page.Data, api.ConsoleAuditRow{
			Guid:          row.Guid,
			ActorUserGuid: row.ActorUserGuid,
			ActorUserName: row.ActorName,
			TargetType:    row.TargetType,
			TargetGuid:    strPtrVal(row.TargetGuid),
			Action:        row.Action,
			Result:        api.ConsoleAuditRowResult(row.Result),
			Reason:        strPtrVal(row.Reason),
			BeforeState:   rawJSONOrNull(row.BeforeState),
			AfterState:    rawJSONOrNull(row.AfterState),
			RequestId:     strPtrVal(row.RequestID),
			CreatedAt:     row.CreatedAt,
		})
	}
	return page, nil
}

// connRowOf 实体 → 契约行（peer 数组 = [peerId, peerName] 有则拼接，
// 双空省略键；conn_id/device_uuid 可空列按必填契约回 ""）。
func connRowOf(row entity.ConnectionAudit) api.ConnAuditRow {
	return api.ConnAuditRow{
		Id:            int(row.Id),
		DeviceId:      row.DeviceId,
		DeviceUuid:    derefStr(row.DeviceUuid),
		ConnId:        derefStr(row.ConnId),
		SessionId:     row.SessionId,
		Ip:            row.Ip,
		Action:        row.Action,
		Peer:          peerArrayOf(row),
		Type:          row.Type,
		RequestedAt:   row.RequestedAt,
		EstablishedAt: row.EstablishedAt,
		ClosedAt:      row.ClosedAt,
		Note:          row.Note,
		Nonce:         row.Nonce,
		ConnAuditRef:  row.ConnAuditRef,
		PrimaryAuth:   &row.PrimaryAuth,
		TwoFactor:     &row.TwoFactor,
	}
}

// connActiveRowOf 活跃连接行（can_disconnect 行内计算）。
func connActiveRowOf(row entity.ConnectionAudit, canDisconnect bool) api.ConnActiveRow {
	return api.ConnActiveRow{
		Id:            int(row.Id),
		DeviceId:      row.DeviceId,
		DeviceUuid:    derefStr(row.DeviceUuid),
		ConnId:        derefStr(row.ConnId),
		SessionId:     row.SessionId,
		Ip:            row.Ip,
		Action:        row.Action,
		Peer:          peerArrayOf(row),
		Type:          row.Type,
		RequestedAt:   row.RequestedAt,
		EstablishedAt: row.EstablishedAt,
		ClosedAt:      row.ClosedAt,
		Note:          row.Note,
		CanDisconnect: canDisconnect,
	}
}

// peerArrayOf 查询行 peer 数组组装（peerId/peerName 双列 →
// [peerId, peerName]；双空 → nil，omitempty 省略）。
func peerArrayOf(row entity.ConnectionAudit) *[]string {
	var peer []string
	if row.PeerId != nil {
		peer = append(peer, *row.PeerId)
	}
	if row.PeerName != nil {
		peer = append(peer, *row.PeerName)
	}
	if peer == nil {
		return nil
	}
	return &peer
}

// alarmInfoOf 告警 info 重建（ip 恒在，id/name 空缺省略）。
func alarmInfoOf(row entity.AlarmAudit) string {
	view := struct {
		Id   *string `json:"id,omitempty"`
		Ip   string  `json:"ip"`
		Name *string `json:"name,omitempty"`
	}{Id: row.InfoId, Name: row.InfoName}
	if row.InfoIp != nil {
		view.Ip = *row.InfoIp
	}
	b, err := json.Marshal(view)
	if err != nil {
		return ""
	}
	return string(b)
}

// rawJSONOrNull 合法 JSON 串直出（json.RawMessage 保持原始形态），
// 空/非法 → nil（参考 parseState 容错语义）。
func rawJSONOrNull(s string) any {
	if s == "" || !json.Valid([]byte(s)) {
		return nil
	}
	return json.RawMessage(s)
}

// sprintfIDMiss PATCH note 404 文案（参考格式串）。
func sprintfIDMiss(id int) string {
	return "Connection audit not found for id=" + strconv.Itoa(id)
}

// pageParams 分页参数取值（CurrentParam/PageSizeParam 为 int 别名；
// 缺省 1/20，契约 min/max 由校验器承担）。
func pageParams(current, pageSize *int) (int, int) {
	cur, size := 1, 20
	if current != nil && *current > 0 {
		cur = *current
	}
	if pageSize != nil && *pageSize > 0 {
		size = *pageSize
	}
	return cur, size
}

// strPtrVal 值字符串转指针（空串 → nil，omitempty 省略空值）。
func strPtrVal(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// optTime 零值时间归 nil（DATETIME 可空列 Go 侧零值兼容）。
func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ListLogin 登录审计分页（GET /api/audits/login；GAP2 新表
// login_audits 查询端）：过滤 result/username(LIKE)/start/end
// （createdAt 闭区间）+ 分页；displayName 由 users LEFT JOIN 补齐。
func (s *QueryService) ListLogin(ctx context.Context, p api.ListLoginAuditsParams) (api.LoginAuditPage, error) {
	current, pageSize := pageParams(p.Current, p.PageSize)
	rows, total, err := s.logins.ListPaged(ctx, repository.LoginAuditFilter{
		Result:   derefStr((*string)(p.Result)),
		Username: derefStr(p.Username),
		Start:    p.Start,
		End:      p.End,
		Current:  current,
		PageSize: pageSize,
	})
	if err != nil {
		return api.LoginAuditPage{}, err
	}
	page := api.LoginAuditPage{
		Data:  make([]api.LoginAuditRow, 0, len(rows)),
		Total: int(total),
	}
	for i := range rows {
		row := &rows[i]
		page.Data = append(page.Data, api.LoginAuditRow{
			Guid:        row.Guid,
			UserGuid:    row.UserGuid,
			Username:    row.Username,
			DisplayName: row.DisplayName,
			Result:      api.LoginAuditRowResult(row.Result),
			Method:      api.LoginAuditRowMethod(row.Method),
			Ip:          strPtrVal(row.IP),
			UserAgent:   strPtrVal(row.UserAgent),
			DeviceId:    strPtrVal(row.DeviceId),
			DeviceUuid:  strPtrVal(row.DeviceUuid),
			Reason:      strPtrVal(row.Reason),
			CreatedAt:   row.CreatedAt,
		})
	}
	return page, nil
}
