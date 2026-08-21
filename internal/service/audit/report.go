// Package audit 审计域服务（M3 T04）：上报端（Public + per-IP
// 50/min 限流在路由档）与查询端（audit.view / devices.disconnect /
// RequireSuperAdmin）。行为以参考 audit.service.ts 实测为准，偏离处
// 以设计文档 §1.1②/§4.2 为最终裁定（conn upsert 三态、T02 时间锚点
// requestedAt、primaryAuth/twoFactor 缺省 0——T02 DDL NOT NULL）。
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// 固定文案契约（参考 audit.controller.ts / audit.service.ts 逐字节）。
const (
	msgConnRecorded    = "Connection audit recorded successfully"
	msgFileRecorded    = "File audit recorded successfully"
	msgAlarmRecorded   = "Alarm audit recorded successfully"
	msgConnNoteUpdated = "Connection audit updated successfully"
	// note-only 模式找不到目标行（参考 NotFoundException 格式串）。
	msgConnNoteMissFmt = "Connection audit not found for deviceId=%s, sessionId=%s"
	msgConnIDMissFmt   = "Connection audit not found for id=%d"
)

// file_info 解析缺省（参考 catch 分支：info 非法 JSON → 全零值）。
const defaultFilesJSON = "[]"

// ReportService 上报端服务（conn upsert / file、alarm nonce 幂等）。
type ReportService struct {
	conns  *repository.ConnectionAuditRepo
	files  *repository.FileAuditRepo
	alarms *repository.AlarmAuditRepo
}

// NewReportService 构建上报服务。
func NewReportService(
	conns *repository.ConnectionAuditRepo,
	files *repository.FileAuditRepo,
	alarms *repository.AlarmAuditRepo,
) *ReportService {
	return &ReportService{conns: conns, files: files, alarms: alarms}
}

// ReportConn 连接审计上报（POST /api/audit/conn）：
//   - note-only 模式（无 uuid、有 session_id+note）：按
//     deviceId+sessionId 定位既有行仅改备注；找不到 → 404；
//   - 常规模式：按 (deviceId, deviceUuid, connId) 定位 upsert，
//     action 迁移三态由仓储 UpsertConn 状态机承担（new→open、
//     ”→established+establishedAt、其余幂等）。
//
// 返回响应文案。
func (s *ReportService) ReportConn(ctx context.Context, req api.ConnAuditReport) (string, error) {
	if req.Uuid == nil && req.SessionId != nil && req.Note != nil {
		return s.reportConnNote(ctx, req)
	}

	row := &entity.ConnectionAudit{
		DeviceId:     req.Id,
		DeviceUuid:   req.Uuid,
		ConnId:       req.ConnId,
		SessionId:    req.SessionId,
		Ip:           emptyStrPtr(req.Ip),
		Action:       derefStr(req.Action),
		PeerId:       peerAt(req.Peer, 0),
		PeerName:     peerAt(req.Peer, 1),
		Type:         derefInt(req.Type),
		RequestedAt:  time.Now(),
		Nonce:        req.Nonce,
		ConnAuditRef: req.ConnAuditRef,
		PrimaryAuth:  derefInt(req.PrimaryAuth),
		TwoFactor:    derefInt(req.TwoFactor),
	}
	if _, _, err := s.conns.UpsertConn(ctx, row); err != nil {
		return "", err
	}
	return msgConnRecorded, nil
}

// reportConnNote note-only 上报（参考 addConnectionNote：note 空串
// 写 NULL 由仓储 UpdateNote 承担）。
func (s *ReportService) reportConnNote(ctx context.Context, req api.ConnAuditReport) (string, error) {
	row, err := s.conns.FindBySession(ctx, req.Id, *req.SessionId)
	if errors.Is(err, repository.ErrNotFound) {
		return "", authsvc.NotFound(fmt.Sprintf(
			msgConnNoteMissFmt, req.Id, *req.SessionId))
	}
	if err != nil {
		return "", err
	}
	if err := s.conns.UpdateNote(ctx, row.Id, *req.Note); err != nil {
		return "", err
	}
	return msgConnRecorded, nil
}

// ReportFile 文件审计上报（POST /api/audit/file）：nonce 幂等由仓储
// UpsertByNonce（UNIQUE(deviceId,nonce) 冲突重查返回既有行）。info
// JSON 解析出 clientIp/clientName/fileCount/files（文件清单截前 10，
// 参考 info.files.slice(0,10)；解析失败按缺省空值落库，不拒单）。
func (s *ReportService) ReportFile(ctx context.Context, req api.FileAuditReport) (string, error) {
	info := parseFileInfo(req.Info)
	files := info.Files
	if len(files) > 10 {
		files = files[:10]
	}
	filesJSON := defaultFilesJSON
	if len(files) > 0 {
		if b, err := json.Marshal(files); err == nil {
			filesJSON = string(b)
		}
	}

	now := time.Now()
	row := &entity.FileAudit{
		DeviceId:    req.Id,
		DeviceUuid:  req.Uuid,
		PeerId:      req.PeerId,
		ConnId:      req.ConnId,
		Type:        int(req.Type),
		Path:        derefStr(req.Path),
		IsFile:      req.IsFile,
		ClientIp:    &info.Ip,
		ClientName:  &info.Name,
		FileCount:   info.Num,
		Files:       filesJSON,
		Nonce:       req.Nonce,
		RequestedAt: now,
		CreatedAt:   now,
	}
	if _, _, err := s.files.UpsertByNonce(ctx, row); err != nil {
		return "", err
	}
	return msgFileRecorded, nil
}

// ReportAlarm 告警审计上报（POST /api/audit/alarm）：nonce 幂等同
// file；info JSON 解析 {id, ip, name} → infoId/infoIp/infoName 列
// （参考 auditAlarm：id/name 空值落 NULL，ip 恒存字符串）。
func (s *ReportService) ReportAlarm(ctx context.Context, req api.AlarmAuditReport) (string, error) {
	info := parseAlarmInfo(req.Info)

	now := time.Now()
	row := &entity.AlarmAudit{
		DeviceId:     req.Id,
		DeviceUuid:   req.Uuid,
		Typ:          req.Typ,
		InfoId:       info.Id,
		InfoIp:       &info.Ip,
		InfoName:     info.Name,
		ConnId:       req.ConnId,
		Nonce:        req.Nonce,
		ConnAuditRef: req.ConnAuditRef,
		CreatedAt:    now,
	}
	if _, _, err := s.alarms.UpsertByNonce(ctx, row); err != nil {
		return "", err
	}
	return msgAlarmRecorded, nil
}

// fileInfo file 上报 info 载荷（参考 JSON.parse 形状）。
type fileInfo struct {
	Ip    string            `json:"ip"`
	Name  string            `json:"name"`
	Num   int               `json:"num"`
	Files []json.RawMessage `json:"files"`
}

// parseFileInfo 解析 file info；非法 JSON 按参考 catch 分支回零值。
func parseFileInfo(raw string) fileInfo {
	var info fileInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return fileInfo{}
	}
	return info
}

// alarmInfo alarm 上报 info 载荷（id/name 可缺省）。
type alarmInfo struct {
	Id   *string `json:"id"`
	Ip   string  `json:"ip"`
	Name *string `json:"name"`
}

// parseAlarmInfo 解析 alarm info；非法 JSON 回零值（ip 恒 ""）。
func parseAlarmInfo(raw string) alarmInfo {
	var info alarmInfo
	if err := json.Unmarshal([]byte(raw), &info); err != nil {
		return alarmInfo{}
	}
	// 参考语义：info.id || null / info.name || null（空串归 NULL）。
	if info.Id != nil && *info.Id == "" {
		info.Id = nil
	}
	if info.Name != nil && *info.Name == "" {
		info.Name = nil
	}
	return info
}

// emptyStrPtr 空串归一化为 ""（参考 createNewConnection：ip=dto.ip||”
// 存空串而非 NULL）。
func emptyStrPtr(p *string) *string {
	v := derefStr(p)
	return &v
}

// peerAt 取 peer 数组第 i 位（越界/缺失 → nil，参考 peer[0]/peer[1]）。
func peerAt(peer *[]string, i int) *string {
	if peer == nil || i >= len(*peer) {
		return nil
	}
	v := (*peer)[i]
	return &v
}

// derefStr 指针字符串取值（nil → ""）。
func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// derefInt 指针整数取值（nil → 0；primaryAuth/twoFactor/type 的
// DDL NOT NULL DEFAULT 0 契约）。
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
