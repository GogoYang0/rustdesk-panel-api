// Package device 本文件：AssignService——设备个人归属域（GAP2 设计
// §2 功能 1）：分配/转移/解绑（PATCH /api/devices/{guid}/assign）、
// 我的设备（GET /api/users/me/devices）与按用户反查设备
// （GET /api/users/{guid}/devices）。
//
// 单属主模型（G5）：归属写 peers.userGuid（既有可空列，无新增 DDL）；
// 授权判定（GetPermissionScope/ListScoped）不读该列——归属与
// device_group scope 正交，分配 ≠ 授权；历史留痕复用 console_audits
// （action=device.assign/device.unassign，before/afterState 记
// {"userGuid": ...} 变化，OQ-1）。
package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// 归属动作与审计留痕的固定键（GAP2 设计 §2.1 决策 3）。
const (
	ActionDeviceAssign   = "device.assign"
	ActionDeviceUnassign = "device.unassign"
	auditTargetDevice    = "device"
	auditStateKey        = "userGuid"
)

// AssignService 设备个人归属域服务。
type AssignService struct {
	authz     *rbac.AuthorizationService
	audit     *rbac.AuditService
	assembler viewAssembler
	peers     *repository.PeerRepo
	users     *repository.UserRepo
}

// NewAssignService 构建归属域服务（audit 可为 nil，nil 时跳过留痕）。
func NewAssignService(
	authz *rbac.AuthorizationService,
	audit *rbac.AuditService,
	peers *repository.PeerRepo,
	sysinfos *repository.SysinfoRepo,
	users *repository.UserRepo,
	groups *repository.DeviceGroupRepo,
	strategies *repository.StrategyRepo,
) *AssignService {
	return &AssignService{
		authz: authz,
		audit: audit,
		assembler: viewAssembler{
			sysinfos: sysinfos, users: users, groups: groups, strategies: strategies,
		},
		peers: peers,
		users: users,
	}
}

// Assign 分配/转移/解绑设备个人归属（devices.assign 路由档在注册处；
// 资源级复核 AssertDeviceAccess：404 Device not found / 403 Device is
// not in an authorized device group）。
//
// userGuid 缺省/空 = 解绑（置 NULL）；非空 = 分配/转移（目标用户不存在
// → 400 User not found）。转移 = 对同一设备再次 assign（before/after
// 留痕即履历）。返回更新后的 DeviceView。
func (s *AssignService) Assign(ctx context.Context, actorGuid, guid string, userGuid *string) (dto.DeviceView, error) {
	if _, _, err := s.authz.AssertDeviceAccess(ctx, actorGuid, rbac.CodeDevicesAssign, guid); err != nil {
		return dto.DeviceView{}, err
	}
	before, err := s.peers.FindByUUID(ctx, guid)
	if err != nil {
		return dto.DeviceView{}, fmt.Errorf("device: load before assign: %w", err)
	}

	// 解析目标：空 = 解绑置 NULL；非空 = 目标用户必须存在（400）。
	var (
		targetGuid *string
		action     string
	)
	if userGuid != nil && *userGuid != "" {
		u, err := s.users.FindByGuid(ctx, *userGuid)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return dto.DeviceView{}, rbac.ErrBadRequest(msgUserNotFound)
			}
			return dto.DeviceView{}, err
		}
		g := u.Guid
		targetGuid = &g
		action = ActionDeviceAssign
	} else {
		action = ActionDeviceUnassign
	}

	if err := s.peers.UpdateColumnsByUUID(ctx, guid, map[string]any{"userGuid": targetGuid}); err != nil {
		return dto.DeviceView{}, fmt.Errorf("device: assign userGuid: %w", err)
	}

	// console_audits 留痕（allowed；写入失败仅告警不阻断，best-effort
	// 模式同 rbac/audit.go RecordDenied）。
	s.recordAssignAudit(ctx, actorGuid, guid, action, derefString(before.UserGuid), derefString(targetGuid))

	p, err := s.peers.FindByUUID(ctx, guid)
	if err != nil {
		return dto.DeviceView{}, fmt.Errorf("device: reload after assign: %w", err)
	}
	views := s.assembler.deviceViews(ctx, []entity.Peer{*p}, time.Now())
	return views[0], nil
}

// recordAssignAudit 归属变化留痕：before/afterState 均为 {"userGuid": ...}
// 形态（空 = 无属主）。audit 未装配或写入失败仅告警，不阻断主流程。
func (s *AssignService) recordAssignAudit(ctx context.Context, actorGuid, deviceGuid, action, before, after string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, rbac.AuditRecord{
		ActorUserGuid: actorGuid,
		TargetType:    auditTargetDevice,
		TargetGuid:    deviceGuid,
		Action:        action,
		Result:        rbac.AuditResultAllowed,
		BeforeState:   assignStateJSON(before),
		AfterState:    assignStateJSON(after),
		RequestID:     rbac.RequestIDFrom(ctx),
	})
}

// assignStateJSON 序列化 {"userGuid": v} 留痕载荷（空值序列化为空串
// 形态，保持 JSON 键存在以便 diff 可读）。
func assignStateJSON(userGuid string) string {
	raw, err := json.Marshal(map[string]string{auditStateKey: userGuid})
	if err != nil {
		return "{}"
	}
	return string(raw)
}

// MyDevices 当前用户名下设备分页（GET /api/users/me/devices；auth 档，
// 不设权限码）：仅 peers.userGuid = 当前用户；响应为精简 MyDeviceView
// （OQ-4：不含 strategyGuid/username 等管理面字段）。
func (s *AssignService) MyDevices(ctx context.Context, userGuid string, q dto.PaginationQuery) (dto.MyDevicePage, error) {
	rows, total, err := s.peers.ListByUserGuid(ctx, userGuid, q.Current, q.PageSize)
	if err != nil {
		return dto.MyDevicePage{}, fmt.Errorf("device: list my devices: %w", err)
	}
	now := time.Now()
	page := dto.MyDevicePage{
		Data:  make([]dto.MyDeviceView, 0, len(rows)),
		Total: int(total),
	}
	for i := range rows {
		p := &rows[i]
		page.Data = append(page.Data, dto.MyDeviceView{
			Uuid:            p.UUID,
			Id:              p.ID,
			Note:            p.Note,
			Status:          p.Status,
			IsOnline:        p.Online(now, repository.OnlineWindow),
			LastHeartbeat:   p.LastHeartbeat,
			DeviceGroupGuid: p.DeviceGroupGuid,
		})
	}
	return page, nil
}

// UserDevices 按用户反查设备分页（GET /api/users/{guid}/devices；
// users.view 档在路由）：目标用户不存在 → 404 User not found；
// 行形状复用 DeviceView 分页。
func (s *AssignService) UserDevices(ctx context.Context, targetGuid string, q dto.PaginationQuery) (dto.PageResult[dto.DeviceView], error) {
	if _, err := s.users.FindByGuid(ctx, targetGuid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.PageResult[dto.DeviceView]{}, rbac.ErrNotFoundErr(msgUserNotFound)
		}
		return dto.PageResult[dto.DeviceView]{}, err
	}
	rows, total, err := s.peers.ListByUserGuid(ctx, targetGuid, q.Current, q.PageSize)
	if err != nil {
		return dto.PageResult[dto.DeviceView]{}, fmt.Errorf("device: list user devices: %w", err)
	}
	views := s.assembler.deviceViews(ctx, rows, time.Now())
	return dto.PageResult[dto.DeviceView]{Data: views, Total: total}, nil
}
