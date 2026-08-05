// Package device 本文件：AdminService——/devices 管理域（设计 §3.1
// DeviceAdminService）：列表（scope 边界）、批量启停、更新、删除、断连。
// 全部动作先经 rbac.AuthorizationService 资源级复核（assertDevice*：
// 404 存在性 → 403 scope；红线：授权一律实时查库）。
package device

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// 关联名称解析失败的业务文案（400 包络，对齐参考 device.service）。
const (
	msgUserNotFound        = "User not found"
	msgDeviceGroupNotFound = "Device group not found"
	msgStrategyNotFound    = "Strategy not found"
)

// AdminService /devices 管理域服务。
type AdminService struct {
	authz     *rbac.AuthorizationService
	assembler viewAssembler
	peers     *repository.PeerRepo
	store     *DisconnectStore
}

// NewAdminService 构建管理域服务。
func NewAdminService(
	authz *rbac.AuthorizationService,
	peers *repository.PeerRepo,
	sysinfos *repository.SysinfoRepo,
	users *repository.UserRepo,
	groups *repository.DeviceGroupRepo,
	strategies *repository.StrategyRepo,
	store *DisconnectStore,
) *AdminService {
	return &AdminService{
		authz: authz,
		assembler: viewAssembler{
			sysinfos: sysinfos, users: users, groups: groups, strategies: strategies,
		},
		peers: peers,
		store: store,
	}
}

// GetDevices 管理设备列表（devices.view）：handler 复取 scope 由本方法
// 内部完成（GetPermissionScope 与路由中间件同语义，设计 §1.3），
// 随后 ListScoped——scoped 操作者排除未分组设备（§4.3）。
func (s *AdminService) GetDevices(ctx context.Context, actorGuid string, q dto.DeviceListQuery) (dto.PageResult[dto.DeviceView], error) {
	scope, err := s.authz.GetPermissionScope(ctx, actorGuid, rbac.CodeDevicesView)
	if err != nil {
		return dto.PageResult[dto.DeviceView]{}, err
	}
	filter := repository.DeviceFilter{
		ID:              q.ID,
		Status:          q.Status,
		IsOnline:        q.IsOnline,
		DeviceName:      q.DeviceName,
		UserName:        q.UserName,
		DeviceUsername:  q.DeviceUsername,
		OS:              q.OS,
		DeviceGroupName: q.DeviceGroupName,
		DeviceGroupGuid: q.DeviceGroupGuid,
		GroupName:       q.GroupName,
		Current:         q.Current,
		PageSize:        q.PageSize,
	}
	rows, total, err := s.peers.ListScoped(ctx, guidSet(scope), filter)
	if err != nil {
		return dto.PageResult[dto.DeviceView]{}, fmt.Errorf("device: list scoped peers: %w", err)
	}
	views := s.assembler.deviceViews(ctx, rows, time.Now())
	return dto.PageResult[dto.DeviceView]{Data: views, Total: total}, nil
}

// UpdateStatus 批量启停（devices.status）：任一设备不存在 → 404 Device
// not found；任一越出 scope → 403 Batch request contains unauthorized
// devices（AssertDevicesAccess 整体拒绝，不部分成功）。逐设备落库，
// 单点失败计入 failed（不中断批次）。
func (s *AdminService) UpdateStatus(ctx context.Context, actorGuid string, req dto.DeviceStatusUpdateRequest) (dto.DeviceStatusUpdateResult, error) {
	if _, _, err := s.authz.AssertDevicesAccess(ctx, actorGuid, rbac.CodeDevicesStatus, req.Guids); err != nil {
		return dto.DeviceStatusUpdateResult{}, err
	}
	status := entity.PeerStatusDisabled
	if req.Status == "enabled" {
		status = entity.PeerStatusActive
	}
	res := dto.DeviceStatusUpdateResult{
		Succeeded: []string{},
		Failed:    []string{},
		Total:     len(req.Guids),
	}
	for _, guid := range req.Guids {
		if err := s.peers.SetStatus(ctx, guid, status); err != nil {
			res.Failed = append(res.Failed, guid)
			continue
		}
		res.Succeeded = append(res.Succeeded, guid)
	}
	res.SucceededCount = len(res.Succeeded)
	res.FailedCount = len(res.Failed)
	return res, nil
}

// UpdateDevice 更新设备（devices.edit）：
//   - note：任意 devices.edit 操作者可改；
//   - 关联字段（userName/deviceGroupName/strategyName，按名称匹配）
//     变更需 super administrator（roles 路线 403 文案）；空串=解绑
//     （置 NULL），名称不存在 → 400；
//   - 指针 nil 字段不更新（三态语义）。
func (s *AdminService) UpdateDevice(ctx context.Context, actorGuid, guid string, req dto.UpdateDeviceRequest) (dto.DeviceView, error) {
	if _, _, err := s.authz.AssertDeviceAccess(ctx, actorGuid, rbac.CodeDevicesEdit, guid); err != nil {
		return dto.DeviceView{}, err
	}
	if req.UserName != nil || req.DeviceGroupName != nil || req.StrategyName != nil {
		if _, err := s.authz.RequireSuperAdmin(ctx, actorGuid); err != nil {
			return dto.DeviceView{}, err
		}
	}

	updates := map[string]any{}
	if req.Note != nil {
		updates["note"] = *req.Note
	}
	if req.UserName != nil {
		if *req.UserName == "" {
			updates["userGuid"] = nil
		} else {
			u, err := s.assembler.users.FindByUsername(ctx, *req.UserName)
			if err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					return dto.DeviceView{}, rbac.ErrBadRequest(msgUserNotFound)
				}
				return dto.DeviceView{}, err
			}
			updates["userGuid"] = u.Guid
		}
	}
	if req.DeviceGroupName != nil {
		if *req.DeviceGroupName == "" {
			updates["deviceGroupGuid"] = nil
		} else {
			g, err := s.assembler.groups.FindByName(ctx, *req.DeviceGroupName)
			if err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					return dto.DeviceView{}, rbac.ErrBadRequest(msgDeviceGroupNotFound)
				}
				return dto.DeviceView{}, err
			}
			updates["deviceGroupGuid"] = g.Guid
		}
	}
	if req.StrategyName != nil {
		if *req.StrategyName == "" {
			updates["strategyGuid"] = nil
		} else {
			st, err := s.assembler.strategies.FindByName(ctx, *req.StrategyName)
			if err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					return dto.DeviceView{}, rbac.ErrBadRequest(msgStrategyNotFound)
				}
				return dto.DeviceView{}, err
			}
			updates["strategyGuid"] = st.Guid
		}
	}

	if len(updates) > 0 {
		if err := s.peers.UpdateColumnsByUUID(ctx, guid, updates); err != nil {
			return dto.DeviceView{}, fmt.Errorf("device: update columns: %w", err)
		}
	}
	p, err := s.peers.FindByUUID(ctx, guid)
	if err != nil {
		return dto.DeviceView{}, fmt.Errorf("device: reload after update: %w", err)
	}
	views := s.assembler.deviceViews(ctx, []entity.Peer{*p}, time.Now())
	return views[0], nil
}

// DeleteDevice 删除设备（devices.delete）：事务显式级联删除
// active_connections（共享知识 9：应用层事务级联，方言统一）。
func (s *AdminService) DeleteDevice(ctx context.Context, actorGuid, uuid string) error {
	if _, _, err := s.authz.AssertDeviceAccess(ctx, actorGuid, rbac.CodeDevicesDelete, uuid); err != nil {
		return err
	}
	return s.peers.DeleteWithConns(ctx, uuid)
}

// Disconnect 断开设备连接（devices.disconnect）：校验通过后将 connIds
// 入队，客户端下一次心跳收到 disconnect 键；响应 pending_disconnect_count
// 为当前 pending 总数（含本次入队）。
func (s *AdminService) Disconnect(ctx context.Context, actorGuid, uuid string, connIDs []int64) (dto.DisconnectResult, error) {
	if _, _, err := s.authz.AssertDeviceAccess(ctx, actorGuid, rbac.CodeDevicesDisconnect, uuid); err != nil {
		return dto.DisconnectResult{}, err
	}
	s.store.AddPending(uuid, connIDs)
	return dto.DisconnectResult{PendingDisconnectCount: len(s.store.Pending(uuid))}, nil
}

// guidSet rbac.PermissionScope → 仓储 GuidSet（Global 语义等价透传）。
func guidSet(scope rbac.PermissionScope) repository.GuidSet {
	if scope.Global {
		return repository.GuidSet{Global: true}
	}
	guids := make([]string, 0, len(scope.DeviceGroupGuids))
	for g := range scope.DeviceGroupGuids {
		guids = append(guids, g)
	}
	return repository.GuidSet{Guids: guids}
}
