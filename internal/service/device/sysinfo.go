// Package device 本文件：SysinfoService——设备系统信息上报（设计 §4.2）。
// 按 uuid 查 peers，不存在直接拒绝（不自动注册，与 heartbeat 相反）；
// 存在则 upsert sysinfos（核心字段"提供即覆盖"、preset 列"非空真值才
// 覆盖"）并处理 preset-device-group-name 关联与 preset-note 兜底；
// preset-address-book-* 字段接受不处理（M3 通讯录联动）。
package device

import (
	"context"
	"errors"
	"log/slog"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// Sysinfo 设备系统信息上报响应文本（httpx.WriteText 契约，openapi enum）。
const (
	SysinfoUpdated  = "SYSINFO_UPDATED"
	SysinfoNotFound = "ID_NOT_FOUND"
)

// SysinfoService 设备系统信息服务。
type SysinfoService struct {
	peers    *repository.PeerRepo
	sysinfos *repository.SysinfoRepo
	groups   *repository.DeviceGroupRepo
	logger   *slog.Logger
}

// NewSysinfoService 构建系统信息服务。
func NewSysinfoService(
	peers *repository.PeerRepo,
	sysinfos *repository.SysinfoRepo,
	groups *repository.DeviceGroupRepo,
	logger *slog.Logger,
) *SysinfoService {
	return &SysinfoService{peers: peers, sysinfos: sysinfos, groups: groups, logger: logger}
}

// Upsert 系统信息上报：返回 found=false 表示设备未注册（handler 输出
// ID_NOT_FOUND；HTTP 恒 200，错误仅指基础设施故障）。
func (s *SysinfoService) Upsert(ctx context.Context, req dto.SysinfoRequest) (bool, error) {
	if _, err := s.peers.FindByUUID(ctx, req.UUID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// 设备未注册：sysinfo 不自动注册（红线，与 heartbeat 相反）。
			return false, nil
		}
		return false, err
	}

	existing, err := s.sysinfos.FindByUUID(ctx, req.UUID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return false, err
	}

	row := entity.Sysinfo{
		UUID:                  req.UUID,
		Hostname:              req.Hostname,
		Username:              req.Username,
		OS:                    req.OS,
		CPU:                   req.CPU,
		Memory:                req.Memory,
		PresetUsername:        req.PresetUsername,
		PresetStrategyName:    req.PresetStrategyName,
		PresetDeviceGroupName: req.PresetDeviceGroupName,
	}
	if existing != nil {
		// 覆盖规则（非指针绑定的语义下两者一致）：请求值为空串一律保留
		// 存量——核心字段"提供即覆盖"（空串视为未提供）；preset 列
		// "非空真值才覆盖"。
		if row.Hostname == "" {
			row.Hostname = existing.Hostname
		}
		if row.Username == "" {
			row.Username = existing.Username
		}
		if row.OS == "" {
			row.OS = existing.OS
		}
		if row.CPU == "" {
			row.CPU = existing.CPU
		}
		if row.Memory == "" {
			row.Memory = existing.Memory
		}
		if row.PresetUsername == "" {
			row.PresetUsername = existing.PresetUsername
		}
		if row.PresetStrategyName == "" {
			row.PresetStrategyName = existing.PresetStrategyName
		}
		if row.PresetDeviceGroupName == "" {
			row.PresetDeviceGroupName = existing.PresetDeviceGroupName
		}
	}
	if err := s.sysinfos.Upsert(ctx, &row); err != nil {
		return false, err
	}

	// preset-device-group-name 非空：按名关联设备组并回写 peers；
	// 组不存在仅告警跳过（与参考一致）。
	if req.PresetDeviceGroupName != "" {
		g, gerr := s.groups.FindByName(ctx, req.PresetDeviceGroupName)
		switch {
		case gerr == nil:
			if uerr := s.peers.UpdateDeviceGroupGuid(ctx, req.UUID, g.Guid); uerr != nil {
				return false, uerr
			}
		case errors.Is(gerr, repository.ErrNotFound):
			if s.logger != nil {
				s.logger.Warn("device: preset device group not found, skip association",
					"uuid", req.UUID, "group", req.PresetDeviceGroupName)
			}
		default:
			return false, gerr
		}
	}

	// preset-note 非空：仅当 peers.note 为空时兜底写入（不覆盖已有注记）。
	if req.PresetNote != "" {
		if err := s.peers.FillNoteIfEmpty(ctx, req.UUID, req.PresetNote); err != nil {
			return false, err
		}
	}
	return true, nil
}
