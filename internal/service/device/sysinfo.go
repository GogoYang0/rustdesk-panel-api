// Package device 本文件：SysinfoService——设备系统信息上报（设计 §4.2）。
// 按 uuid 查 peers，不存在直接拒绝（不自动注册，与 heartbeat 相反）；
// 存在则 upsert sysinfos（核心字段"提供即覆盖"、preset 列"非空真值
// 才覆盖"）并处理 preset-device-group-name 关联与 preset-note 兜底；
// preset-address-book-* 联动（M2 批复 #3，M3 T05 落地）：在超管名下
// findOrCreate 名为 preset-address-book-name 的 custom 地址簿，upsert
// 设备为该书的 ab peer（alias/note/password 语义）并按
// preset-address-book-tag 幂等关联标签；失败仅记日志不阻断。
package device

import (
	"context"
	"errors"
	"log/slog"
	"strings"

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
	peers          *repository.PeerRepo
	sysinfos       *repository.SysinfoRepo
	groups         *repository.DeviceGroupRepo
	users          *repository.UserRepo
	abBooks        *repository.AddressBookRepo
	abPeers        *repository.AddressBookPeerRepo
	abTags         *repository.AddressBookTagRepo
	abPeerTags     *repository.AddressBookPeerTagRepo
	adminUsername  string
	logger         *slog.Logger
}

// NewSysinfoService 构建系统信息服务（ab 联动仓储与超管用户名为
// M3 T05 增量；users/ab* 传 nil 时联动静默跳过——兼容旧装配）。
func NewSysinfoService(
	peers *repository.PeerRepo,
	sysinfos *repository.SysinfoRepo,
	groups *repository.DeviceGroupRepo,
	users *repository.UserRepo,
	abBooks *repository.AddressBookRepo,
	abPeers *repository.AddressBookPeerRepo,
	abTags *repository.AddressBookTagRepo,
	abPeerTags *repository.AddressBookPeerTagRepo,
	adminUsername string,
	logger *slog.Logger,
) *SysinfoService {
	return &SysinfoService{
		peers: peers, sysinfos: sysinfos, groups: groups,
		users: users, abBooks: abBooks, abPeers: abPeers,
		abTags: abTags, abPeerTags: abPeerTags,
		adminUsername: adminUsername, logger: logger,
	}
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

	// preset-address-book-* 联动（M2 批复 #3）：失败仅记日志不阻断。
	s.associateAddressBook(ctx, req)
	return true, nil
}

// associateAddressBook preset-address-book-* 联动：name 非空时在超管
// 名下 findOrCreate custom 书并 upsert ab peer + 标签关联。任何失败
// 仅 Warn（联动是尽力而为的部署预置，不得阻断 sysinfo 主流程）。
func (s *SysinfoService) associateAddressBook(ctx context.Context, req dto.SysinfoRequest) {
	if req.PresetAddressBookName == "" {
		return
	}
	if s.abBooks == nil || s.abPeers == nil || s.abTags == nil || s.abPeerTags == nil || s.users == nil {
		return
	}
	name := strings.TrimSpace(req.PresetAddressBookName)
	if name == "" {
		return
	}
	warn := func(step string, err error) {
		if s.logger != nil {
			s.logger.Warn("device: preset address book association skipped",
				"step", step, "uuid", req.UUID, "book", name, "error", err.Error())
		}
	}

	// owner=超管（部署预置语义：设备自动进入管理员视角的地址簿）。
	admin, err := s.users.FindByUsernameOrEmail(ctx, s.adminUsername)
	if err != nil {
		warn("resolve-admin", err)
		return
	}
	book, err := s.abBooks.FindOrCreateCustom(ctx, admin.Guid, name)
	if err != nil {
		warn("find-or-create-book", err)
		return
	}

	// upsert ab peer（deviceId=设备 uuid；alias/note/password 提供即覆盖）。
	peer, err := s.abPeers.Upsert(ctx, &entity.AddressBookPeer{
		AddressBookGuid: book.Guid,
		DeviceId:        req.UUID,
		Hash:            nil,
		Password:        nonEmptyStr(req.PresetAddressBookPassword),
		Alias:           nonEmptyStr(req.PresetAddressBookAlias),
		Note:            req.PresetAddressBookNote,
	})
	if err != nil {
		warn("upsert-peer", err)
		return
	}

	// 标签关联（preset-address-book-tag 逗号分隔多值；幂等并集）。
	if req.PresetAddressBookTag == "" {
		return
	}
	have := make(map[string]struct{})
	if existing, err := s.abPeerTags.TagsByPeer(ctx, peer.Guid); err == nil {
		for _, t := range existing {
			have[t.Guid] = struct{}{}
		}
	}
	for _, raw := range strings.Split(req.PresetAddressBookTag, ",") {
		tagName := strings.TrimSpace(raw)
		if tagName == "" {
			continue
		}
		tag, err := s.abTags.FindOrCreate(ctx, book.Guid, tagName, 0)
		if err != nil {
			warn("ensure-tag:"+tagName, err)
			continue
		}
		if _, ok := have[tag.Guid]; ok {
			continue
		}
		have[tag.Guid] = struct{}{}
		if err := s.abPeerTags.ReplaceForPeer(ctx, peer.Guid, keysOf(have)); err != nil {
			warn("link-tag:"+tagName, err)
			return
		}
	}
}

// nonEmptyStr 空串→nil（ab peers 可空列语义）。
func nonEmptyStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// keysOf 集合键列表。
func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
