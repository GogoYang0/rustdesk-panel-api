// Package device 本文件：QueryService——/peers 可见设备查询
// （设计 §1.1③：无权限码、JWT+状态复核；三源可见性，管理员全量）
// 与 /peers、/devices 共用的视图批量组装器（四源批量查询防 N+1）。
package device

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// FormatPeerVersion 客户端整版本号格式化（设计 §1.1③，info.version）：
//
//	major = ver / 1e6；minor = (ver % 1e6) / 1e3；
//	patch = (ver % 1e3) / 10；suffix = ver % 10
//
// 结果 major.minor.patch，suffix>0 追加 -suffix；ver=0 → 空串。
func FormatPeerVersion(ver int64) string {
	if ver == 0 {
		return ""
	}
	major := ver / 1_000_000
	minor := (ver % 1_000_000) / 1_000
	patch := (ver % 1_000) / 10
	suffix := ver % 10
	out := strconv.FormatInt(major, 10) + "." + strconv.FormatInt(minor, 10) + "." + strconv.FormatInt(patch, 10)
	if suffix > 0 {
		out += "-" + strconv.FormatInt(suffix, 10)
	}
	return out
}

// viewAssembler 视图批量组装器：sysinfos（uuid）/users（userGuid）/
// device_groups（deviceGroupGuid）/strategies（strategyGuid）四源批量
// 查询后内存拼装，避免行级 N+1。
type viewAssembler struct {
	sysinfos   *repository.SysinfoRepo
	users      *repository.UserRepo
	groups     *repository.DeviceGroupRepo
	strategies *repository.StrategyRepo
}

// peerViews 组装 PeerView 列表（/peers 契约：11 必需字段，
// 不含 userGuid/deviceGroupGuid 双键——形状差异由 DeviceView 承载）。
func (a *viewAssembler) peerViews(ctx context.Context, rows []entity.Peer, now time.Time) []dto.PeerView {
	out := make([]dto.PeerView, 0, len(rows))
	if len(rows) == 0 {
		return out
	}
	sysByUUID := a.sysinfoMap(ctx, rows)
	userByGuid := a.userMap(ctx, rows)
	groupByGuid := a.groupMap(ctx, rows)
	stratByGuid := a.strategyMap(ctx, rows)

	for i := range rows {
		p := &rows[i]
		view := dto.PeerView{
			ID:         p.ID,
			GUID:       p.UUID,
			Status:     p.Status,
			IsOnline:   p.Online(now, repository.OnlineWindow),
			LastOnline: p.LastHeartbeat,
			User:       derefString(p.UserGuid),
			Note:       p.Note,
		}
		if u, ok := userByGuid[view.User]; ok {
			view.UserName = u.Username
		}
		if g, ok := groupByGuid[derefString(p.DeviceGroupGuid)]; ok {
			view.DeviceGroupName = g.Name
		}
		if st, ok := stratByGuid[derefString(p.StrategyGuid)]; ok {
			view.StrategyName = st.Name
		}
		si := sysByUUID[p.UUID] // 缺失时零值：info 各字段空串（合法形态）
		view.Info = dto.PeerInfo{
			DeviceName: si.Hostname,
			Username:   si.Username,
			OS:         si.OS,
			Version:    FormatPeerVersion(p.Ver),
			CPU:        si.CPU,
			Memory:     si.Memory,
			IP:         "", // 恒空串（参考行为契约）
		}
		out = append(out, view)
	}
	return out
}

// deviceViews 组装 DeviceView 列表（= PeerView + userGuid/deviceGroupGuid
// 双键，camelCase 可空）。
func (a *viewAssembler) deviceViews(ctx context.Context, rows []entity.Peer, now time.Time) []dto.DeviceView {
	peers := a.peerViews(ctx, rows, now)
	out := make([]dto.DeviceView, 0, len(rows))
	for i := range rows {
		p := &rows[i]
		base := peers[i]
		out = append(out, dto.DeviceView{
			PeerView:        base,
			UserGuid:        p.UserGuid,
			DeviceGroupGuid: p.DeviceGroupGuid,
		})
	}
	return out
}

// sysinfoMap uuid → sysinfo（缺失 uuid 不出现在 map）。
func (a *viewAssembler) sysinfoMap(ctx context.Context, rows []entity.Peer) map[string]entity.Sysinfo {
	uuids := make([]string, 0, len(rows))
	for i := range rows {
		uuids = append(uuids, rows[i].UUID)
	}
	list, err := a.sysinfos.FindByUUIDs(ctx, uuids)
	if err != nil {
		return map[string]entity.Sysinfo{}
	}
	m := make(map[string]entity.Sysinfo, len(list))
	for _, si := range list {
		m[si.UUID] = si
	}
	return m
}

// userMap userGuid → user（视图仅需 username）。
func (a *viewAssembler) userMap(ctx context.Context, rows []entity.Peer) map[string]entity.User {
	guids := collectGuids(rows, func(p *entity.Peer) string { return derefString(p.UserGuid) })
	if len(guids) == 0 {
		return map[string]entity.User{}
	}
	list, err := a.users.FindByGuids(ctx, guids)
	if err != nil {
		return map[string]entity.User{}
	}
	m := make(map[string]entity.User, len(list))
	for _, u := range list {
		m[u.Guid] = u
	}
	return m
}

// groupMap deviceGroupGuid → device group（视图仅需 name）。
func (a *viewAssembler) groupMap(ctx context.Context, rows []entity.Peer) map[string]entity.DeviceGroup {
	guids := collectGuids(rows, func(p *entity.Peer) string { return derefString(p.DeviceGroupGuid) })
	if len(guids) == 0 {
		return map[string]entity.DeviceGroup{}
	}
	list, err := a.groups.FindByGuids(ctx, guids)
	if err != nil {
		return map[string]entity.DeviceGroup{}
	}
	m := make(map[string]entity.DeviceGroup, len(list))
	for _, g := range list {
		m[g.Guid] = g
	}
	return m
}

// strategyMap strategyGuid → strategy（视图仅需 name）。
func (a *viewAssembler) strategyMap(ctx context.Context, rows []entity.Peer) map[string]entity.Strategy {
	guids := collectGuids(rows, func(p *entity.Peer) string { return derefString(p.StrategyGuid) })
	if len(guids) == 0 {
		return map[string]entity.Strategy{}
	}
	list, err := a.strategies.FindByGuids(ctx, guids)
	if err != nil {
		return map[string]entity.Strategy{}
	}
	m := make(map[string]entity.Strategy, len(list))
	for _, st := range list {
		m[st.Guid] = st
	}
	return m
}

// collectGuids 抽取非空 guid 并去重。
func collectGuids(rows []entity.Peer, pick func(*entity.Peer) string) []string {
	seen := make(map[string]struct{}, len(rows))
	out := make([]string, 0, len(rows))
	for i := range rows {
		g := pick(&rows[i])
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

// derefString 空安全解引用（nil → ""）。
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// QueryService /peers 可见设备查询。
type QueryService struct {
	assembler viewAssembler
	peers     *repository.PeerRepo
}

// NewQueryService 构建查询服务。
func NewQueryService(
	peers *repository.PeerRepo,
	sysinfos *repository.SysinfoRepo,
	users *repository.UserRepo,
	groups *repository.DeviceGroupRepo,
	strategies *repository.StrategyRepo,
) *QueryService {
	return &QueryService{
		assembler: viewAssembler{sysinfos: sysinfos, users: users, groups: groups, strategies: strategies},
		peers:     peers,
	}
}

// GetAccessiblePeers 三源可见性分页（设计 §1.1③）：非管理员可见 =
// 自己名下 ∪ device_group_user_permissions 授权组内 ∪ user_user_permissions
// 被授权用户名下；管理员全量（含未分组）。viewer 来自 handler 的
// rbac.GetCurrentUser（Auth 路由状态复核），isAdmin 以查库结果为准。
func (s *QueryService) GetAccessiblePeers(ctx context.Context, viewer *rbac.UserRef, q dto.PeerListQuery) (dto.PageResult[dto.PeerView], error) {
	filter := repository.PeerFilter{
		ID:              q.ID,
		Status:          q.Status,
		IsOnline:        q.IsOnline,
		UserName:        q.UserName,
		DeviceGroupGuid: q.DeviceGroupGuid,
		DeviceGroupName: q.DeviceGroupName,
		OS:              q.OS,
		Current:         q.Current,
		PageSize:        q.PageSize,
	}
	var (
		rows  []entity.Peer
		total int64
		err   error
	)
	if viewer.IsAdmin {
		rows, total, err = s.peers.ListAll(ctx, filter)
	} else {
		rows, total, err = s.peers.ListAccessiblePeers(ctx, viewer.Guid, filter)
	}
	if err != nil {
		return dto.PageResult[dto.PeerView]{}, fmt.Errorf("device: list accessible peers: %w", err)
	}
	views := s.assembler.peerViews(ctx, rows, time.Now())
	return dto.PageResult[dto.PeerView]{Data: views, Total: total}, nil
}
