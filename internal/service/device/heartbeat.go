// Package device 本文件：HeartbeatService——设备心跳上报全链
// （设计 §4.1）：心跳落库（未知设备自动注册，Upsert OnConflict 并发
// 首跳安全）→ conns diff 事务同步 → 断连确认出队 → 策略解析与下发门槛。
package device

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// HeartbeatService 设备心跳服务。
type HeartbeatService struct {
	peers      *repository.PeerRepo
	conns      *repository.ActiveConnectionRepo
	strategies *repository.StrategyRepo
	users      *repository.UserRepo
	groups     *repository.DeviceGroupRepo
	store      *DisconnectStore
	logger     *slog.Logger
	// now 可注入时钟（测试锚定 is_online 与门槛比较；生产 time.Now）。
	now func() time.Time
}

// NewHeartbeatService 构建心跳服务。
func NewHeartbeatService(
	peers *repository.PeerRepo,
	conns *repository.ActiveConnectionRepo,
	strategies *repository.StrategyRepo,
	users *repository.UserRepo,
	groups *repository.DeviceGroupRepo,
	store *DisconnectStore,
	logger *slog.Logger,
) *HeartbeatService {
	return &HeartbeatService{
		peers:      peers,
		conns:      conns,
		strategies: strategies,
		users:      users,
		groups:     groups,
		store:      store,
		logger:     logger,
		now:        time.Now,
	}
}

// Handle 心跳全链（设计 §4.1 步骤 3-11）：
//
//  1. UpsertHeartbeat：不存在则 INSERT（status 走 DB 默认 1），存在则仅
//     更新心跳列——两种路径同为一条 OnConflict 语句，无需分支；
//  2. conns 键存在（指针非 nil）时：diff 前先取现存连接，将"本次未上报
//     的存量连接"（客户端不再上报 = 已断开确认）从断连队列移除，
//     再 DiffSyncConns 事务同步快照；
//  3. pending 断连非空 → 响应携带 disconnect 键；
//  4. findStrategyForDevice 三级回退解析策略，仅当
//     strategy.updatedAt(毫秒) 严格大于报文 modified_at 才下发
//     （config_options + 新 modified_at），否则响应为 {}（或仅含 disconnect）。
func (s *HeartbeatService) Handle(ctx context.Context, req dto.HeartbeatRequest) (dto.HeartbeatResponse, error) {
	now := s.now().UTC()
	if err := s.peers.UpsertHeartbeat(ctx, req.UUID, req.ID, req.Ver, req.ModifiedAt, now); err != nil {
		return dto.HeartbeatResponse{}, err
	}

	if req.Conns != nil {
		reported := *req.Conns
		// 断连确认：对比 diff 前的存量连接，消失者出队。
		// （客户端收到 disconnect 键后断开连接，随之停止上报该 connId。）
		existing, err := s.ActiveConnectionIds(ctx, req.UUID)
		if err != nil {
			return dto.HeartbeatResponse{}, err
		}
		if len(existing) > 0 {
			reportedSet := make(map[int64]struct{}, len(reported))
			for _, c := range reported {
				reportedSet[c] = struct{}{}
			}
			gone := make([]int64, 0, len(existing))
			for _, c := range existing {
				if _, ok := reportedSet[c]; !ok {
					gone = append(gone, c)
				}
			}
			if len(gone) > 0 {
				s.store.RemoveDisconnected(req.UUID, gone)
			}
		}
		if err := s.peers.DiffSyncConns(ctx, req.UUID, reported); err != nil {
			return dto.HeartbeatResponse{}, err
		}
	}

	resp := dto.HeartbeatResponse{}
	if pending := s.store.Pending(req.UUID); len(pending) > 0 {
		resp.Disconnect = pending
	}

	strat, err := s.findStrategyForDevice(ctx, req.UUID)
	if err != nil {
		return dto.HeartbeatResponse{}, err
	}
	if strat != nil && strat.UpdatedAt.UnixMilli() > req.ModifiedAt {
		resp.Strategy = &dto.StrategyOptionsPayload{ConfigOptions: ParseConfigOptions(strat.ConfigOptions)}
		resp.ModifiedAt = strat.UpdatedAt.UnixMilli()
	}
	return resp, nil
}

// ActiveConnectionIds 设备当前活跃连接 ID（断连确认 diff 与视图组装共用）。
func (s *HeartbeatService) ActiveConnectionIds(ctx context.Context, uuid string) ([]int64, error) {
	return s.conns.ListConnIds(ctx, uuid)
}

// findStrategyForDevice 设备端策略解析（设计 §1.1④）：
// peers.strategyGuid → users.strategyGuid（经 peers.userGuid）→
// device_groups.strategyGuid（经 peers.deviceGroupGuid），逐级回退，
// 均无（或悬空引用，防御）→ nil。悬空引用继续回退的原因：删除策略的
// 事务会置空三处引用，但历史数据/手工运维可能残留脏 guid。
func (s *HeartbeatService) findStrategyForDevice(ctx context.Context, uuid string) (*entity.Strategy, error) {
	peer, err := s.peers.FindByUUID(ctx, uuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// UpsertHeartbeat 刚注册的理论不可达；防御性返回无策略。
			return nil, nil
		}
		return nil, err
	}
	// ① 设备直挂策略。
	strat, err := s.strategyByGuid(ctx, peer.StrategyGuid)
	if strat != nil || err != nil {
		return strat, err
	}
	// ② 归属用户的策略。
	if peer.UserGuid != nil {
		u, uerr := s.users.FindByGuid(ctx, *peer.UserGuid)
		if uerr != nil && !errors.Is(uerr, repository.ErrNotFound) {
			return nil, uerr
		}
		if uerr == nil {
			strat, err = s.strategyByGuid(ctx, u.StrategyGuid)
			if strat != nil || err != nil {
				return strat, err
			}
		}
	}
	// ③ 归属设备组的策略。
	if peer.DeviceGroupGuid != nil {
		g, gerr := s.groups.FindByID(ctx, *peer.DeviceGroupGuid)
		if gerr != nil && !errors.Is(gerr, repository.ErrNotFound) {
			return nil, gerr
		}
		if gerr == nil {
			return s.strategyByGuid(ctx, g.StrategyGuid)
		}
	}
	return nil, nil
}

// strategyByGuid 按 guid 取策略；guid 为空或策略不存在（悬空引用）返回
// (nil, nil) 继续下一级回退；其余错误透传。
func (s *HeartbeatService) strategyByGuid(ctx context.Context, guid *string) (*entity.Strategy, error) {
	if guid == nil || *guid == "" {
		return nil, nil
	}
	strat, err := s.strategies.FindByID(ctx, *guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			if s.logger != nil {
				s.logger.Warn("device: dangling strategy reference, fallback to next level", "strategyGuid", *guid)
			}
			return nil, nil
		}
		return nil, err
	}
	return strat, nil
}

// ParseConfigOptions 解析 strategies.configOptions（TEXT JSON 串）为
// API 契约的 Record<string,string>（设计 §1.1④）。空串 → {}；
// 解析失败或非 map[string]string 形态（脏数据防御）→ {}，
// 保证 heartbeat 响应恒符合 openapi config_options 契约。
func ParseConfigOptions(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" {
		return out
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return out
	}
	if m == nil {
		return out
	}
	return m
}
