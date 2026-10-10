// Package updatecheck 本文件：版本更新检查（设计事实④，M3 T07）。
//
// 每小时后台 POST {NEXUS_UPSTREAM}/v1/update/check（15s 超时），遥测 payload
// 含 version/deployment(channel+install_id)/system/runtime/database/
// statistics；install_id 落 system_settings（key=system.installId，含 legacy
// key 迁移）；结果内存缓存 + frontend_version 持久化（category=update_check）。
// 查询参数 frontend_version 仅影响响应中 frontend 分支的比对基准。
package updatecheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// system_settings 键（共享知识 18/19）。
const (
	// KeyInstallID 安装实例 id（新键）。
	KeyInstallID = "system.installId"
	// KeyInstallIDLegacy legacy 键（读取时回退并迁移至新键）。
	KeyInstallIDLegacy = "install_id"
	// KeyUpdateChannel 更新渠道（stable|nightly）。
	KeyUpdateChannel = "update_channel"
	// KeyFrontendVersion 前端版本持久化（category=update_check）。
	KeyFrontendVersion = "update_check.frontendVersion"
	// category 归段。
	categorySystem       = "system"
	categoryUpdateCheck  = "update_check"
)

// updateCheckPath 上游检查路径。
const updateCheckPath = "/v1/update/check"

// requestTimeout 上游请求超时（设计事实④：15s）。
const requestTimeout = 15 * time.Second

// defaultChannel 缺省渠道（设计事实④）。
const defaultChannel = "stable"

// maxResponseBody 上游响应体上限。
const maxResponseBody = 1 << 20

// ChannelStable / ChannelNightly 合法渠道枚举（共享知识 19）。
const (
	ChannelStable  = "stable"
	ChannelNightly = "nightly"
)

// IsValidChannel 报告渠道是否合法（env UPDATE_CHANNEL 与库值共用）。
func IsValidChannel(channel string) bool {
	return channel == ChannelStable || channel == ChannelNightly
}

// Service 版本更新检查服务。
type Service struct {
	upstream string
	version  string
	channel  string
	settings *repository.SystemSettingRepo
	// counters 业务统计来源（可为 nil，nil 时计 0）。
	counters Counters
	// client 可注入 HTTP 客户端（测试用）；默认 15s 超时客户端。
	client *http.Client
	// now 可注入虚拟时钟（测试用）；默认 time.Now。
	now func() time.Time

	// mu 保护 cache（内存缓存）。
	mu    sync.RWMutex
	cache *dto.UpdateCheckResultView
}

// Counters 业务统计计数器（由仓储实现的窄接口，避免包级耦合）。
type Counters interface {
	CountAllUsers(ctx context.Context) (int64, error)
	CountAllDevices(ctx context.Context) (int64, error)
	CountAllGroups(ctx context.Context) (int64, error)
	CountAllStrategies(ctx context.Context) (int64, error)
}

// Options 构建参数。
type Options struct {
	// Upstream 上游基址（NEXUS_UPSTREAM，仅测试覆写）。
	Upstream string
	// Version 面板版本号。
	Version string
	// Channel 更新渠道（UPDATE_CHANNEL，env fallback）。
	Channel string
	// Settings system_settings 仓储。
	Settings *repository.SystemSettingRepo
	// Counters 统计来源（可为 nil）。
	Counters Counters
}

// NewService 构建服务。
func NewService(opts Options) *Service {
	channel := opts.Channel
	if !IsValidChannel(channel) {
		channel = defaultChannel
	}
	return &Service{
		upstream: strings.TrimRight(opts.Upstream, "/"),
		version:  opts.Version,
		channel:  channel,
		settings: opts.Settings,
		counters: opts.Counters,
		client:   &http.Client{Timeout: requestTimeout},
		now:      time.Now,
	}
}

// Get 读取更新检查结果。
//
// 内存缓存未命中时同步刷新一次上游（首个请求不空等 cron tick）；
// frontendVersion 非空时覆盖 frontend 分支的 current 基准。
func (s *Service) Get(ctx context.Context, frontendVersion string) (dto.UpdateCheckResultView, error) {
	if frontendVersion != "" {
		if err := s.settings.Set(ctx, KeyFrontendVersion, frontendVersion, categoryUpdateCheck); err != nil {
			return dto.UpdateCheckResultView{}, err
		}
	} else {
		stored, err := s.settings.Get(ctx, KeyFrontendVersion)
		if err == nil {
			frontendVersion = stored.Value
		} else if !isNotFound(err) {
			return dto.UpdateCheckResultView{}, err
		}
	}
	s.mu.RLock()
	cached := s.cache
	s.mu.RUnlock()
	if cached != nil {
		return applyFrontendVersion(*cached, frontendVersion), nil
	}
	result, err := s.Refresh(ctx)
	if err != nil {
		// 上游不可用时不阻断面板：返回零更新结果（hasUpdate=false）。
		fallback := dto.UpdateCheckResultView{}
		fallback.Backend.Current = s.version
		fallback.Backend.Latest = s.version
		fallback.Frontend.Current = frontendVersion
		fallback.Frontend.Latest = frontendVersion
		installID, _ := s.InstallID(ctx)
		fallback.InstallId = &installID
		return fallback, nil
	}
	return applyFrontendVersion(result, frontendVersion), nil
}

// Refresh 立即执行一次上游检查并刷新缓存（cron 与首请求共用）。
func (s *Service) Refresh(ctx context.Context) (dto.UpdateCheckResultView, error) {
	installID, err := s.InstallID(ctx)
	if err != nil {
		return dto.UpdateCheckResultView{}, err
	}
	payload, err := s.buildPayload(ctx, installID)
	if err != nil {
		return dto.UpdateCheckResultView{}, err
	}
	upstream, err := s.postUpstream(ctx, payload)
	if err != nil {
		return dto.UpdateCheckResultView{}, err
	}
	result := s.buildResult(upstream, installID, "")
	s.mu.Lock()
	s.cache = &result
	s.mu.Unlock()
	return result, nil
}

// InstallID 读取（必要时生成并迁移）安装实例 id。
//
// 迁移语义：新键缺失而 legacy 键存在时，把 legacy 值提升为新键
// （保留 legacy 键不删，兼容回滚）。
func (s *Service) InstallID(ctx context.Context) (string, error) {
	if row, err := s.settings.Get(ctx, KeyInstallID); err == nil {
		if strings.TrimSpace(row.Value) != "" {
			return row.Value, nil
		}
	} else if !isNotFound(err) {
		return "", err
	}
	if row, err := s.settings.Get(ctx, KeyInstallIDLegacy); err == nil {
		if legacy := strings.TrimSpace(row.Value); legacy != "" {
			if err := s.settings.Set(ctx, KeyInstallID, legacy, categorySystem); err != nil {
				return "", err
			}
			return legacy, nil
		}
	} else if !isNotFound(err) {
		return "", err
	}
	generated, err := newInstallID()
	if err != nil {
		return "", err
	}
	if err := s.settings.Set(ctx, KeyInstallID, generated, categorySystem); err != nil {
		return "", err
	}
	return generated, nil
}

// Channel 生效渠道：库值优先（合法时），否则 env 缺省。
func (s *Service) Channel(ctx context.Context) string {
	row, err := s.settings.Get(ctx, KeyUpdateChannel)
	if err == nil {
		if stored := strings.TrimSpace(row.Value); IsValidChannel(stored) {
			return stored
		}
	}
	return s.channel
}

// buildPayload 组装遥测 payload（gopsutil 采集 system/runtime，统计取计数器）。
func (s *Service) buildPayload(ctx context.Context, installID string) (dto.UpdateCheckPayload, error) {
	payload := dto.UpdateCheckPayload{
		Version: s.version,
		Deployment: dto.UpdateDeploymentInfo{
			Channel:   s.Channel(ctx),
			InstallID: installID,
		},
		System: dto.UpdateSystemInfo{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Runtime: dto.UpdateRuntimeInfo{
			GoVersion: runtime.Version(),
		},
		Database: dto.UpdateDatabaseInfo{Driver: "sqlite"},
	}
	if info, err := host.Info(); err == nil && info != nil {
		payload.System.Hostname = info.Hostname
		payload.Runtime.UptimeSec = int64(info.Uptime)
	}
	if counts, err := cpu.Counts(true); err == nil {
		payload.System.CPUCount = counts
	}
	if vm, err := mem.VirtualMemory(); err == nil && vm != nil {
		payload.System.MemTotal = vm.Total
	}
	if s.counters != nil {
		if n, err := s.counters.CountAllUsers(ctx); err == nil {
			payload.Stats.Users = n
		}
		if n, err := s.counters.CountAllDevices(ctx); err == nil {
			payload.Stats.Devices = n
		}
		if n, err := s.counters.CountAllGroups(ctx); err == nil {
			payload.Stats.Groups = n
		}
		if n, err := s.counters.CountAllStrategies(ctx); err == nil {
			payload.Stats.Strategy = n
		}
	}
	return payload, nil
}

// postUpstream POST 遥测 payload 并解析上游结果。
func (s *Service) postUpstream(ctx context.Context, payload dto.UpdateCheckPayload) (dto.UpdateCheckUpstream, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return dto.UpdateCheckUpstream{}, fmt.Errorf("update-check: encode payload failed: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.upstream+updateCheckPath, bytes.NewReader(body))
	if err != nil {
		return dto.UpdateCheckUpstream{}, fmt.Errorf("update-check: build request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return dto.UpdateCheckUpstream{}, fmt.Errorf("update-check: upstream request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return dto.UpdateCheckUpstream{}, fmt.Errorf("update-check: read upstream failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return dto.UpdateCheckUpstream{}, fmt.Errorf("update-check: upstream returned status %d", resp.StatusCode)
	}
	var out dto.UpdateCheckUpstream
	if err := json.Unmarshal(raw, &out); err != nil {
		return dto.UpdateCheckUpstream{}, fmt.Errorf("update-check: decode upstream failed: %w", err)
	}
	return out, nil
}

// buildResult 上游结果 → 面板响应（缺分支时回退当前版本，hasUpdate=false）。
func (s *Service) buildResult(upstream dto.UpdateCheckUpstream, installID, frontendVersion string) dto.UpdateCheckResultView {
	out := dto.UpdateCheckResultView{}
	out.Backend.Current = s.version
	out.Backend.Latest = s.version
	if upstream.Backend != nil && upstream.Backend.Version != "" {
		out.Backend.Latest = upstream.Backend.Version
		out.Backend.HasUpdate = compareVersion(upstream.Backend.Version, s.version) > 0
		if out.Backend.HasUpdate && upstream.Backend.DownloadURL != "" {
			url := upstream.Backend.DownloadURL
			out.Backend.DownloadUrl = &url
		}
	}
	out.Frontend.Current = frontendVersion
	out.Frontend.Latest = frontendVersion
	if upstream.Frontend != nil && upstream.Frontend.Version != "" {
		out.Frontend.Latest = upstream.Frontend.Version
		out.Frontend.HasUpdate = compareVersion(upstream.Frontend.Version, frontendVersion) > 0
		if out.Frontend.HasUpdate && upstream.Frontend.DownloadURL != "" {
			url := upstream.Frontend.DownloadURL
			out.Frontend.DownloadUrl = &url
		}
	}
	id := installID
	out.InstallId = &id
	return out
}

// applyFrontendVersion 仅替换 frontend 分支的比对基准（内存缓存共享，
// 不因查询参数污染缓存本体）。
func applyFrontendVersion(base dto.UpdateCheckResultView, frontendVersion string) dto.UpdateCheckResultView {
	out := base
	out.Frontend.Current = frontendVersion
	out.Frontend.HasUpdate = compareVersion(out.Frontend.Latest, frontendVersion) > 0
	if !out.Frontend.HasUpdate {
		out.Frontend.DownloadUrl = nil
	}
	return out
}

// compareVersion 语义化版本比较：返回 >0 表示 a 比 b 新。
//
// 解析失败时退化为字符串非等值比较（保守判为有更新）。
func compareVersion(a, b string) int {
	av, aok := parseVersion(a)
	bv, bok := parseVersion(b)
	if !aok || !bok {
		if a == b {
			return 0
		}
		return 1
	}
	for i := 0; i < 3; i++ {
		if av[i] != bv[i] {
			if av[i] > bv[i] {
				return 1
			}
			return -1
		}
	}
	return 0
}

// parseVersion 解析 "v?X.Y.Z" 形态为三段整数。
func parseVersion(raw string) ([3]int, bool) {
	var out [3]int
	trimmed := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if trimmed == "" {
		return out, false
	}
	// 去掉预发布后缀（-rc.1 等）。
	if idx := strings.IndexAny(trimmed, "-+"); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// newInstallID 生成 32 位十六进制安装实例 id。
func newInstallID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("update-check: generate install id failed: %w", err)
	}
	return fmt.Sprintf("%x", buf), nil
}

// isNotFound 判定仓储未找到（避免直接依赖 gorm 错误类型）。
func isNotFound(err error) bool {
	return err == repository.ErrNotFound || strings.Contains(err.Error(), "not found")
}
