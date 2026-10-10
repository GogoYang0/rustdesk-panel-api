// Package updatecheck 本文件：版本更新检查（v0.2.1 改版：版本源 =
// GitHub Releases）。
//
// 前端分支 ← https://api.github.com/repos/GogoYang0/rustdesk-panel-web/releases/latest；
// 后端分支 ← 同主 GogoYang0/rustdesk-panel-api。tag_name 去前导 v 即
// latest，release body 为 changelog，html_url 为 downloadUrl；GitHub
// 不可达时该分支回退 current==latest、hasUpdate=false（不阻断面板）。
// 保留每小时遥测 POST {NEXUS_UPSTREAM}/v1/update/check（best-effort，
// 失败仅记日志不影响版本结果）；install_id 落 system_settings
// （key=system.installId，含 legacy key 迁移）；结果内存缓存 +
// frontend_version 持久化（category=update_check）。
package updatecheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

// updateCheckPath 上游遥测路径。
const updateCheckPath = "/v1/update/check"

// GitHub Releases 版本源（v0.2.1 问题 12）。
const (
	githubAPIBase      = "https://api.github.com"
	githubWebRepo      = "GogoYang0/rustdesk-panel-web"
	githubBackendRepo  = "GogoYang0/rustdesk-panel-api"
	githubTimeout      = 10 * time.Second
	githubAcceptHeader = "application/vnd.github+json"
)

// githubRelease GitHub Releases latest 响应（仅取所需字段）。
type githubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
}

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
	// githubClient GitHub Releases 客户端（10s 超时；测试可注入
	// githubBase 覆写基址）。
	githubClient *http.Client
	// githubBase GitHub API 基址（测试覆写；默认 https://api.github.com）。
	githubBase string
	// logger 遥测失败告警（可为 nil）。
	logger *slog.Logger
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
	// Upstream 上游基址（NEXUS_UPSTREAM 遥测，仅测试覆写）。
	Upstream string
	// GitHubBase GitHub API 基址（仅测试覆写；空=官方 api.github.com）。
	GitHubBase string
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
	githubBase := opts.GitHubBase
	if githubBase == "" {
		githubBase = githubAPIBase
	}
	return &Service{
		upstream:     strings.TrimRight(opts.Upstream, "/"),
		version:      opts.Version,
		channel:      channel,
		settings:     opts.Settings,
		counters:     opts.Counters,
		client:       &http.Client{Timeout: requestTimeout},
		githubClient: &http.Client{Timeout: githubTimeout},
		githubBase:   githubBase,
		now:          time.Now,
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
		// install_id 等基础设施故障不阻断面板：返回零更新结果
		// （hasUpdate=false）。
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

// Refresh 立即执行一次版本检查并刷新缓存（cron 与首请求共用）：
//
//  1. install_id（生成/迁移）；
//  2. 遥测 POST {NEXUS_UPSTREAM}/v1/update/check（best-effort，失败
//     仅记日志——v0.2.1 起版本源改为 GitHub，上游不再决定版本结果）；
//  3. GitHub Releases latest（frontend←web 仓 / backend←api 仓），
//     任一分支不可达时该分支回退 current==latest、hasUpdate=false。
func (s *Service) Refresh(ctx context.Context) (dto.UpdateCheckResultView, error) {
	installID, err := s.InstallID(ctx)
	if err != nil {
		return dto.UpdateCheckResultView{}, err
	}
	s.telemetryBestEffort(ctx, installID)

	var result dto.UpdateCheckResultView
	applyBranch(&result.Backend.Current, &result.Backend.Latest,
		&result.Backend.HasUpdate, &result.Backend.DownloadUrl, &result.Backend.Changelog,
		s.checkBranch(ctx, githubBackendRepo, s.version))
	applyBranch(&result.Frontend.Current, &result.Frontend.Latest,
		&result.Frontend.HasUpdate, &result.Frontend.DownloadUrl, &result.Frontend.Changelog,
		s.checkBranch(ctx, githubWebRepo, s.version))
	result.InstallId = &installID
	s.mu.Lock()
	s.cache = &result
	s.mu.Unlock()
	return result, nil
}

// applyBranch 分支结果写入响应视图（可空字段空串归 nil）。
func applyBranch(current, latest *string, hasUpdate *bool, downloadURL, changelog **string, out branchOut) {
	*current = out.Current
	*latest = out.Latest
	*hasUpdate = out.HasUpdate
	if out.DownloadURL != "" {
		u := out.DownloadURL
		*downloadURL = &u
	}
	if out.Changelog != "" {
		c := out.Changelog
		*changelog = &c
	}
}

// branchOut 单分支检查输出。
type branchOut struct {
	Current     string
	Latest      string
	HasUpdate   bool
	DownloadURL string
	Changelog   string
}

// checkBranch 拉取单分支 GitHub Releases latest 并组装（不可达时回退
// 无更新）。current 基准 = 面板版本号（applyFrontendVersion 会以查询
// 参数覆盖 frontend.current）。
func (s *Service) checkBranch(ctx context.Context, repo, current string) branchOut {
	rel, err := s.fetchGitHubRelease(ctx, repo)
	if err != nil {
		return branchOut{Current: current, Latest: current}
	}
	latest := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	out := branchOut{Current: current, Latest: latest}
	out.HasUpdate = compareVersion(latest, current) > 0
	if out.HasUpdate {
		out.DownloadURL = rel.HTMLURL
		out.Changelog = rel.Body
	}
	return out
}

// telemetryBestEffort 遥测上报（设计事实④保留项）：upstream 为空或
// 请求失败时静默跳过（记日志）。
func (s *Service) telemetryBestEffort(ctx context.Context, installID string) {
	if s.upstream == "" {
		return
	}
	payload, err := s.buildPayload(ctx, installID)
	if err != nil {
		s.logWarn("update-check: build payload failed", err)
		return
	}
	if _, err := s.postUpstream(ctx, payload); err != nil && s.logger != nil {
		s.logWarn("update-check: telemetry upstream failed", err)
	}
}

// logWarn nil 安全告警。
func (s *Service) logWarn(msg string, err error) {
	if s.logger != nil {
		s.logger.Warn(msg, "error", err.Error())
	}
}

// WithLogger 注入日志器（bootstrap 装配）。
func (s *Service) WithLogger(l *slog.Logger) *Service {
	s.logger = l
	return s
}

// fetchGitHubRelease GET {githubBase}/repos/{repo}/releases/latest
// （10s 超时、Accept vnd.github+json、UA 必填）。
func (s *Service) fetchGitHubRelease(ctx context.Context, repo string) (githubRelease, error) {
	reqCtx, cancel := context.WithTimeout(ctx, githubTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet,
		s.githubBase+"/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return githubRelease{}, fmt.Errorf("update-check: build github request failed: %w", err)
	}
	req.Header.Set("Accept", githubAcceptHeader)
	req.Header.Set("User-Agent", "rustdesk-panel")
	resp, err := s.githubClient.Do(req)
	if err != nil {
		return githubRelease{}, fmt.Errorf("update-check: github request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return githubRelease{}, fmt.Errorf("update-check: read github response failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return githubRelease{}, fmt.Errorf("update-check: github returned status %d", resp.StatusCode)
	}
	var out githubRelease
	if err := json.Unmarshal(raw, &out); err != nil {
		return githubRelease{}, fmt.Errorf("update-check: decode github response failed: %w", err)
	}
	return out, nil
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
