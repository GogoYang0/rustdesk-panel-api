package nexus

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// pollInterval 构建轮询周期（设计事实⑤：10s 定时扫 pending/building）。
const pollInterval = 10 * time.Second

// upstreamFile 上游构建产物清单单元（/v1/build/{uuid} 响应）。
type upstreamFile struct {
	Filename string `json:"filename"`
	Size     *int   `json:"size,omitempty"`
	URL      string `json:"url,omitempty"`
}

// Start 启动 10s 轮询后台任务（设计事实⑤）：pending/building 任务完成后
// 下载产物落 DATA_DIR/nexus 并落库终态。ctx 取消即退出。仅在进程生命周期
// 内调用（main 装配期）；单副本语义（多副本重复轮询幂等无害，README 注明）。
func (s *NexusService) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.pollOnce(ctx)
			}
		}
	}()
}

// pollOnce 单轮：拉取所有 pending/building 任务并推进状态。
func (s *NexusService) pollOnce(ctx context.Context) {
	rows, err := s.ListPolling(ctx)
	if err != nil {
		return
	}
	for i := range rows {
		s.pollBuild(ctx, &rows[i])
	}
}

// pollBuild 查询单任务上游状态并推进（完成则下载产物）。
func (s *NexusService) pollBuild(ctx context.Context, b *entity.NexusBuild) {
	// 取归属用户绑定态 token（缺失则保留 pending 待重试）。
	var tok entity.NexusToken
	if err := s.db.WithContext(ctx).Where("userGuid = ?", b.UserGuid).First(&tok).Error; err != nil {
		return
	}
	var status struct {
		Status  string         `json:"status"`
		Message string         `json:"message"`
		Files   []upstreamFile `json:"files"`
	}
	st, _, err := s.upstreamJSON(ctx, http.MethodGet, "/v1/build/"+b.Uuid, nil, tok.NexusToken, &status)
	if err != nil || st != http.StatusOK {
		return
	}
	switch status.Status {
	case "building":
		if b.Status != entity.NexusStatusBuilding {
			_ = s.db.WithContext(ctx).Model(b).Update("status", entity.NexusStatusBuilding).Error
		}
		return
	case "completed":
		files := s.downloadArtifacts(ctx, b.Uuid, tok.NexusToken, status.Files)
		_ = s.updateBuildStatus(ctx, b.Uuid, entity.NexusStatusCompleted, status.Message, files)
	case "failed":
		_ = s.updateBuildStatus(ctx, b.Uuid, entity.NexusStatusFailed, status.Message, nil)
	default:
		// pending 或未识别 → 保留，下一轮再查。
		return
	}
}

// downloadArtifacts 下载产物字节并落盘（仅 completed 调用）；失败项跳过。
func (s *NexusService) downloadArtifacts(ctx context.Context, uuid, bearer string, specs []upstreamFile) []fileItem {
	out := make([]fileItem, 0, len(specs))
	for _, f := range specs {
		path := "/v1/build/" + uuid + "/file/" + url.PathEscape(f.Filename)
		st, raw, err := s.upstreamJSON(ctx, http.MethodGet, path, nil, bearer, nil)
		if err != nil || st != http.StatusOK {
			continue
		}
		if err := s.storage.WriteFile(uuid, f.Filename, raw); err != nil {
			continue
		}
		sz := len(raw)
		out = append(out, fileItem{Filename: f.Filename, Size: &sz})
	}
	return out
}
