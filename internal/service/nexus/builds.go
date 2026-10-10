package nexus

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"time"

	"gorm.io/gorm"

	"github.com/google/uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// fileItem 产物清单落库单元（nexus_builds.files JSON 形态）。
type fileItem struct {
	Filename string `json:"filename"`
	Size     *int   `json:"size,omitempty"`
}

// CreateBuild 提交定制构建（POST 特例 201）：取绑定态 Bearer → 上游 /v1/build；
// 上游错误按矩阵映射；成功后落库 nexus_builds（status:pending）并返回视图。
func (s *NexusService) CreateBuild(ctx context.Context, userGuid string, dto api.NexusGenerateDto) (*api.NexusBuildView, error) {
	tok, err := s.requireToken(ctx, userGuid)
	if err != nil {
		return nil, err
	}
	body := map[string]any{
		"os":     string(dto.Os),
		"arch":   string(dto.Arch),
		"custom": dto.Custom,
	}
	var resp struct {
		Uuid   string `json:"uuid"`
		Status string `json:"status"`
	}
	status, raw, err := s.upstreamJSON(ctx, http.MethodPost, "/v1/build", body, tok.NexusToken, &resp)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return nil, mapBuildError(status, raw)
	}

	uuidStr := resp.Uuid
	if uuidStr == "" {
		uuidStr = uuid.New().String()
	}
	customJSON, err := json.Marshal(dto.Custom)
	if err != nil {
		return nil, err
	}
	rec := entity.NexusBuild{
		Uuid:      uuidStr,
		UserGuid:  userGuid,
		Os:        string(dto.Os),
		Arch:      string(dto.Arch),
		Custom:    string(customJSON),
		Status:    entity.NexusStatusPending,
		CreatedAt: time.Now(),
	}
	if appName := dto.Custom["app-name"]; appName != "" {
		rec.AppName = &appName
	}
	if err := s.db.WithContext(ctx).Create(&rec).Error; err != nil {
		return nil, err
	}
	return toBuildView(&rec), nil
}

// ListBuilds 列出当前用户的构建任务（created_at DESC）。
func (s *NexusService) ListBuilds(ctx context.Context, userGuid string) ([]api.NexusBuildView, error) {
	var rows []entity.NexusBuild
	if err := s.db.WithContext(ctx).
		Where("userGuid = ?", userGuid).
		Order("createdAt DESC").
		Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]api.NexusBuildView, 0, len(rows))
	for i := range rows {
		out = append(out, *toBuildView(&rows[i]))
	}
	return out, nil
}

// findOwnedBuild 按 uuid + 归属查询构建；跨用户或无记录 → 404。
func (s *NexusService) findOwnedBuild(ctx context.Context, userGuid, buildUuid string) (*entity.NexusBuild, error) {
	var rec entity.NexusBuild
	err := s.db.WithContext(ctx).Where("uuid = ? AND userGuid = ?", buildUuid, userGuid).First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, rbac.ErrNotFoundErr("Build task not found")
	}
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// CancelBuild 取消构建（DELETE 特例 204）：仅 pending/building 可取消；
// 终态或不存在（含跨用户）→ 404/409。
func (s *NexusService) CancelBuild(ctx context.Context, userGuid, buildUuid string) error {
	rec, err := s.findOwnedBuild(ctx, userGuid, buildUuid)
	if err != nil {
		return err
	}
	if !rec.IsPolling() {
		return rbac.ErrConflictMsg("Build task cannot be cancelled in current status")
	}
	rec.Status = entity.NexusStatusCanceled
	return s.db.WithContext(ctx).Save(&rec).Error
}

// ListFiles 返回构建产物清单（GET builds/{uuid}/files）：跨用户 → 404。
func (s *NexusService) ListFiles(ctx context.Context, userGuid, buildUuid string) (api.BuildFiles, error) {
	rec, err := s.findOwnedBuild(ctx, userGuid, buildUuid)
	if err != nil {
		return api.BuildFiles{}, err
	}
	return toBuildFiles(rec.Files), nil
}

// ResolveFile 安全解析构建产物绝对路径（safeJoin 防穿越）；穿越 → ErrInvalidPath。
// 调用方须已通过 findOwnedBuild 归属校验。
func (s *NexusService) ResolveFile(buildUuid, filename string) (string, error) {
	return s.storage.SafeJoin(filepath.Join(buildUuid, filename))
}

// ReadFile 读取已解析的绝对产物路径字节。
func (s *NexusService) ReadFile(absPath string) ([]byte, error) {
	return s.storage.ReadFile(absPath)
}

// DownloadFile 下载构建产物：先校验归属（跨用户 → 404），再 safeJoin（穿越
// → ErrInvalidPath 映射 400）并读取字节。文件名白名单由 handler 层先行过滤。
//
// 产物缺失/非普通文件 → 404 Build artifact not found（不泄漏 500）。
func (s *NexusService) DownloadFile(ctx context.Context, userGuid, buildUuid, filename string) ([]byte, error) {
	if _, err := s.findOwnedBuild(ctx, userGuid, buildUuid); err != nil {
		return nil, err
	}
	abs, err := s.ResolveFile(buildUuid, filename)
	if err != nil {
		return nil, err
	}
	data, err := s.ReadFile(abs)
	if errors.Is(err, ErrArtifactNotFound) {
		return nil, rbac.ErrNotFoundErr("Build artifact not found")
	}
	return data, err
}

// toBuildView 实体 → 视图（created_at 零值省略）。
//
// 状态映射（共享知识 17 / openapi NexusBuildView.status enum）：库内沿用
// 兼容基准字面量 'done' / 'canceled'，对外视图枚举为
// 'completed' / 'cancelled'——映射集中于此单一出口，避免两套字面量
// 在各调用点漂移。
func toBuildView(b *entity.NexusBuild) *api.NexusBuildView {
	v := &api.NexusBuildView{
		Uuid:   b.Uuid,
		Os:     b.Os,
		Arch:   b.Arch,
		Status: toViewStatus(b.Status),
	}
	if b.Custom != "" {
		c := b.Custom
		v.Custom = &c
	}
	if b.Message != "" {
		m := b.Message
		v.Message = &m
	}
	if !b.CreatedAt.IsZero() {
		t := b.CreatedAt
		v.CreatedAt = &t
	}
	return v
}

// toViewStatus 库内状态字面量 → 对外视图枚举（唯一映射出口）。
func toViewStatus(status string) api.NexusBuildViewStatus {
	switch status {
	case entity.NexusStatusDone:
		return api.NexusBuildViewStatusCompleted
	case entity.NexusStatusCanceled:
		return api.NexusBuildViewStatusCancelled
	case entity.NexusStatusBuilding:
		return api.NexusBuildViewStatusBuilding
	case entity.NexusStatusFailed:
		return api.NexusBuildViewStatusFailed
	default:
		// pending 及任何未识别中间态一律回 pending（枚举收敛）。
		return api.NexusBuildViewStatusPending
	}
}

// toBuildFiles 解析 nexus_builds.files JSON → BuildFiles 视图。
func toBuildFiles(jsonStr string) api.BuildFiles {
	out := api.BuildFiles{}
	if jsonStr == "" {
		return out
	}
	var items []fileItem
	if err := json.Unmarshal([]byte(jsonStr), &items); err != nil {
		return out
	}
	for _, it := range items {
		out.Files = append(out.Files, struct {
			Filename string `json:"filename"`
			Size     *int   `json:"size,omitempty"`
		}{Filename: it.Filename, Size: it.Size})
	}
	return out
}

// ListPolling 返回仍处于轮询窗口（pending|building）的构建（poller 使用）。
func (s *NexusService) ListPolling(ctx context.Context) ([]entity.NexusBuild, error) {
	var rows []entity.NexusBuild
	err := s.db.WithContext(ctx).
		Where("status IN ?", []string{entity.NexusStatusPending, entity.NexusStatusBuilding}).
		Find(&rows).Error
	return rows, err
}

// updateBuildStatus 落库构建终态 + 产物清单（poller 使用）。
func (s *NexusService) updateBuildStatus(ctx context.Context, buildUuid, status, message string, files []fileItem) error {
	filesJSON, err := json.Marshal(files)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Model(&entity.NexusBuild{}).
		Where("uuid = ?", buildUuid).
		Updates(map[string]any{
			"status":  status,
			"message": message,
			"files":   string(filesJSON),
		}).Error
}
