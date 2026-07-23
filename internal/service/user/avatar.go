package user

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// maxAvatarSize 头像大小上限（2MB）。
const maxAvatarSize = 2 << 20

// avatarFilenamePattern 静态头像文件名白名单（共享知识 15）：
// 仅小写 hex 与连字符 + .webp，天然排除 ../ 等穿越序列。
var avatarFilenamePattern = regexp.MustCompile(`^[a-f0-9-]+\.webp$`)

// AvatarService 头像存储：DATA_DIR/avatars，文件名 {userGuid}.webp。
type AvatarService struct {
	users *repository.UserRepo
	// dir 头像目录（DATA_DIR/avatars）。
	dir string
}

// NewAvatarService 构建服务（目录按需创建）。
func NewAvatarService(users *repository.UserRepo, dataDir string) *AvatarService {
	return &AvatarService{users: users, dir: filepath.Join(dataDir, "avatars")}
}

// Upload 校验并保存头像（multipart 文件内容），返回对外文件名。
// 约束：仅 webp（RIFF/WEBP 魔数嗅探）、≤2MB、文件名={guid}.webp。
func (s *AvatarService) Upload(ctx context.Context, guid string, file io.Reader, size int64) (api.AvatarResponse, error) {
	if size > maxAvatarSize {
		return api.AvatarResponse{}, authsvc.BadRequest("Avatar must be at most 2MB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAvatarSize+1))
	if err != nil {
		return api.AvatarResponse{}, authsvc.BadRequest("Failed to read avatar upload")
	}
	if len(data) > maxAvatarSize {
		return api.AvatarResponse{}, authsvc.BadRequest("Avatar must be at most 2MB")
	}
	if !isWebp(data) {
		return api.AvatarResponse{}, authsvc.BadRequest("Avatar must be a WebP image")
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return api.AvatarResponse{}, fmt.Errorf("avatar: mkdir %s: %w", s.dir, err)
	}
	filename := guid + ".webp"
	if err := os.WriteFile(filepath.Join(s.dir, filename), data, 0o644); err != nil {
		return api.AvatarResponse{}, fmt.Errorf("avatar: write %s: %w", filename, err)
	}
	if err := s.users.UpdateColumns(ctx, guid, map[string]any{
		"avatar":    filename,
		"updatedAt": time.Now(),
	}); err != nil {
		return api.AvatarResponse{}, err
	}
	return api.AvatarResponse{Avatar: filename}, nil
}

// Delete 删除头像文件并清空 avatar 列（文件不存在视为已删除）。
func (s *AvatarService) Delete(ctx context.Context, guid string) (api.MessageResponse, error) {
	if err := s.users.UpdateColumns(ctx, guid, map[string]any{
		"avatar":    "",
		"updatedAt": time.Now(),
	}); err != nil {
		return api.MessageResponse{}, err
	}
	// 文件清理失败不影响列状态（下次上传覆盖）。
	_ = os.Remove(filepath.Join(s.dir, guid+".webp"))
	return api.MessageResponse{Message: "Avatar deleted"}, nil
}

// Serve 将头像文件写入 w（含 Content-Type 与 Cache-Control）。
// filename 必须通过白名单正则与 resolve 双重校验（防路径穿越）。
// 返回 false 表示资源不存在（调用侧输出 404）。
func (s *AvatarService) Serve(w http.ResponseWriter, filename string) bool {
	// 白名单：hex+连字符+.webp，排除一切路径分隔符。
	if !avatarFilenamePattern.MatchString(filename) {
		return false
	}
	full := filepath.Join(s.dir, filename)
	// resolve 防穿越：Join 后必须仍在头像目录内（防御性双保险）。
	absDir, err := filepath.Abs(s.dir)
	if err != nil {
		return false
	}
	absFile, err := filepath.Abs(full)
	if err != nil || absFile != filepath.Join(absDir, filepath.Base(absFile)) {
		return false
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "image/webp")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	return true
}

// isWebp 嗅探 RIFF/WEBP 魔数（文件头 12 字节）。
func isWebp(b []byte) bool {
	return len(b) >= 12 && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WEBP"
}
