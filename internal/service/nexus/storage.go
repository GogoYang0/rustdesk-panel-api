// Package nexus 实现 M3 nexus 域（设计事实⑤）：GitHub 设备码绑定 +
// 定制构建提交/轮询落盘 + 产物 safeJoin 下载。上游固定代理
// NEXUS_UPSTREAM（默认 https://api.databk.top）。
package nexus

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidPath safeJoin 穿越面（rel 以 .. 起始或逃逸根目录）。
// 映射为 400 Invalid path（与 static.FilesHandler 同一安全语义，批复 #8）。
var ErrInvalidPath = errors.New("invalid path")

// Storage 管理 DATA_DIR/nexus 产物布局与 safeJoin 防路径穿越。
type Storage struct {
	root string
}

// NewStorage 构建产物存储（root = dataDir/nexus）。
func NewStorage(dataDir string) *Storage {
	return &Storage{root: filepath.Join(dataDir, "nexus")}
}

// Root 返回并确保产物根目录存在，返回绝对路径。
func (s *Storage) Root() (string, error) {
	abs, err := filepath.Abs(s.root)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", err
	}
	return abs, nil
}

// BuildDir 返回指定构建 uuid 的产物目录（确保存在）。
func (s *Storage) BuildDir(uuid string) (string, error) {
	root, err := s.Root()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, uuid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

// WriteFile 将产物字节写入 buildDir/{filename}（调用方须已白名单过文件名）。
func (s *Storage) WriteFile(uuid, filename string, content []byte) error {
	dir, err := s.BuildDir(uuid)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, filename), content, 0o644)
}

// ReadFile 读取落盘产物（已 safeJoin 校验后的绝对路径）。
func (s *Storage) ReadFile(absPath string) ([]byte, error) {
	return os.ReadFile(absPath)
}

// SafeJoin 将 rel 解析到 root 内：rel 含 .. 段逃逸根目录 → ErrInvalidPath
// （设计事实⑤：rel.startsWith('..') → 400 Invalid path）。resolve 后
// 必须仍在 root 内（含 root 自身）。语义与 static.FilesHandler 一致。
func (s *Storage) SafeJoin(rel string) (string, error) {
	root, err := s.Root()
	if err != nil {
		return "", err
	}
	// 防御：归一后若首个分量即 ".." 或整体为 ".." → 直接拒绝。
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", ErrInvalidPath
	}
	target := filepath.Join(root, filepath.FromSlash(rel))
	target, err = filepath.Abs(target)
	if err != nil {
		return "", ErrInvalidPath
	}
	if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return "", ErrInvalidPath
	}
	return target, nil
}
