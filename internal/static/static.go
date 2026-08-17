// Package static 提供静态资源服务（M3 扩展点①，设计 §1.2/§1.1⑨）：
//
//	SPAHandler   —— go:embed dist 的单页应用托管；/api、/files、/avatars
//	                三前缀之外的全部 GET 回 index.html（SPA fallback，
//	                共享知识 25）；三前缀内未匹配路径回 NestJS 风格 404。
//	FilesHandler —— /files/{path} 服务 nexus 构建产物（DATA_DIR/nexus），
//	                safeJoin 防路径穿越（穿越面 → 400 Invalid path）。
//	WebpHandler  —— 头像安全文件服务工具：文件名白名单正则
//	                ^[a-f0-9-]+\.webp$ + resolve 防御（T03 avatar 域接入）。
//
// 参考项目为纯 API（无静态托管）；/ 与 /files 为 Go 单二进制形态新增
// 能力（M3 批复 #5），无兼容基线。
package static

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/httpx"
)

//go:embed dist
var distFS embed.FS

// excludedPrefixes SPA fallback 的排除前缀（共享知识 25，逐字节契约）。
var excludedPrefixes = []string{"/api", "/files", "/avatars"}

// webpNameRe 头像文件名白名单（共享知识 25）：
// 仅允许 hex/连字符组成的 guid 形态 + .webp 后缀——天然排除
// ../ 穿越、路径分隔符与任意扩展名。
var webpNameRe = regexp.MustCompile(`^[a-f0-9-]+\.webp$`)

// indexHTML 构建期读出占位页（dist 由前端仓库构建流程灌入，
// M3 期间为占位 index.html，保证 embed 可编译；设计 §5.1）。
var indexHTML = func() []byte {
	data, err := fs.ReadFile(distFS, "dist/index.html")
	if err != nil {
		// embed 指令保证 dist 目录存在；缺失属编程错误，启动期快速失败。
		panic("static: embedded dist/index.html missing: " + err.Error())
	}
	return data
}()

// SPAHandler 返回 SPA 托管 handler（挂载于 mux 的 "GET /" 兜底位）。
//
// 行为：路径命中排除前缀（精确或子路径）→ NestJS 风格 404 包络
// （对齐参考未知 API 路径形态）；其余 GET 一律 200 + text/html 的
// index.html（前端路由接管）。
func SPAHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		for _, prefix := range excludedPrefixes {
			if p == prefix || strings.HasPrefix(p, prefix+"/") {
				httpx.Fail(w, http.StatusNotFound, "Cannot "+r.Method+" "+p)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})
}

// FilesHandler 返回 nexus 产物服务 handler（挂载于 "GET /files/{path...}"）。
//
// 行为：r.PathValue("path") 与 nexusDir 做 safeJoin（resolve 后
// relative 判定，rel 以 .. 起始或逃逸根目录 → 400 Invalid path，
// 与 nexus 下载共用同一安全语义，设计事实⑤）；命中文件以
// application/octet-stream + attachment 直出（M3 批复 #8：文件名
// 上游已按 basename 白名单化）。
func FilesHandler(nexusDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rel := r.PathValue("path")
		if rel == "" {
			httpx.Fail(w, http.StatusBadRequest, "Invalid path")
			return
		}
		root, err := filepath.Abs(nexusDir)
		if err != nil {
			httpx.ErrInternal(w)
			return
		}
		// safeJoin：Join + Abs 归一，结果必须仍在根目录内。
		target := filepath.Join(root, filepath.FromSlash(rel))
		target, err = filepath.Abs(target)
		if err != nil || target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			httpx.Fail(w, http.StatusBadRequest, "Invalid path")
			return
		}
		data, err := os.ReadFile(target)
		if err != nil {
			if os.IsNotExist(err) {
				httpx.ErrNotFound(w, "File not found")
				return
			}
			httpx.ErrInternal(w)
			return
		}
		httpx.WriteBinary(w, path.Base(filepath.ToSlash(target)), data)
	})
}

// WebpHandler 返回头像安全文件服务 handler（挂载于头像静态路由）。
//
// 行为：文件名必须命中白名单正则（^[a-f0-9-]+\.webp$，共享知识 25），
// 未命中 → 404；命中后仍做 resolve 防御（纵深防御），以
// image/webp + public 缓存直出（设计事实①：Cache-Control max-age 86400）。
func WebpHandler(dir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("filename")
		if !webpNameRe.MatchString(name) {
			httpx.ErrNotFound(w, "Avatar not found")
			return
		}
		root, err := filepath.Abs(dir)
		if err != nil {
			httpx.ErrInternal(w)
			return
		}
		target, err := filepath.Abs(filepath.Join(root, name))
		if err != nil || target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			httpx.ErrNotFound(w, "Avatar not found")
			return
		}
		data, err := os.ReadFile(target)
		if err != nil {
			if os.IsNotExist(err) {
				httpx.ErrNotFound(w, "Avatar not found")
				return
			}
			httpx.ErrInternal(w)
			return
		}
		w.Header().Set("Content-Type", "image/webp")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}
