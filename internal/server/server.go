// Package server 负责 http.Server 组装与优雅关闭（自 M0 main.go 迁出），
// 以及路由表注册（openapi paths 的镜像）。
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/config"
)

// Version 由构建时 -ldflags "-X github.com/.../internal/server.Version=..." 注入。
var Version = "dev"

// Server 包装 http.Server，提供阻塞运行与优雅关闭。
type Server struct {
	http   *http.Server
	logger *slog.Logger
}

// NewHTTPServer 组装 http.Server（ReadHeaderTimeout 10s，防 slowloris）。
func NewHTTPServer(cfg config.Config, handler http.Handler, logger *slog.Logger) *Server {
	return &Server{
		http: &http.Server{
			Addr:              cfg.HTTPAddr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// Run 阻塞监听；ctx 取消后以 10s 宽限期优雅关闭并返回 nil。
// 监听失败返回错误。
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("rustdesk-panel-api listening", "addr", s.http.Addr, "version", Version)
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("graceful shutdown failed", "err", err)
		}
		return nil
	}
}
