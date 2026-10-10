// Package updatecheck 本文件：每小时 cron 调度（M3 T07）。
//
// 进程内单例（多副本会重复检查，幂等无害；与 M2 心跳同属单副本形态，
// 由 README 说明）。
package updatecheck

import (
	"context"
	"log/slog"
	"time"

	"github.com/robfig/cron/v3"
)

// hourlySpec cron 表达式：每小时第 7 分钟执行（错开整点高峰）。
const hourlySpec = "7 * * * *"

// Scheduler 后台调度器。
type Scheduler struct {
	service *Service
	logger  *slog.Logger
	cron    *cron.Cron
}

// NewScheduler 构建调度器。
func NewScheduler(service *Service, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		service: service,
		logger:  logger,
		// cron 表达式 + recover 包装：单次失败不影响后续 tick。
		cron: cron.New(cron.WithChain(cron.Recover(cronLogAdapter{logger: logger}))),
	}
}

// Start 注册每小时任务并启动；返回错误时调用方决定是否 fail-fast。
func (s *Scheduler) Start() error {
	if _, err := s.cron.AddFunc(hourlySpec, s.tick); err != nil {
		return err
	}
	s.cron.Start()
	s.logger.Info("update-check scheduler started", "spec", hourlySpec)
	return nil
}

// Stop 停止调度（等待运行中的任务结束，5s 上限）。
func (s *Scheduler) Stop() {
	if s.cron == nil {
		return
	}
	ctx := s.cron.Stop()
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		s.logger.Warn("update-check scheduler stop timed out")
	}
}

// tick 单次检查；失败仅记日志（不改变服务可用性）。
func (s *Scheduler) tick() {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout+5*time.Second)
	defer cancel()
	if _, err := s.service.Refresh(ctx); err != nil {
		s.logger.Warn("update-check refresh failed", "error", err)
		return
	}
	s.logger.Info("update-check refreshed")
}

// cronLogAdapter 把 cron 内部错误日志桥接到 slog。
type cronLogAdapter struct {
	logger *slog.Logger
}

// Info 实现 cron.Logger 的 InfoPrintf。
func (a cronLogAdapter) Info(msg string, keysAndValues ...interface{}) {
	a.logger.Info("update-check cron", append([]interface{}{"message", msg}, keysAndValues...)...)
}

// Error 实现 cron.Logger 的 ErrorPrintf。
func (a cronLogAdapter) Error(err error, msg string, keysAndValues ...interface{}) {
	a.logger.Error("update-check cron", append([]interface{}{"message", msg, "error", err}, keysAndValues...)...)
}
