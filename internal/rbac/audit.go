package rbac

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/logger"
)

// AuditService 控制台审计（等价 ConsoleAuditInterceptor 的显式调用形态，
// 设计 §1.3）：RBAC 拒绝路径记 denied（失败仅告警）；角色/用户角色服务
// 在事务内记 allowed（before/after 全量快照）；其余变更端点在 handler
// 成功路径记 allowed（afterState=脱敏后请求体）。
type AuditService struct {
	store  AuditStore
	logger *slog.Logger
}

// AuditStore 审计持久化端口。T02 由 repository.ConsoleAuditRepo 经
// server 装配层适配接入；T01 允许为 nil（Record 仅告警跳过）。
type AuditStore interface {
	CreateAudit(ctx context.Context, rec AuditRecord) error
}

// AuditRecord console_audits 行载荷（列名见实体 consoleaudit.go）。
type AuditRecord struct {
	ActorUserGuid string
	TargetType    string
	TargetGuid    string
	Action        string
	Result        string // allowed | denied
	Reason        string
	BeforeState   string
	AfterState    string
	RequestID     string
}

// NewAuditService 构建审计服务。
func NewAuditService(store AuditStore, logger *slog.Logger) *AuditService {
	return &AuditService{store: store, logger: logger}
}

// Record 写入一条审计；持久化错误向上传播（事务调用方需要回滚）。
// store 未接入时告警跳过。
func (s *AuditService) Record(ctx context.Context, rec AuditRecord) error {
	if s.store == nil {
		s.warn("audit store not wired, record dropped", rec)
		return nil
	}
	return s.store.CreateAudit(ctx, rec)
}

// RecordDenied 写入拒绝审计：失败仅告警不阻断（设计 §1.1② 决策算法 7）。
func (s *AuditService) RecordDenied(ctx context.Context, rec AuditRecord) {
	rec.Result = AuditResultDenied
	if err := s.Record(ctx, rec); err != nil {
		s.warn("record denied audit failed", rec)
	}
}

// warn 输出告警日志（nil logger 安全）。
func (s *AuditService) warn(msg string, rec AuditRecord) {
	if s.logger == nil {
		return
	}
	s.logger.Warn(msg, "action", rec.Action, "targetType", rec.TargetType,
		"targetGuid", rec.TargetGuid, "requestId", rec.RequestID)
}

// RequestIDFrom 便捷取请求 ID（无则空串）。
func RequestIDFrom(ctx context.Context) string {
	return logger.RequestIDFromContext(ctx)
}

// sensitiveKeyPattern 匹配需要脱敏的键名（与参考一致：
// password/token/secret/verifier/credential/api[_-]?key…）。
var sensitiveKeyPattern = regexp.MustCompile(`(?i)(password|token|secret|verifier|credential|api[_-]?key)`)

// RedactJSON 序列化 v 并对敏感键值替换为 "[REDACTED]"（递归遍历
// object/array）。序列化失败返回 "{}"。
func RedactJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return string(raw)
	}
	redacted := redactValue(doc)
	out, err := json.Marshal(redacted)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// redactValue 递归脱敏：map 键命中敏感正则 → 替换值；数组逐项处理。
func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if sensitiveKeyPattern.MatchString(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = redactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redactValue(val)
		}
		return out
	default:
		return v
	}
}
