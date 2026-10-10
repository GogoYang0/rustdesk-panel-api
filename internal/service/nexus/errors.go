package nexus

import (
	"net/http"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// nexus 固定文案契约（共享知识 16/17，逐字节禁止改写）。
const (
	// msgTokenExpired 401：绑定态缺失或失效 → 提示重新绑定。
	msgTokenExpired = "Nexus token has expired, please rebind"
	// msgBuildInProgress 409：已有进行中构建任务。
	msgBuildInProgress = "A build task is already in progress"
	// msgMonthlyLimit 429→409：月构建额度（15/月）已达上限。
	msgMonthlyLimit = "Monthly build limit reached (15 per month)"
)

// upstreamError 上游非 2xx 的通用映射（绑定/轮询链路使用）：上游 503/504
// → 503；其余 → 502。仅返回 Error 包络形态（auth 端点已声明 502/503/default）。
func upstreamError(status int, _ []byte) error {
	if status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
		return &rbac.StatusError{Status: http.StatusServiceUnavailable, Message: "Nexus upstream unavailable"}
	}
	return &rbac.StatusError{Status: http.StatusBadGateway, Message: "Nexus upstream error"}
}

// mapBuildError 构建提交上游错误映射矩阵（设计事实⑤ / 共享知识 16）：
//
//	401 → 重新绑定；403 → 上游文案透传；409 → 进行中；429 → 映射 409 月限；
//	5xx → 502；其余 4xx → 502（上游异常）。
//
// raw 用于 403 透传上游文案。
func mapBuildError(status int, raw []byte) error {
	switch status {
	case http.StatusUnauthorized:
		return rbac.ErrUnauthorizedMsg(msgTokenExpired)
	case http.StatusForbidden:
		return &rbac.StatusError{Status: http.StatusForbidden, Message: string(firstLine(raw))}
	case http.StatusConflict:
		return rbac.ErrConflictMsg(msgBuildInProgress)
	case http.StatusTooManyRequests:
		return rbac.ErrConflictMsg(msgMonthlyLimit)
	case http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &rbac.StatusError{Status: http.StatusServiceUnavailable, Message: "Nexus build service unavailable"}
	default:
		return &rbac.StatusError{Status: http.StatusBadGateway, Message: "Nexus build operation failed"}
	}
}

// firstLine 取原始响应的首行（用于 403 上游文案透传，剥离换行）。
func firstLine(raw []byte) []byte {
	for i, b := range raw {
		if b == '\n' {
			return raw[:i]
		}
	}
	return raw
}
