package servermgmt

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// 转发协议常量（事实③）。
const (
	// forwardGetTimeout GET 转发超时 10s。
	forwardGetTimeout = 10 * time.Second
	// forwardMutateTimeout 变更类转发超时 240s。
	forwardMutateTimeout = 240 * time.Second
	// maxForwardBody 响应体上限 8MB。
	maxForwardBody = 8 << 20
)

// MaxForwardBody 暴露响应体上限（handler 读取请求体时复用同一阈值）。
func MaxForwardBody() int { return maxForwardBody }

// 固定文案（共享知识 16，逐字节禁改）。
const (
	msgNodeUnavailable      = "Server node unavailable"       // 503 网络错误
	msgInvalidRequest       = "Invalid server management request" // 400/agent 400
	msgResourceNotFound     = "Server resource not found"     // 404
	msgConfigConflict       = "Server configuration conflicts" // 409→400
	msgOperationTimeout     = "Server management operation timed out" // 504
	msgOperationFailed      = "Server management operation failed"   // 其他 5xx→502
	msgInvalidResponse      = "Invalid node management response"     // 非 JSON→502
)

// Forward 经 agent 转发：构造 {url}{path} 请求，注入 Bearer token 与
// JSON 头，禁跟随重定向，按方法选择超时（GET 10s / 其他 240s），读取
// ≤8MB 响应并经错误映射矩阵统一收口。
//
// 返回：映射后的 HTTP 状态码与（成功时）上游 JSON 字节；错误以
// *rbac.StatusError 携带映射后的状态码与固定文案（handler 经
// rbac.WriteStatusError 直接出包络）。
func (c *Client) Forward(ctx context.Context, method, nodeID, path string, body []byte) (int, []byte, error) {
	node, ok := c.Node(nodeID)
	if !ok {
		return 0, nil, ErrNodeNotFound
	}

	timeout := forwardGetTimeout
	if method != http.MethodGet {
		timeout = forwardMutateTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := strings.TrimRight(node.URL, "/") + path
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, url, reqBody)
	if err != nil {
		return 0, nil, &rbac.StatusError{Status: http.StatusBadRequest, Message: msgInvalidRequest}
	}
	req.Header.Set("Authorization", "Bearer "+node.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// 网络错误（含超时）→ 503。
		if c.logger != nil {
			c.logger.Warn("servermgmt: forward network error", "node", nodeID, "path", path, "error", err.Error())
		}
		return 0, nil, &rbac.StatusError{Status: http.StatusServiceUnavailable, Message: msgNodeUnavailable}
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxForwardBody)+1))
	if err != nil {
		return 0, nil, &rbac.StatusError{Status: http.StatusBadGateway, Message: msgInvalidResponse}
	}
	if int64(len(raw)) > maxForwardBody {
		return 0, nil, &rbac.StatusError{Status: http.StatusBadGateway, Message: msgInvalidResponse}
	}

	return mapStatus(resp.StatusCode, raw)
}

// mapStatus 错误映射矩阵（事实③）：成功态透传 + JSON object 校验；
// 特定上游码映射固定文案与状态码；其他 5xx→502；非 JSON→502。
func mapStatus(code int, raw []byte) (int, []byte, error) {
	switch code {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		if !isJSONObject(raw) {
			return 0, nil, &rbac.StatusError{Status: http.StatusBadGateway, Message: msgInvalidResponse}
		}
		return code, raw, nil
	case http.StatusNoContent:
		return http.StatusNoContent, nil, nil
	case http.StatusBadRequest:
		return 0, nil, &rbac.StatusError{Status: http.StatusBadRequest, Message: msgInvalidRequest}
	case http.StatusNotFound:
		return 0, nil, &rbac.StatusError{Status: http.StatusNotFound, Message: msgResourceNotFound}
	case http.StatusConflict:
		return 0, nil, &rbac.StatusError{Status: http.StatusBadRequest, Message: msgConfigConflict}
	case http.StatusGatewayTimeout:
		return 0, nil, &rbac.StatusError{Status: http.StatusGatewayTimeout, Message: msgOperationTimeout}
	}
	if code >= 500 {
		return 0, nil, &rbac.StatusError{Status: http.StatusBadGateway, Message: msgOperationFailed}
	}
	// 其余 2xx/4xx 未列：透传上游状态码（仍校验 JSON object）。
	if !isJSONObject(raw) {
		return 0, nil, &rbac.StatusError{Status: http.StatusBadGateway, Message: msgInvalidResponse}
	}
	return code, raw, nil
}

// isJSONObject 判断字节流首个非空白字符为 '{'（事实③：响应体必须为
// JSON object）。
func isJSONObject(raw []byte) bool {
	i := 0
	for i < len(raw) && (raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\n' || raw[i] == '\r') {
		i++
	}
	return i < len(raw) && raw[i] == '{'
}
