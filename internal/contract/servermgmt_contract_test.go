package contract

import (
	"net/http"
	"testing"
)

// TestContractServerMGMT 服务器域（M3 T06，事实③）契约双向校验：
// 认证挡 401、无节点配置时列表 200 空数组、未注册节点转发 404（契约允许）。
// 错误映射矩阵（503/502/...）在 internal/service/servermgmt/forward_test.go
// 以假 agent 逐条锁定。
func TestContractServerMGMT(t *testing.T) {
	cs, _ := newAuthContractServer(t)
	token, _ := abLogin(t, cs)

	// 未认证 → 401（servers.view 档）。
	cs.get(t, "/api/servers", nil, http.StatusUnauthorized)
	// 已认证、RUSTDESK_NODES 未配置 → 200 空数组（并发握手无节点）。
	cs.get(t, "/api/servers", bearer(token), http.StatusOK)
	// 未注册节点 → 404（契约允许 404，forwarder 返回 Server node not found）。
	cs.get(t, "/api/servers/ghost/peers", bearer(token), http.StatusNotFound)
	cs.get(t, "/api/servers/ghost/sessions", bearer(token), http.StatusNotFound)
	cs.get(t, "/api/servers/ghost/services/hbbs/config", bearer(token), http.StatusNotFound)
}
