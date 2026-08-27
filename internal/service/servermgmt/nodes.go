// Package servermgmt 服务器管理转发域（设计事实③）：RUSTDESK_NODES 解析
// 校验（启动 fail-fast）、并发 /v1/status 握手，以及统一收口的转发客户端
// 与错误映射矩阵。零新增依赖，纯 net/http 实现。
package servermgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// Node 服务器节点配置（RUSTDESK_NODES 元素，事实③）。
type Node struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	URL   string `json:"url"`   // 纯 HTTP(S) origin（pathname=/、无 query/hash）
	Token string `json:"token"` // ≥32 字符
}

// nodeIDRe id 格式：^[a-zA-Z0-9_-]{1,64}$（事实③）。
var nodeIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// NodeStatus 节点握手状态（GET servers 响应元素）。
type NodeStatus struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Reachable  bool   `json:"reachable"`
	Services   []any  `json:"services"`
	ApiVersion int    `json:"api_version,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
}

// maxNodes RUSTDESK_NODES 节点数上限（事实③）。
const maxNodes = 100

// ParseNodes 解析并校验 RUSTDESK_NODES（事实③：启动校验失败直接终止进程）。
func ParseNodes(raw string) ([]Node, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var nodes []Node
	if err := json.Unmarshal([]byte(raw), &nodes); err != nil {
		return nil, fmt.Errorf("RUSTDESK_NODES: invalid JSON array: %w", err)
	}
	if len(nodes) > maxNodes {
		return nil, fmt.Errorf("RUSTDESK_NODES: too many nodes (%d > %d)", len(nodes), maxNodes)
	}
	seen := make(map[string]struct{}, len(nodes))
	for i, n := range nodes {
		if !nodeIDRe.MatchString(n.ID) {
			return nil, fmt.Errorf("RUSTDESK_NODES[%d]: invalid id %q (must match %s)", i, n.ID, nodeIDRe.String())
		}
		if _, dup := seen[n.ID]; dup {
			return nil, fmt.Errorf("RUSTDESK_NODES: duplicate node id %q", n.ID)
		}
		seen[n.ID] = struct{}{}
		if n.Name == "" || len(n.Name) > 100 {
			return nil, fmt.Errorf("RUSTDESK_NODES[%d]: name must be non-empty and <=100", i)
		}
		if len(n.Token) < 32 {
			return nil, fmt.Errorf("RUSTDESK_NODES[%d]: token must be >=32 chars", i)
		}
		if !isPureOrigin(n.URL) {
			return nil, fmt.Errorf("RUSTDESK_NODES[%d]: url must be a pure http(s) origin (no path/query/fragment)", i)
		}
	}
	return nodes, nil
}

// isPureOrigin url 必须为纯 HTTP(S) origin：scheme http/https、host 非空、
// 无 query/fragment、path 为空或 "/"（事实③）。
func isPureOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Host == "" {
		return false
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Path == "" || u.Path == "/"
}

// Client 服务器管理转发客户端（无新增依赖，net/http）。
type Client struct {
	nodes      []Node
	byID       map[string]Node
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient 构建转发客户端（nodes 可为空切片；logger 可 nil）。
func NewClient(nodes []Node, logger *slog.Logger) *Client {
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}
	return &Client{
		nodes:  nodes,
		byID:  byID,
		logger: logger,
		httpClient: &http.Client{
			// 超时按请求覆盖；此处为上限保险。
			Timeout: 240 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // 禁跟随重定向（事实③）
			},
		},
	}
}

// Node 按 id 取节点；不存在返回 false。
func (c *Client) Node(id string) (Node, bool) {
	n, ok := c.byID[id]
	return n, ok
}

// Nodes 返回全部已注册节点配置。
func (c *Client) Nodes() []Node { return c.nodes }

// NodeStatus 单节点握手：GET {url}/v1/status，校验 api_version=1 且
// node_id 匹配；不可达/校验失败返回 reachable:false（非整体失败，事实③）。
func (c *Client) NodeStatus(ctx context.Context, node Node) NodeStatus {
	unreachable := NodeStatus{ID: node.ID, Name: node.Name, Reachable: false, Services: []any{}}
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimRight(node.URL, "/")+"/v1/status", nil)
	if err != nil {
		return unreachable
	}
	req.Header.Set("Authorization", "Bearer "+node.Token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return unreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return unreachable
	}
	var st struct {
		ApiVersion int    `json:"api_version"`
		NodeID     string `json:"node_id"`
		Services   []any  `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return unreachable
	}
	if st.ApiVersion != 1 || st.NodeID != node.ID {
		return unreachable
	}
	if st.Services == nil {
		st.Services = []any{}
	}
	return NodeStatus{
		ID:         node.ID,
		Name:       node.Name,
		Reachable:  true,
		Services:   st.Services,
		ApiVersion: st.ApiVersion,
		NodeID:     st.NodeID,
	}
}

// ListStatus 并发握手全部节点（事实③：不可达节点单独标记）。
func (c *Client) ListStatus(ctx context.Context) []NodeStatus {
	out := make([]NodeStatus, len(c.nodes))
	var wg sync.WaitGroup
	for i, n := range c.nodes {
		wg.Add(1)
		go func(idx int, node Node) {
			defer wg.Done()
			out[idx] = c.NodeStatus(ctx, node)
		}(i, n)
	}
	wg.Wait()
	return out
}

// ErrNodeNotFound 节点 id 未注册。
var ErrNodeNotFound = rbac.ErrNotFoundErr("Server node not found")
