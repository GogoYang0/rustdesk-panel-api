// Package oidcadmin 本文件：OIDC discovery 拉取与 provider guid 生成
// （辅助实现，M3 T07）。
package oidcadmin

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// discoveryPath 标准 OIDC discovery 相对路径（RFC 8414 openid-configuration）。
const discoveryPath = "/.well-known/openid-configuration"

// maxDiscoveryBody discovery 响应体上限（防御异常大响应）。
const maxDiscoveryBody = 1 << 20

// fetchDiscovery 拉取 {issuer}/.well-known/openid-configuration 并解析端点。
//
// issuer 已带 discovery 路径时直接使用；4xx/5xx 与非 JSON 均返回错误。
func fetchDiscovery(ctx context.Context, issuer string, client *http.Client) (discoveryResult, error) {
	issuer = strings.TrimSpace(strings.TrimRight(issuer, "/"))
	if issuer == "" {
		return discoveryResult{}, errors.New("issuer is not configured")
	}
	endpoint := issuer
	if !strings.HasSuffix(endpoint, discoveryPath) {
		endpoint += discoveryPath
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return discoveryResult{}, fmt.Errorf("discovery request failed: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return discoveryResult{}, fmt.Errorf("discovery request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBody))
	if err != nil {
		return discoveryResult{}, fmt.Errorf("discovery read failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return discoveryResult{}, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}
	var raw struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return discoveryResult{}, fmt.Errorf("discovery decode failed: %w", err)
	}
	if raw.AuthorizationEndpoint == "" || raw.TokenEndpoint == "" {
		return discoveryResult{}, errors.New("discovery document is missing required endpoints")
	}
	return discoveryResult{
		AuthorizationEndpoint: raw.AuthorizationEndpoint,
		TokenEndpoint:         raw.TokenEndpoint,
		UserinfoEndpoint:      raw.UserinfoEndpoint,
		JwksURI:               raw.JwksURI,
	}, nil
}

// newGuid 生成 RFC 4122 v4 形态的 36 位 guid（与全站 uuid 形态一致）。
func newGuid() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// 极罕见的熵源故障：以零填充保证调用方仍拿到合法形状
		// （唯一性由数据库主键冲突兜底）。
		buf = make([]byte, 16)
	}
	buf[6] = (buf[6] & 0x0f) | 0x40 // version 4
	buf[8] = (buf[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
