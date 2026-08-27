package nexus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// 固定上游代理（设计事实⑤ / 共享知识 19）。
const defaultUpstream = "https://api.databk.top"

// 设备码登录内存登记项（设计事实⑤：login_id 内存 map）。
type loginEntry struct {
	UserGuid string
	ExpiresAt time.Time
}

// NexusService nexus 域核心服务：绑定态 + 构建生命周期 + 产物存储。
type NexusService struct {
	db       *gorm.DB
	upstream string
	storage  *Storage

	loginMu  sync.Mutex
	loginIDs map[string]loginEntry

	httpClient *http.Client
}

// NewNexusService 构建 nexus 服务（upstream 为空回落缺省；dataDir 用于产物落盘）。
func NewNexusService(db *gorm.DB, upstream, dataDir string) *NexusService {
	if strings.TrimSpace(upstream) == "" {
		upstream = defaultUpstream
	}
	return &NexusService{
		db:         db,
		upstream:   strings.TrimRight(upstream, "/"),
		storage:    NewStorage(dataDir),
		loginIDs:   make(map[string]loginEntry),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Storage 暴露产物存储（handler 下载复用 safeJoin）。
func (s *NexusService) Storage() *Storage { return s.storage }

// upstreamJSON 向 nexus 上游发起 JSON 请求；bearer 非空则带 Authorization。
// 返回上游状态码、原始响应体、传输错误（非 2xx 不视为错误，由调用方映射）。
func (s *NexusService) upstreamJSON(ctx context.Context, method, path string, body any, bearer string, out any) (int, []byte, error) {
	var 	reqBody *bytes.Buffer
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("nexus: marshal request: %w", err)
		}
		reqBody = bytes.NewBuffer(raw)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.upstream+path, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("nexus: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		// 上游不可达 → 503（与 servermgmt 同类语义：节点不可用）。
		return 0, nil, &rbac.StatusError{Status: http.StatusServiceUnavailable, Message: "Nexus upstream unreachable"}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("nexus: read upstream response: %w", err)
	}
	if out != nil && len(raw) > 0 && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, raw, fmt.Errorf("nexus: upstream invalid json: %w", err)
		}
	}
	return resp.StatusCode, raw, nil
}

// Login 发起 GitHub 设备码登录：调用上游 /v1/auth/github/login，返回设备码
// 载荷并将 login_id 登记到内存 map（绑定当前用户，15min 有效期）。
// 响应契约 schema:{}（自由形态），原样透出上游载荷。
func (s *NexusService) Login(ctx context.Context, userGuid string) (map[string]any, error) {
	var payload map[string]any
	status, raw, err := s.upstreamJSON(ctx, http.MethodPost, "/v1/auth/github/login", map[string]any{"github_login": userGuid}, "", &payload)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, upstreamError(status, raw)
	}
	loginID, _ := payload["login_id"].(string)
	if loginID == "" {
		return nil, rbac.ErrBadRequest("invalid nexus login response")
	}
	s.loginMu.Lock()
	s.loginIDs[loginID] = loginEntry{UserGuid: userGuid, ExpiresAt: time.Now().Add(15 * time.Minute)}
	s.loginMu.Unlock()
	return payload, nil
}

// PollStatus 轮询设备码授权态：校验 login_id 归属 + 上游 /v1/auth/github/status；
// 授权完成 → token 落 nexus_tokens（userGuid 主键 upsert），返回上游载荷。
// 响应契约 schema:{}（自由形态）。
func (s *NexusService) PollStatus(ctx context.Context, userGuid, loginID string) (map[string]any, error) {
	// 校验 login_id 归属当前用户（防越权轮询他人设备码）。
	s.loginMu.Lock()
	entry, ok := s.loginIDs[loginID]
	if ok && time.Now().After(entry.ExpiresAt) {
		delete(s.loginIDs, loginID)
		ok = false
	}
	s.loginMu.Unlock()
	if !ok || entry.UserGuid != userGuid {
		return nil, rbac.ErrNotFoundErr("Nexus login session not found")
	}

	var payload map[string]any
	q := "/v1/auth/github/status?login_id=" + url.QueryEscape(loginID)
	status, raw, err := s.upstreamJSON(ctx, http.MethodGet, q, nil, "", &payload)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, upstreamError(status, raw)
	}
	// 上游返回 authorized + token → 落库绑定。
	if st, _ := payload["status"].(string); st == "authorized" {
		token, _ := payload["token"].(string)
		username, _ := payload["username"].(string)
		if token != "" {
			if err := s.upsertToken(userGuid, token, username, loginID); err != nil {
				return nil, err
			}
			s.loginMu.Lock()
			delete(s.loginIDs, loginID)
			s.loginMu.Unlock()
		}
	}
	return payload, nil
}

// BindStatus 读取绑定态（nexus_tokens，userGuid 主键）；未绑定 → {bound:false}。
func (s *NexusService) BindStatus(ctx context.Context, userGuid string) (*api.NexusBindStatus, error) {
	var tok entity.NexusToken
	err := s.db.WithContext(ctx).Where("userGuid = ?", userGuid).First(&tok).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &api.NexusBindStatus{Bound: false}, nil
	}
	if err != nil {
		return nil, err
	}
	return &api.NexusBindStatus{
		Bound:         true,
		CurrentUuid:   tok.CurrentUuid,
		ExpiresAt:     &tok.ExpiresAt,
		NexusUsername: tok.NexusUsername,
	}, nil
}

// Unbind 解绑：删除 nexus_tokens 行（幂等，无记录亦返回 nil）。
func (s *NexusService) Unbind(ctx context.Context, userGuid string) error {
	s.loginMu.Lock()
	for k, v := range s.loginIDs {
		if v.UserGuid == userGuid {
			delete(s.loginIDs, k)
		}
	}
	s.loginMu.Unlock()
	return s.db.WithContext(ctx).Where("userGuid = ?", userGuid).Delete(&entity.NexusToken{}).Error
}

// upsertToken 以 userGuid 为主键 upsert 绑定态（nexus_tokens）。
func (s *NexusService) upsertToken(userGuid, token, username, loginID string) error {
	cu := loginID
	rec := entity.NexusToken{
		UserGuid:      userGuid,
		NexusToken:    token,
		NexusUsername: &username,
		ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
		CurrentUuid:   &cu,
	}
	return s.db.Save(&rec).Error
}

// requireToken 取当前用户绑定态 token（未绑定 → 401 重新绑定）。
func (s *NexusService) requireToken(ctx context.Context, userGuid string) (*entity.NexusToken, error) {
	var tok entity.NexusToken
	err := s.db.WithContext(ctx).Where("userGuid = ?", userGuid).First(&tok).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, rbac.ErrUnauthorizedMsg(msgTokenExpired)
	}
	if err != nil {
		return nil, err
	}
	return &tok, nil
}
