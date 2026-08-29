// Package oidcadmin 本文件：OIDC 提供者 CRUD/sort/toggle/test（设计事实⑧，
// M3 T07）。
//
// 全部 AdminGuard；列表分页 {data,total}，排序 priority ASC + name ASC；
// 响应含 clientSecret 明文（参考即如此，复刻）。sort 请求体为 guid 数组，
// 数组顺序即 priority（从 0 递增）。issuer 变更时清 provider 缓存。
package oidcadmin

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// discoveryTimeout discovery 测试超时。
const discoveryTimeout = 10 * time.Second

// ProviderService OIDC 提供者管理服务。
type ProviderService struct {
	repo *repository.OidcProviderAdminRepo
	// cache 进程内 discovery 缓存（issuer → 端点），issuer 变更时失效。
	mu    sync.RWMutex
	cache map[string]discoveryResult
	// probe 可注入 discovery 探测器（测试用）；默认 HTTP discovery。
	probe func(ctx context.Context, issuer string) (discoveryResult, error)
}

// discoveryResult discovery 端点集合（test 响应 endpoints 字段）。
type discoveryResult struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// NewProviderService 构建服务。
func NewProviderService(repo *repository.OidcProviderAdminRepo) *ProviderService {
	return &ProviderService{
		repo:  repo,
		cache: map[string]discoveryResult{},
		probe: defaultProbe,
	}
}

// List 分页列表：priority ASC + name ASC。
func (s *ProviderService) List(ctx context.Context, current, pageSize int) (dto.OidcProviderPageView, error) {
	rows, total, err := s.repo.ListPaged(ctx, current, pageSize)
	if err != nil {
		return dto.OidcProviderPageView{}, err
	}
	out := dto.OidcProviderPageView{Data: make([]dto.OidcProviderDtoView, 0, len(rows)), Total: int(total)}
	for i := range rows {
		out.Data = append(out.Data, toView(&rows[i]))
	}
	return out, nil
}

// Get 详情；未找到 404。
func (s *ProviderService) Get(ctx context.Context, guid string) (dto.OidcProviderDtoView, error) {
	p, err := s.repo.FindByGuid(ctx, guid)
	if err != nil {
		return dto.OidcProviderDtoView{}, mapNotFound(err)
	}
	return toView(p), nil
}

// Create 创建（POST 语义 200）；重名 400。
func (s *ProviderService) Create(ctx context.Context, req *dto.OidcProviderUpsertDto) (dto.OidcProviderDtoView, error) {
	if err := dto.ValidateProviderCreate(req); err != nil {
		return dto.OidcProviderDtoView{}, err
	}
	if _, err := s.repo.FindByName(ctx, req.Name); err == nil {
		return dto.OidcProviderDtoView{}, dto.ErrDuplicateProvider()
	} else if !errors.Is(err, repository.ErrNotFound) {
		return dto.OidcProviderDtoView{}, err
	}
	providerType := dto.ProviderTypeOIDC
	if req.Type != nil {
		providerType = string(*req.Type)
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	priority := 0
	if req.Priority != nil {
		priority = *req.Priority
	}
	scope := dto.DefaultScopeFor(providerType)
	if req.Scope != nil && *req.Scope != "" {
		scope = *req.Scope
	}
	rec := &entity.OidcProvider{
		Guid:         newGuid(),
		Name:         req.Name,
		Type:         providerType,
		Issuer:       req.Issuer,
		ClientId:     req.ClientId,
		ClientSecret: req.ClientSecret,
		Scope:        scope,
		Enabled:      enabled,
		Priority:     priority,
	}
	if err := s.repo.Create(ctx, rec); err != nil {
		return dto.OidcProviderDtoView{}, err
	}
	return toView(rec), nil
}

// Update 部分更新（PATCH）：issuer 变更时清 provider 缓存；重名 400。
func (s *ProviderService) Update(ctx context.Context, guid string, req *dto.OidcProviderUpsertDto) (dto.OidcProviderDtoView, error) {
	rec, err := s.repo.FindByGuid(ctx, guid)
	if err != nil {
		return dto.OidcProviderDtoView{}, mapNotFound(err)
	}
	if err := dto.ValidateProviderUpdate(req); err != nil {
		return dto.OidcProviderDtoView{}, err
	}
	if other, err := s.repo.FindByName(ctx, req.Name); err == nil && other.Guid != guid {
		return dto.OidcProviderDtoView{}, dto.ErrDuplicateProvider()
	} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return dto.OidcProviderDtoView{}, err
	}
	previousIssuer := rec.Issuer
	rec.Name = req.Name
	rec.Issuer = req.Issuer
	rec.ClientId = req.ClientId
	rec.ClientSecret = req.ClientSecret
	if req.Type != nil {
		rec.Type = string(*req.Type)
	}
	if req.Scope != nil && *req.Scope != "" {
		rec.Scope = *req.Scope
	}
	if req.Enabled != nil {
		rec.Enabled = *req.Enabled
	}
	if req.Priority != nil {
		rec.Priority = *req.Priority
	}
	if err := s.repo.Save(ctx, rec); err != nil {
		return dto.OidcProviderDtoView{}, err
	}
	if previousIssuer != rec.Issuer {
		s.invalidate(previousIssuer)
	}
	return toView(rec), nil
}

// Delete 删除；未找到 404；成功文案固定 'OIDC provider deleted'。
func (s *ProviderService) Delete(ctx context.Context, guid string) error {
	rec, err := s.repo.FindByGuid(ctx, guid)
	if err != nil {
		return mapNotFound(err)
	}
	if err := s.repo.DeleteByGuid(ctx, guid); err != nil {
		return err
	}
	s.invalidate(rec.Issuer)
	return nil
}

// Sort body 为 guid 数组，数组顺序即 priority（从 0 递增）。
func (s *ProviderService) Sort(ctx context.Context, guids []string) error {
	if len(guids) == 0 {
		return rbac.ErrBadRequest("Provider order is required")
	}
	return s.repo.ReorderPriorities(ctx, guids)
}

// Toggle 启停切换（读当前 enabled 取反落库）。
func (s *ProviderService) Toggle(ctx context.Context, guid string) (dto.OidcProviderDtoView, error) {
	rec, err := s.repo.FindByGuid(ctx, guid)
	if err != nil {
		return dto.OidcProviderDtoView{}, mapNotFound(err)
	}
	rec.Enabled = !rec.Enabled
	if err := s.repo.Save(ctx, rec); err != nil {
		return dto.OidcProviderDtoView{}, err
	}
	s.invalidate(rec.Issuer)
	return toView(rec), nil
}

// Test discovery 验证：恒返回 (result, nil)（失败以 success:false 表达，
// 保证 HTTP 200 + SettingsTestResult 契约）。成功时附 endpoints。
func (s *ProviderService) Test(ctx context.Context, guid string) (dto.SettingsTestResultView, error) {
	rec, err := s.repo.FindByGuid(ctx, guid)
	if err != nil {
		return dto.SettingsTestResultView{}, mapNotFound(err)
	}
	result, derr := s.probe(ctx, rec.Issuer)
	if derr != nil {
		return dto.SettingsTestResultView{Success: false, Message: derr.Error()}, nil
	}
	s.mu.Lock()
	s.cache[rec.Issuer] = result
	s.mu.Unlock()
	endpoints := map[string]any{
		"authorization_endpoint": result.AuthorizationEndpoint,
		"token_endpoint":         result.TokenEndpoint,
		"userinfo_endpoint":      result.UserinfoEndpoint,
		"jwks_uri":               result.JwksURI,
	}
	return dto.SettingsTestResultView{
		Success:   true,
		Message:   "OIDC discovery successful",
		Endpoints: &endpoints,
	}, nil
}

// invalidate 失效指定 issuer 的 discovery 缓存。
func (s *ProviderService) invalidate(issuer string) {
	if issuer == "" {
		return
	}
	s.mu.Lock()
	delete(s.cache, issuer)
	s.mu.Unlock()
}

// Lookup 读缓存的 discovery 端点（供 auth 域消费；缓存未命中返回 false）。
func (s *ProviderService) Lookup(issuer string) (map[string]any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result, ok := s.cache[issuer]
	if !ok {
		return nil, false
	}
	return map[string]any{
		"authorization_endpoint": result.AuthorizationEndpoint,
		"token_endpoint":         result.TokenEndpoint,
		"userinfo_endpoint":      result.UserinfoEndpoint,
		"jwks_uri":               result.JwksURI,
	}, true
}

// toView 实体 → 视图（clientSecret 明文可见，设计事实⑧）。
//
// createdAt 为可选字段：oidc_providers 表无该列（M1 基线 DDL 既定），
// 故视图恒不填充（openapi 中非 required）。
func toView(p *entity.OidcProvider) dto.OidcProviderDtoView {
	return dto.OidcProviderDtoView{
		Guid:         p.Guid,
		Name:         p.Name,
		Type:         toViewType(p.Type),
		Issuer:       p.Issuer,
		ClientId:     p.ClientId,
		ClientSecret: p.ClientSecret,
		Scope:        p.Scope,
		Enabled:      p.Enabled,
		Priority:     p.Priority,
	}
}

// toViewType 实体 type → 视图枚举（未知值归 oidc）。
func toViewType(raw string) dto.OidcProviderDtoViewType {
	if raw == dto.ProviderTypeOAuth2 {
		return dto.ProviderTypeOAuth2View
	}
	return dto.ProviderTypeOIDCView
}
// mapNotFound 仓储未找到 → 404 固定语义。
func mapNotFound(err error) error {
	if errors.Is(err, repository.ErrNotFound) {
		return rbac.ErrNotFoundErr("OIDC provider not found")
	}
	return err
}

// defaultProbe 默认 discovery 探测器（由 discovery.go 提供实现）。
var defaultProbe = func(ctx context.Context, issuer string) (discoveryResult, error) {
	return fetchDiscovery(ctx, issuer, &http.Client{Timeout: discoveryTimeout})
}
