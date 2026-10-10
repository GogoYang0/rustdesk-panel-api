package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"uuid"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// oidcAuthStateTTL 授权中间态有效期（短 TTL，设计 §4 OIDC 回调流）。
const oidcAuthStateTTL = 10 * time.Minute

// oidcSubjectPrefix 幂等绑定前缀：oidc:{providerName}:{sub}。
const oidcSubjectPrefix = "oidc:"

// defaultScope provider 未配置 scope 时的缺省值。
const defaultScope = "openid profile email"

// OidcFlowService OIDC 授权流：login-options、发起授权、轮询、回调。
//
// M3 T07（M1 批复 #7）：提供商来源切 oidc_providers 表（enabled 数据驱动 +
// priority 排序），env OIDC_* 降级为 fallback（表中无 enabled 记录时启用）。
type OidcFlowService struct {
	providers *repository.OidcRepo
	users     *repository.UserRepo
	groups    *repository.UserGroupRepo
	tokens    *TokenService
	// fallback env OIDC 配置（表中无 enabled 记录时的降级形态）。
	fallback *EnvOidcFallback
}

// NewOidcFlowService 构建服务。
func NewOidcFlowService(providers *repository.OidcRepo, users *repository.UserRepo,
	groups *repository.UserGroupRepo, tokens *TokenService) *OidcFlowService {
	return &OidcFlowService{providers: providers, users: users, groups: groups, tokens: tokens}
}

// WithEnvFallback 注入 env OIDC fallback（bootstrap 装配；nil 时无降级）。
func (s *OidcFlowService) WithEnvFallback(fallback *EnvOidcFallback) *OidcFlowService {
	s.fallback = fallback
	return s
}

// fallbackProvider 构造 env fallback 的临时 provider 视图
// （表内无 enabled 记录时启用；每次构造避免污染仓储）。
func (s *OidcFlowService) fallbackProvider() *entity.OidcProvider {
	if s.fallback == nil || !s.fallback.Enabled || s.fallback.Issuer == "" {
		return nil
	}
	name := s.fallback.Name
	if name == "" {
		name = "oidc"
	}
	return &entity.OidcProvider{
		Guid:         "env-fallback",
		Name:         name,
		Type:         "oidc",
		Issuer:       s.fallback.Issuer,
		ClientId:     s.fallback.ClientID,
		ClientSecret: s.fallback.ClientSecret,
		Scope:        normalizeScope(s.fallback.Scope),
		Enabled:      true,
		Priority:     0,
	}
}

// resolveProvider 按名解析生效 provider：表内记录优先，缺失时回退 env。
func (s *OidcFlowService) resolveProvider(ctx context.Context, name string) (*entity.OidcProvider, error) {
	p, err := s.providers.FindByName(ctx, name)
	if err == nil && p.Enabled {
		return p, nil
	}
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	if fb := s.fallbackProvider(); fb != nil && fb.Name == name {
		return fb, nil
	}
	return nil, repository.ErrNotFound
}

// LoginOptions 登录方式选项（§2.1 #2）：启用中的提供商按 priority 升序。
//
// M3 T07 数据驱动：优先取 oidc_providers 表 enabled 记录；表中无 enabled
// 记录且 env 已配置时，降级返回 env fallback 单项（M1 行为回归）。
func (s *OidcFlowService) LoginOptions(ctx context.Context) (dto.LoginOptionsResult, error) {
	providers, err := s.providers.FindEnabledProviders(ctx)
	if err != nil {
		return dto.LoginOptionsResult{}, err
	}
	res := dto.LoginOptionsResult{Names: []string{}, Items: []dto.ProviderOption{}}
	if len(providers) == 0 {
		if fb := s.fallbackProvider(); fb != nil {
			res.Names = append(res.Names, "oidc/"+fb.Name)
			res.Items = append(res.Items, dto.ProviderOption{Name: fb.Name})
		}
		return res, nil
	}
	for _, p := range providers {
		if p.Icon != "" {
			res.HasIcons = true
		}
		res.Names = append(res.Names, "oidc/"+p.Name)
		res.Items = append(res.Items, dto.ProviderOption{Name: p.Name, Icon: p.Icon})
	}
	return res, nil
}

// RequestAuth 发起授权（§2.1 #17）：建 oidc_auth_states
// （PKCE codeVerifier + nonce + state，短 TTL），返回授权 URL。
// callbackURI 为本服务对外回调地址（handler 依请求推导）。
func (s *OidcFlowService) RequestAuth(ctx context.Context, req *api.OidcAuthRequest, callbackURI string) (dto.AuthURLResult, error) {
	p, err := s.resolveProvider(ctx, req.Provider)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.AuthURLResult{}, NotFound("Provider not found")
		}
		return dto.AuthURLResult{}, err
	}
	if !p.Enabled {
		return dto.AuthURLResult{}, NotFound("Provider not found")
	}
	if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" {
		return dto.AuthURLResult{}, BadRequest("Provider is not fully configured")
	}
	verifier, err := randomToken(48)
	if err != nil {
		return dto.AuthURLResult{}, err
	}
	state := uuid.New().String()
	nonce := uuid.New().String()
	code := uuid.New().String() // 客户端轮询凭据
	deviceJSON, err := json.Marshal(req.DeviceInfo)
	if err != nil {
		deviceJSON = []byte("{}")
	}
	record := &entity.OidcAuthState{
		Guid:                uuid.New().String(),
		Code:                code,
		Op:                  p.Name,
		ProviderType:        p.Type,
		DeviceId:            derefStr(req.DeviceId),
		DeviceUuid:          derefStr(req.DeviceUuid),
		DeviceInfo:          string(deviceJSON),
		RedirectUri:         callbackURI,
		State:               state,
		Status:              oidcStatusPending,
		CodeVerifier:        verifier,
		Nonce:               nonce,
		FrontendRedirectUrl: derefStr(req.FrontendRedirectUrl),
		ExpiresAt:           time.Now().Add(oidcAuthStateTTL),
	}
	if err := s.providers.SaveState(ctx, record); err != nil {
		return dto.AuthURLResult{}, err
	}
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", p.ClientId)
	params.Set("redirect_uri", callbackURI)
	params.Set("scope", scopeOrDefault(p.Scope))
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", s256Challenge(verifier))
	params.Set("code_challenge_method", "S256")
	// 轮询凭据以 login_code 附在授权 URL 后（客户端从跳转地址解析出
	// 该参数用于 auth-query 轮询；spec 响应仅含 {url}，此为既定假设）。
	params.Set("login_code", code)
	return dto.AuthURLResult{URL: p.AuthorizationEndpoint + "?" + params.Encode()}, nil
}

// QueryAuth 客户端轮询授权结果（§2.1 #18）。
func (s *OidcFlowService) QueryAuth(ctx context.Context, code string) (dto.AuthQueryResult, error) {
	state, err := s.providers.FindStateByCode(ctx, code)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.AuthQueryResult{}, NotFound("Auth state not found")
		}
		return dto.AuthQueryResult{}, err
	}
	switch state.Status {
	case oidcStatusSuccess:
		return dto.AuthQueryResult{Status: oidcStatusSuccess, Token: state.AccessToken}, nil
	case oidcStatusError:
		return dto.AuthQueryResult{Status: oidcStatusError, Message: "Authorization failed"}, nil
	default:
		if time.Now().After(state.ExpiresAt) {
			return dto.AuthQueryResult{Status: oidcStatusError, Message: "Authorization state expired"}, nil
		}
		return dto.AuthQueryResult{Status: oidcStatusPending}, nil
	}
}

// HandleCallback 提供商回调（§2.1 #19）：换 token（PKCE）→ 取 userinfo →
// findOrCreateUser（幂等绑定防账号接管）→ 签发面板 JWT → 完结 state；
// 可选 ID Token 校验（provider 配置了 jwksUri 时启用 go-oidc）。
func (s *OidcFlowService) HandleCallback(ctx context.Context, q dto.CallbackQuery) (dto.CallbackResult, error) {
	renderError := func(title, message string) (dto.CallbackResult, error) {
		return dto.CallbackResult{OK: false, Title: title, Message: message}, nil
	}
	if q.Error != "" {
		return renderError("Authorization failed", q.Error)
	}
	state, err := s.providers.FindStateByState(ctx, q.State)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return renderError("Invalid state", "Authorization state is invalid or expired")
		}
		return dto.CallbackResult{}, err
	}
	if state.Status != oidcStatusPending {
		return renderError("State already used", "This authorization request has already been completed")
	}
	if time.Now().After(state.ExpiresAt) {
		return renderError("State expired", "Authorization state is invalid or expired")
	}
	p, err := s.resolveProvider(ctx, state.Op)
	if err != nil {
		return dto.CallbackResult{}, err
	}
	conf := &oauth2.Config{
		ClientID:     p.ClientId,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.AuthorizationEndpoint,
			TokenURL: p.TokenEndpoint,
		},
		RedirectURL: state.RedirectUri,
	}
	tok, err := conf.Exchange(ctx, q.Code, oauth2.SetAuthURLParam("code_verifier", state.CodeVerifier))
	if err != nil {
		_ = s.providers.CompleteState(ctx, state.Code, repository.StatePatch{Status: strPtr(oidcStatusError)})
		return renderError("Token exchange failed", "Could not complete the authorization code exchange")
	}
	// 可选 ID Token 校验（issuer/JWKS 由 provider 记录配置，M1 测试样例可不配置）。
	if rawIDToken, _ := tok.Extra("id_token").(string); rawIDToken != "" && p.JwksUri != "" {
		if err := s.verifyIDToken(ctx, p, rawIDToken, state.Nonce); err != nil {
			_ = s.providers.CompleteState(ctx, state.Code, repository.StatePatch{Status: strPtr(oidcStatusError)})
			return renderError("ID token verification failed", "Provider identity could not be verified")
		}
	}
	userinfo, err := fetchUserinfo(conf.Client(ctx, tok), p.UserinfoEndpoint)
	if err != nil {
		_ = s.providers.CompleteState(ctx, state.Code, repository.StatePatch{Status: strPtr(oidcStatusError)})
		return renderError("Userinfo failed", "Could not fetch user profile from provider")
	}
	sub, _ := userinfo["sub"].(string)
	if sub == "" {
		_ = s.providers.CompleteState(ctx, state.Code, repository.StatePatch{Status: strPtr(oidcStatusError)})
		return renderError("Invalid userinfo", "Provider did not return a subject identifier")
	}
	user, err := s.findOrCreateUser(ctx, p, sub, stringField(userinfo, "preferred_username"), stringField(userinfo, "name"), stringField(userinfo, "email"))
	if err != nil {
		return dto.CallbackResult{}, err
	}
	dev := stateDevice(state)
	token, err := s.tokens.Generate(ctx, user, dev)
	if err != nil {
		return dto.CallbackResult{}, err
	}
	if err := s.providers.CompleteState(ctx, state.Code, repository.StatePatch{
		Status:      strPtr(oidcStatusSuccess),
		UserGuid:    &user.Guid,
		AccessToken: &token,
	}); err != nil {
		return dto.CallbackResult{}, err
	}
	res := dto.CallbackResult{OK: true, Title: "Login successful", Message: "You can now return to the application."}
	if state.FrontendRedirectUrl != "" {
		// web 模式：token 走 URL fragment（不进服务器访问日志）。
		res.RedirectURL = state.FrontendRedirectUrl + "#access_token=" + url.QueryEscape(token)
	}
	return res, nil
}

// verifyIDToken 用 provider 配置的 JWKS 校验 ID Token（签名/issuer/audience/nonce）。
func (s *OidcFlowService) verifyIDToken(ctx context.Context, p *entity.OidcProvider, rawIDToken, nonce string) error {
	keySet := oidc.NewRemoteKeySet(ctx, p.JwksUri)
	verifier := oidc.NewVerifier(p.Issuer, keySet, &oidc.Config{ClientID: p.ClientId})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return err
	}
	if idToken.Nonce != nonce {
		return errors.New("oidc: nonce mismatch")
	}
	return nil
}

// findOrCreateUser 幂等绑定：oidcSubject = "oidc:{providerName}:{sub}"
// （防账号接管：绑定关系唯一，且不按 email 自动合并既有本地账号）。
func (s *OidcFlowService) findOrCreateUser(ctx context.Context, p *entity.OidcProvider,
	sub, preferredUsername, displayName, email string) (*entity.User, error) {
	subject := oidcSubjectPrefix + p.Name + ":" + sub
	if existing, err := s.users.FindByOidcSubject(ctx, subject); err == nil {
		return existing, nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	base := preferredUsername
	if base == "" {
		base = "oidc_" + shortSuffix(sub, 8)
	}
	username := base
	for i := 0; i < 5; i++ {
		if _, err := s.users.FindByUsernameOrEmail(ctx, username); errors.Is(err, repository.ErrNotFound) {
			break
		} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return nil, err
		}
		username = base + "-" + shortSuffix(uuid.New().String(), 6)
	}
	user := &entity.User{
		Guid:          uuid.New().String(),
		Username:      username,
		DisplayName:   displayName,
		Email:         email,
		Status:        1,
		ThirdAuthType: "oidc",
		OidcSubject:   &subject,
	}
	if group, err := s.groups.FindDefault(ctx); err == nil && group != nil {
		groupGuid := group.Guid
		user.UserGroupGuid = &groupGuid
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}
	return user, nil
}

// stateDevice 还原发起授权时的设备信息。
func stateDevice(state *entity.OidcAuthState) dto.LoginDevice {
	info := &api.DeviceInfo{}
	if state.DeviceInfo != "" {
		_ = json.Unmarshal([]byte(state.DeviceInfo), info)
	}
	return dto.DeviceFromRequest(state.DeviceId, state.DeviceUuid, info)
}

// fetchUserinfo 以 OAuth2 client 拉取 userinfo（GET，JSON）。
func fetchUserinfo(client *http.Client, endpoint string) (map[string]any, error) {
	if endpoint == "" {
		return nil, errors.New("oidc: userinfo endpoint is not configured")
	}
	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("oidc: get userinfo failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oidc: read userinfo failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: userinfo status %d", resp.StatusCode)
	}
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("oidc: decode userinfo failed: %w", err)
	}
	return out, nil
}

// randomToken 生成 n 字节随机数的 base64url 串（PKCE verifier）。
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oidc: generate random failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// s256Challenge PKCE S256：BASE64URL(SHA256(verifier))。
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// scopeOrDefault provider 未配置 scope 时回退缺省。
func scopeOrDefault(scope string) string {
	if strings.TrimSpace(scope) == "" {
		return defaultScope
	}
	return scope
}

// stringField 读取 userinfo 的字符串字段。
func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// strPtr 字符串字面量指针（StatePatch 用）。
func strPtr(s string) *string { return &s }

// shortSuffix 取前 n 个字符（防御性处理超短输入）。
func shortSuffix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
