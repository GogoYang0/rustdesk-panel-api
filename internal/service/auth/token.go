package auth

import (
	"context"
	"fmt"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// errTokenRejected 统一拒绝原因（对外文案由 JWTAuth 中间件产出：
// "Token expired or revoked"）。
var errTokenRejected = middleware.ErrTokenInvalid

// Claims JWT payload（camelCase 契约：isAdmin、deviceId，共享知识 2/4）。
type Claims struct {
	Sub      string // users.guid
	Username string
	Email    string
	IsAdmin  bool
	DeviceId string
	Jti      string
}

// TokenService JWT 签发/校验/撤销：HS256 + user_tokens 有状态撤销
// （共享知识 4：每个受保护请求查库校验 userGuid+jti+isRevoked=false 且未过期）。
type TokenService struct {
	tokens *repository.UserTokenRepo
	secret []byte
	expiry time.Duration
	// now 可注入虚拟时钟（测试用）；默认 time.Now。
	now func() time.Time
}

// NewTokenService 构建服务；expiryDays 为 JWT 有效期（天，JWT_EXPIRY_DAYS）。
func NewTokenService(tokens *repository.UserTokenRepo, secret string, expiryDays int) *TokenService {
	if expiryDays <= 0 {
		expiryDays = 30
	}
	return &TokenService{
		tokens: tokens,
		secret: []byte(secret),
		expiry: time.Duration(expiryDays) * 24 * time.Hour,
		now:    time.Now,
	}
}

// Generate 签发 JWT 并落 user_tokens 记录。
//
// jti = 标准 uuid v4（共享知识 3），user_tokens.guid 恒等于 jti；
// expiresAt = now + expiry。设备维度信息来自 LoginDevice。
func (s *TokenService) Generate(ctx context.Context, user *entity.User, dev dto.LoginDevice) (string, error) {
	jti := uuid.New().String()
	now := s.now()
	expiresAt := now.Add(s.expiry)
	record := &entity.UserToken{
		Guid:       jti,
		UserGuid:   user.Guid,
		Jti:        jti,
		DeviceId:   dev.Id,
		DeviceUuid: dev.Uuid,
		DeviceOs:   dev.Os,
		DeviceType: dev.Type,
		DeviceName: dev.Name,
		ExpiresAt:  expiresAt,
	}
	if err := s.tokens.Create(ctx, record); err != nil {
		return "", fmt.Errorf("token: persist session failed: %w", err)
	}
	claims := jwt.MapClaims{
		"sub":      user.Guid,
		"username": user.Username,
		"email":    user.Email,
		"isAdmin":  user.IsAdmin,
		"deviceId": dev.Id,
		"jti":      jti,
		"iat":      now.Unix(),
		"exp":      expiresAt.Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("token: sign failed: %w", err)
	}
	return signed, nil
}

// Validate 校验原始 token：HS256 验签 → exp 校验 → sub/jti 形状校验 →
// user_tokens 撤销表查询。通过后返回注入 context 的身份
// （实现 middleware.TokenValidator，共享知识 4）。
func (s *TokenService) Validate(ctx context.Context, raw string) (*middleware.Identity, error) {
	parsed, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return s.secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !parsed.Valid {
		return nil, errTokenRejected
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errTokenRejected
	}
	sub, _ := mc["sub"].(string)
	jti, _ := mc["jti"].(string)
	if sub == "" || jti == "" {
		return nil, errTokenRejected
	}
	if _, err := s.tokens.FindActive(ctx, sub, jti); err != nil {
		// 已撤销 / 已过期 / 无记录 → 一律拒绝。
		return nil, errTokenRejected
	}
	ident := &middleware.Identity{UserGuid: sub, Jti: jti}
	if v, ok := mc["username"].(string); ok {
		ident.Username = v
	}
	if v, ok := mc["email"].(string); ok {
		ident.Email = v
	}
	if v, ok := mc["isAdmin"].(bool); ok {
		ident.IsAdmin = v
	}
	if v, ok := mc["deviceId"].(string); ok {
		ident.DeviceId = v
	}
	return ident, nil
}

// RevokeCurrent 撤销当前 token（jti 维度，登出场景）。
func (s *TokenService) RevokeCurrent(ctx context.Context, userGuid, jti string) error {
	return s.tokens.RevokeByJti(ctx, userGuid, jti)
}

// RevokeDevice 设备维度撤销（登出附带场景：同设备全部会话失效）。
func (s *TokenService) RevokeDevice(ctx context.Context, userGuid, deviceId, deviceUuid string) error {
	return s.tokens.RevokeByDevice(ctx, userGuid, deviceId, deviceUuid)
}
