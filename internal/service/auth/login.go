package auth

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// AuthService 登录分发（type 分支）、登出与当前用户。
type AuthService struct {
	users   *repository.UserRepo
	tokens  *TokenService
	tfa     *TfaService
	passkey *PasskeyService
}

// NewAuthService 构建服务。
func NewAuthService(users *repository.UserRepo, tokens *TokenService, tfa *TfaService, passkey *PasskeyService) *AuthService {
	return &AuthService{users: users, tokens: tokens, tfa: tfa, passkey: passkey}
}

// Login 登录分发（§2.1 #1）：
//   - type 缺省 / account：username+password（默认）；
//   - tfa_code / email_code：两步验证完成（TfaService）；
//   - sms_code：400 未开放。
func (s *AuthService) Login(ctx context.Context, req *api.LoginRequest) (*api.LoginResponse, error) {
	loginType := ""
	if req.Type != nil {
		loginType = string(*req.Type)
	}
	dev := dto.DeviceFromRequest(derefStr(req.Id), derefStr(req.Uuid), req.DeviceInfo)
	switch loginType {
	case "", string(api.LoginRequestTypeAccount):
		return s.loginAccount(ctx, req, dev)
	case string(api.LoginRequestTypeTfaCode):
		return s.tfa.CompleteTfaLogin(ctx, req, dev)
	case string(api.LoginRequestTypeEmailCode):
		return s.tfa.CompleteEmailCodeLogin(ctx, req, dev)
	case string(api.LoginRequestTypeSmsCode):
		return nil, BadRequest("SMS login is not available")
	default:
		return nil, BadRequest("Unknown login type")
	}
}

// loginAccount 场景 A：普通账号密码登录（无二次验证），
// 含 TOTP/passkey 二次验证分流（场景 B / passkey_tfa 分支）。
func (s *AuthService) loginAccount(ctx context.Context, req *api.LoginRequest, dev dto.LoginDevice) (*api.LoginResponse, error) {
	if req.Username == nil || *req.Username == "" || req.Password == nil || *req.Password == "" {
		return nil, BadRequest("Username and password are required")
	}
	user, err := s.users.FindByUsernameOrEmail(ctx, *req.Username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// 不区分"用户不存在"与"密码错误"（防枚举）。
			return nil, Unauthorized(msgBadCredentials)
		}
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(*req.Password)) != nil {
		return nil, Unauthorized(msgBadCredentials)
	}
	if user.Status != 1 {
		return nil, Unauthorized(msgUserDisabled)
	}
	// 二次验证分流：已绑定 TOTP 优先；其次 passkey 2FA（共享知识 6）。
	if user.TfaEnabled() {
		return s.tfa.BeginTfaLogin(ctx, user)
	}
	if user.ParseUserInfo().PasskeyTfaEnabled() {
		return s.passkey.BeginTfaLogin(ctx, user)
	}
	return s.completeLogin(ctx, user, dev)
}

// completeLogin 签发最终会话并组装 account 响应（场景 A/B/C 收敛点）。
func (s *AuthService) completeLogin(ctx context.Context, user *entity.User, dev dto.LoginDevice) (*api.LoginResponse, error) {
	token, err := s.tokens.Generate(ctx, user, dev)
	if err != nil {
		return nil, err
	}
	payload := dto.BuildUserPayload(user)
	return &api.LoginResponse{
		AccessToken: &token,
		Type:        api.AccessToken,
		User:        &payload,
	}, nil
}

// Logout 登出：撤销当前 jti + 设备维度撤销（§2.1 #3）。
func (s *AuthService) Logout(ctx context.Context, ident *middleware.Identity, req *api.LogoutRequest) error {
	if err := s.tokens.RevokeCurrent(ctx, ident.UserGuid, ident.Jti); err != nil {
		return err
	}
	deviceId, deviceUuid := "", ""
	if req != nil {
		deviceId = derefStr(req.Id)
		deviceUuid = derefStr(req.Uuid)
	}
	return s.tokens.RevokeDevice(ctx, ident.UserGuid, deviceId, deviceUuid)
}

// CurrentUser 当前用户 payload（全列加载以返回 tfa_enabled/has_password/verifier）。
func (s *AuthService) CurrentUser(ctx context.Context, userGuid string) (api.UserPayload, error) {
	user, err := s.users.FindByGuidWithSecrets(ctx, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.UserPayload{}, NotFound("User not found")
		}
		return api.UserPayload{}, err
	}
	return dto.BuildUserPayload(user), nil
}

// derefStr 安全解引用字符串指针。
func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
