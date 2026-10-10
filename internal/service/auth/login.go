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

// 登录审计 reason 固定文案（GAP2 设计 §3.4：审计锚点短标记，
// 与 result 枚举互补；HTTP 错误文案另由 msg* 契约常量承载）。
const (
	auditReasonBadCredentials = "bad_credentials"
	auditReasonUserDisabled   = "user_disabled"
	auditReasonTfaCodeInvalid = "tfa_code_invalid"
	auditReasonPasskeyFailed  = "passkey_rejected"
)

// AuthService 登录分发（type 分支）、登出与当前用户。
type AuthService struct {
	users   *repository.UserRepo
	tokens  *TokenService
	tfa     *TfaService
	passkey *PasskeyService
	// mfa 强制 MFA 判定与绑定服务（GAP2 §3.2；nil 时无强制，单测兼容）。
	mfa *MfaService
	// audits 登录审计记录器（GAP2 G3 best-effort；nil 时跳过）。
	audits *LoginAuditRecorder
}

// NewAuthService 构建服务。
func NewAuthService(users *repository.UserRepo, tokens *TokenService, tfa *TfaService, passkey *PasskeyService) *AuthService {
	return &AuthService{users: users, tokens: tokens, tfa: tfa, passkey: passkey}
}

// WithMfa 注入强制 MFA 服务与登录审计记录器（bootstrap 装配；GAP2）。
func (s *AuthService) WithMfa(mfa *MfaService, audits *LoginAuditRecorder) *AuthService {
	s.mfa = mfa
	s.audits = audits
	return s
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
// 含强制 MFA 分流（GAP2：status 复核之后、既有 TFA/passkey 判定之前）
// 与 TOTP/passkey 二次验证分流（场景 B / passkey_tfa 分支）。
func (s *AuthService) loginAccount(ctx context.Context, req *api.LoginRequest, dev dto.LoginDevice) (*api.LoginResponse, error) {
	if req.Username == nil || *req.Username == "" || req.Password == nil || *req.Password == "" {
		return nil, BadRequest("Username and password are required")
	}
	inputName := *req.Username
	failAudit := func(result, reason string, userGuid *string) {
		s.audits.Record(ctx, LoginAuditEntry{
			UserGuid: userGuid, Username: inputName, Result: result,
			Method: entity.LoginAuditMethodPassword, DeviceId: derefStr(req.Id),
			DeviceUuid: derefStr(req.Uuid), Reason: reason,
		})
	}
	user, err := s.users.FindByUsernameOrEmail(ctx, inputName)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// 不区分"用户不存在"与"密码错误"（防枚举）；审计锚 username 原文。
			s.audits.Record(ctx, LoginAuditEntry{
				Username: inputName, Result: entity.LoginAuditResultFailed,
				Method: entity.LoginAuditMethodPassword, DeviceId: derefStr(req.Id),
				DeviceUuid: derefStr(req.Uuid), Reason: auditReasonBadCredentials,
			})
			return nil, Unauthorized(msgBadCredentials)
		}
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(*req.Password)) != nil {
		failAudit(entity.LoginAuditResultFailed, auditReasonBadCredentials, strPtr(user.Guid))
		return nil, Unauthorized(msgBadCredentials)
	}
	if user.Status != 1 {
		failAudit(entity.LoginAuditResultFailed, auditReasonUserDisabled, strPtr(user.Guid))
		return nil, Unauthorized(msgUserDisabled)
	}
	// 强制 MFA 分流（GAP2 设计 §3.2）：策略命中且无 TOTP/passkey-2FA
	// → mfa_enroll 绑定步会话（优先于既有二次验证分支——用户无 2FA
	// 可验证，先绑定再进站）。
	if s.mfa != nil {
		enforced, err := s.mfa.Enforced(ctx, user)
		if err != nil {
			return nil, err
		}
		if enforced {
			s.audits.Record(ctx, LoginAuditEntry{
				UserGuid: strPtr(user.Guid), Username: user.Username,
				Result: entity.LoginAuditResultMfaEnrollRequired,
				Method: entity.LoginAuditMethodPassword, DeviceId: derefStr(req.Id),
				DeviceUuid: derefStr(req.Uuid),
			})
			return s.mfa.BeginMfaEnrollment(ctx, user)
		}
	}
	// 二次验证分流：已绑定 TOTP 优先；其次 passkey 2FA（共享知识 6）。
	if user.TfaEnabled() {
		s.audits.Record(ctx, LoginAuditEntry{
			UserGuid: strPtr(user.Guid), Username: user.Username,
			Result: entity.LoginAuditResultTfaRequired,
			Method: entity.LoginAuditMethodPassword, DeviceId: derefStr(req.Id),
			DeviceUuid: derefStr(req.Uuid),
		})
		return s.tfa.BeginTfaLogin(ctx, user)
	}
	if user.ParseUserInfo().PasskeyTfaEnabled() {
		s.audits.Record(ctx, LoginAuditEntry{
			UserGuid: strPtr(user.Guid), Username: user.Username,
			Result: entity.LoginAuditResultTfaRequired,
			Method: entity.LoginAuditMethodPassword, DeviceId: derefStr(req.Id),
			DeviceUuid: derefStr(req.Uuid),
		})
		return s.passkey.BeginTfaLogin(ctx, user)
	}
	return s.completeLogin(ctx, user, dev)
}

// completeLogin 签发最终会话并组装 account 响应（场景 A/B/C 收敛点；
// GAP2：success 审计在签发成功后落库，method 固定 password——
// passkey/OIDC 收敛点各自显式记录）。
func (s *AuthService) completeLogin(ctx context.Context, user *entity.User, dev dto.LoginDevice) (*api.LoginResponse, error) {
	token, err := s.tokens.Generate(ctx, user, dev)
	if err != nil {
		return nil, err
	}
	s.audits.Record(ctx, LoginAuditEntry{
		UserGuid: strPtr(user.Guid), Username: user.Username,
		Result: entity.LoginAuditResultSuccess, Method: entity.LoginAuditMethodPassword,
		DeviceId: dev.Id, DeviceUuid: dev.Uuid,
	})
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

// strPtr 字符串指针（审计载荷；定义见 oidcflow.go）。

// derefStr 安全解引用字符串指针。
func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
