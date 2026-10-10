// Package auth 本文件：MfaService——强制 MFA 判定与未认证态 TOTP 绑定
// 通道（GAP2 设计 §3.2，共享知识 G1/G2）。
//
// 强制判定收敛点（OQ-3 批复：统一执行，防免密通道绕过）：
//   - loginAccount（password 登录，type=mfa_enroll 分支主通道）；
//   - passkey 免密登录（VerifyAuthLogin method=passkey 收敛点）；
//   - OIDC 回调（HandleCallback 签发前，无 2FA 用户拒绝并引导口令登录绑定）。
//
// 绑定通道为公开端点 + mfa_enroll 步会话 secret（用户此时无 access_token，
// 不能复用 /api/users/me/tfa）：pending TOTP secret 存 login_sessions.code
// 列（G2），users.info 不动，状态随会话单次存活。TTL 10 分钟（OQ-6）。
package auth

import (
	"context"
	"errors"
	"time"

	"github.com/pquerna/otp/totp"
	"uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// mfa_enroll 步会话参数（G2/OQ-6）：TTL 10 分钟（绑定流程含扫码，
// 较既有 5 分钟两步会话更长）。
const (
	sessionMethodMfaEnroll = "mfa_enroll"
	mfaEnrollTTL           = 10 * time.Minute
)

// MfaPolicyReader 强制 MFA 策略读取口（窄接口，由 service/settings 的
// MfaService 实现，避免 auth 包依赖 settings 包；模式同 RuntimeSettings）。
type MfaPolicyReader interface {
	// Enforced 返回策略侧判定：enforceGlobal 或 userGroupGuid 命中组级名单。
	Enforced(ctx context.Context, userGroupGuid string) (bool, error)
}

// MfaService 强制 MFA 判定与绑定服务。
type MfaService struct {
	users    *repository.UserRepo
	sessions *repository.LoginSessionRepo
	tokens   *TokenService
	// login 登录服务引用（verify 通过后复用 completeLogin 收敛签发；
	// 同包互引，装配期回填，见 bootstrap）。
	login *AuthService
	policy MfaPolicyReader
}

// NewMfaService 构建服务。
func NewMfaService(users *repository.UserRepo, sessions *repository.LoginSessionRepo,
	tokens *TokenService, policy MfaPolicyReader) *MfaService {
	return &MfaService{users: users, sessions: sessions, tokens: tokens, policy: policy}
}

// WithLogin 回填登录服务引用（verify 通过后复用 completeLogin 收敛签发；
// 装配期调用，解除 AuthService ↔ MfaService 构造环）。
func (s *MfaService) WithLogin(login *AuthService) *MfaService {
	s.login = login
	return s
}

// Enforced 强制判定（设计 §3.1）：策略命中且「已有 2FA」不成立。
// 已有 2FA = TOTP 已绑定（users.tfaSecret 非空）或 passkey-2FA 已开启
// （users.info.other.passkey_tfa_enabled）——passkey-2FA 用户不再强制
// 绑定 TOTP。owner/isAdmin 不豁免（OQ-2）。
func (s *MfaService) Enforced(ctx context.Context, user *entity.User) (bool, error) {
	if s.policy == nil {
		return false, nil
	}
	hit, err := s.policy.Enforced(ctx, derefStr(user.UserGroupGuid))
	if err != nil || !hit {
		return false, err
	}
	// 已有 2FA 视为满足策略（不在强制之列）。
	if user.TfaEnabled() || user.ParseUserInfo().PasskeyTfaEnabled() {
		return false, nil
	}
	return true, nil
}

// BeginMfaEnrollment 登录分流入口（loginAccount / passkey / OIDC 收敛点）：
// 建 mfa_enroll 步会话（10 分钟、单活跃，建前 DeleteExisting），返回
// type=mfa_enroll + secret（G1：secret 复用 LoginResponse.secret 承载）。
// 调用方负责 mfa_enroll_required 审计埋点。
func (s *MfaService) BeginMfaEnrollment(ctx context.Context, user *entity.User) (*api.LoginResponse, error) {
	secret, err := s.createEnrollSession(ctx, user.Guid)
	if err != nil {
		return nil, err
	}
	payload := dto.BuildUserPayload(user)
	return &api.LoginResponse{
		Type:   api.MfaEnroll,
		Secret: &secret,
		User:   &payload,
	}, nil
}

// BeginEnroll 绑定第一步（POST /api/auth/mfa/enroll，公开凭 secret）：
// 校验 mfa_enroll 步会话 → 生成 TOTP key → pending secret 存会话 code 列
// （覆盖旧 pending，重新出二维码）。返回 pending secret 与 otpauth URL。
func (s *MfaService) BeginEnroll(ctx context.Context, secret string) (api.MfaEnrollResult, error) {
	if secret == "" {
		return api.MfaEnrollResult{}, BadRequest("Secret is required")
	}
	sess, err := s.sessions.FindUsable(ctx, secret, repository.StringSet{sessionMethodMfaEnroll})
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.MfaEnrollResult{}, Unauthorized(msgStepSessionInvalid)
		}
		return api.MfaEnrollResult{}, err
	}
	user, err := s.users.FindByGuidWithSecrets(ctx, sess.UserGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.MfaEnrollResult{}, Unauthorized(msgStepSessionInvalid)
		}
		return api.MfaEnrollResult{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: user.Username,
	})
	if err != nil {
		return api.MfaEnrollResult{}, err
	}
	if err := s.sessions.UpdateCode(ctx, sess.Guid, key.Secret()); err != nil {
		return api.MfaEnrollResult{}, err
	}
	return api.MfaEnrollResult{Secret: key.Secret(), OtpauthUrl: key.URL()}, nil
}

// VerifyEnroll 绑定第二步（POST /api/auth/mfa/enroll/verify，公开凭
// secret + tfaCode）：校验 pending → 落 users.tfaSecret → MarkUsed →
// completeLogin 签发（收敛点）。验证码错误 401 固定文案；调用方负责
// mfa_enroll_completed / tfa_failed 审计埋点。
func (s *MfaService) VerifyEnroll(ctx context.Context, secret, code string, dev dto.LoginDevice, expectUsername *string) (*api.LoginResponse, error) {
	if secret == "" || code == "" {
		return nil, BadRequest("Secret and tfaCode are required")
	}
	sess, err := s.sessions.FindUsable(ctx, secret, repository.StringSet{sessionMethodMfaEnroll})
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, Unauthorized(msgStepSessionInvalid)
		}
		return nil, err
	}
	user, err := s.users.FindByGuidWithSecrets(ctx, sess.UserGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, Unauthorized(msgStepSessionInvalid)
		}
		return nil, err
	}
	pending := sess.Code
	if pending == "" {
		return nil, BadRequest("No pending two-factor enrollment")
	}
	if !totp.Validate(code, pending) {
		return nil, Unauthorized(msgTfaCodeInvalid)
	}
	// username 匹配性复核（对齐 completeStep 场景 B 第 12 步语义）。
	if expectUsername != nil && *expectUsername != "" &&
		*expectUsername != user.Username && *expectUsername != user.Email {
		return nil, Unauthorized(msgBadCredentials)
	}
	if user.Status != 1 {
		return nil, Unauthorized(msgUserDisabled)
	}
	if err := s.users.UpdateColumns(ctx, user.Guid, map[string]any{"tfaSecret": pending}); err != nil {
		return nil, err
	}
	if err := s.sessions.MarkUsed(ctx, sess.Guid); err != nil {
		return nil, err
	}
	// completeLogin 收敛签发（GAP2 时序图第 8 步）。
	return s.login.completeLogin(ctx, user, dev)
}

// createEnrollSession 建 mfa_enroll 步会话（单活跃：同用户同方法先
// DeleteExisting；guid 即对外 secret，G2）。
func (s *MfaService) createEnrollSession(ctx context.Context, userGuid string) (string, error) {
	if err := s.sessions.DeleteExisting(ctx, userGuid, sessionMethodMfaEnroll); err != nil {
		return "", err
	}
	secret := uuid.New().String()
	sess := &entity.LoginSession{
		Guid:      secret,
		UserGuid:  userGuid,
		Method:    sessionMethodMfaEnroll,
		Code:      "",
		ExpiresAt: time.Now().Add(mfaEnrollTTL),
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return "", err
	}
	return secret, nil
}
