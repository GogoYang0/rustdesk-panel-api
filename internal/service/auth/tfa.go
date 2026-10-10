package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/pquerna/otp/totp"
	"uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// totpIssuer 固定 issuer（共享知识 8）。
const totpIssuer = "RustDesk"

// TfaService TOTP 两步验证：密钥生成/绑定/关闭与两步登录。
type TfaService struct {
	users    *repository.UserRepo
	sessions *repository.LoginSessionRepo
	tokens   *TokenService
}

// NewTfaService 构建服务。
func NewTfaService(users *repository.UserRepo, sessions *repository.LoginSessionRepo, tokens *TokenService) *TfaService {
	return &TfaService{users: users, sessions: sessions, tokens: tokens}
}

// Setup 生成 TOTP 密钥：pending secret 存 users.info.other.tfa_pending_secret
// （共享知识 6），每次调用覆盖旧 pending（重新出二维码）；
// 已绑定用户的正式 tfaSecret 不受影响，直至 verify 通过才覆盖。
func (s *TfaService) Setup(ctx context.Context, userGuid string) (dto.SetupTfaResult, error) {
	user, err := s.users.FindByGuidWithSecrets(ctx, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.SetupTfaResult{}, NotFound("User not found")
		}
		return dto.SetupTfaResult{}, err
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: user.Username,
	})
	if err != nil {
		return dto.SetupTfaResult{}, err
	}
	info := user.ParseUserInfo()
	info.SetTfaPendingSecret(key.Secret())
	if err := s.users.UpdateColumns(ctx, user.Guid, map[string]any{"info": marshalInfo(info)}); err != nil {
		return dto.SetupTfaResult{}, err
	}
	// Secret 必须是 base32（key.Secret()）；key.String() 是完整 otpauth URL。
	return dto.SetupTfaResult{Secret: key.Secret(), OtpauthURL: key.URL()}, nil
}

// VerifyAndBind 校验验证码并绑定：通过后落 users.tfaSecret 并清除 pending。
func (s *TfaService) VerifyAndBind(ctx context.Context, userGuid, code string) (api.MessageResponse, error) {
	user, err := s.users.FindByGuidWithSecrets(ctx, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, NotFound("User not found")
		}
		return api.MessageResponse{}, err
	}
	info := user.ParseUserInfo()
	pending := info.TfaPendingSecret()
	if pending == "" {
		return api.MessageResponse{}, BadRequest("No pending two-factor setup")
	}
	if !totp.Validate(code, pending) {
		return api.MessageResponse{}, Unauthorized(msgTfaCodeInvalid)
	}
	info.SetTfaPendingSecret("")
	updates := map[string]any{"tfaSecret": pending, "info": marshalInfo(info)}
	if err := s.users.UpdateColumns(ctx, user.Guid, updates); err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Two-factor authentication enabled"}, nil
}

// Disable 关闭 2FA：需携带当前有效验证码（§2.1 #7）。
func (s *TfaService) Disable(ctx context.Context, userGuid, code string) (api.MessageResponse, error) {
	user, err := s.users.FindByGuidWithSecrets(ctx, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, NotFound("User not found")
		}
		return api.MessageResponse{}, err
	}
	if user.TfaSecret == "" {
		return api.MessageResponse{}, BadRequest("Two-factor authentication is not enabled")
	}
	if !totp.Validate(code, user.TfaSecret) {
		return api.MessageResponse{}, Unauthorized(msgTfaCodeInvalid)
	}
	if err := s.users.UpdateColumns(ctx, user.Guid, map[string]any{"tfaSecret": ""}); err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Two-factor authentication disabled"}, nil
}

// BeginTfaLogin 场景 B 前半段：建 tfa 会话（5 分钟、单活跃，建前 DeleteExisting），
// 返回 type=email_check + tfa_type=tfa_check + secret（客户端兼容形态，共享知识 7）。
func (s *TfaService) BeginTfaLogin(ctx context.Context, user *entity.User) (*api.LoginResponse, error) {
	secret, err := s.createStepSession(ctx, user.Guid, sessionMethodTfa, "")
	if err != nil {
		return nil, err
	}
	tfaType := api.TfaCheck
	payload := dto.BuildUserPayload(user)
	return &api.LoginResponse{
		Type:    api.EmailCheck,
		TfaType: &tfaType,
		Secret:  &secret,
		User:    &payload,
	}, nil
}

// CompleteTfaLogin 场景 B 后半段：type=tfa_code 分支
// （secret+tfaCode，单次使用，username 匹配性复核）。
func (s *TfaService) CompleteTfaLogin(ctx context.Context, req *api.LoginRequest, dev dto.LoginDevice) (*api.LoginResponse, error) {
	if req.Secret == nil || *req.Secret == "" || req.TfaCode == nil || *req.TfaCode == "" {
		return nil, BadRequest("Secret and tfaCode are required")
	}
	return s.completeStep(ctx, *req.Secret, *req.TfaCode, sessionMethodTfa, dev, req.Username)
}

// CompleteEmailCodeLogin type=email_code 分支（secret+verificationCode）。
// M1 无邮件发送域；email 会话仅可由既有流程注入，完成逻辑与 TOTP 同构。
func (s *TfaService) CompleteEmailCodeLogin(ctx context.Context, req *api.LoginRequest, dev dto.LoginDevice) (*api.LoginResponse, error) {
	if req.Secret == nil || *req.Secret == "" || req.VerificationCode == nil || *req.VerificationCode == "" {
		return nil, BadRequest("Secret and verificationCode are required")
	}
	return s.completeStep(ctx, *req.Secret, *req.VerificationCode, sessionMethodEmail, dev, req.Username)
}

// completeStep 两步验证完成骨架：查可用会话 → 校验验证码 →
// username 复核 → status 复核 → 单次使用标记 → 签发。
func (s *TfaService) completeStep(ctx context.Context, secret, code, method string, dev dto.LoginDevice, expectUsername *string) (*api.LoginResponse, error) {
	sess, err := s.sessions.FindUsable(ctx, secret, repository.StringSet{method})
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
	switch method {
	case sessionMethodTfa:
		if !totp.Validate(code, user.TfaSecret) {
			return nil, Unauthorized(msgTfaCodeInvalid)
		}
	case sessionMethodEmail:
		if subtle.ConstantTimeCompare([]byte(code), []byte(sess.Code)) != 1 {
			return nil, Unauthorized(msgTfaCodeInvalid)
		}
	}
	// username 匹配性复核（设计场景 B 第 12 步）。
	if expectUsername != nil && *expectUsername != "" &&
		*expectUsername != user.Username && *expectUsername != user.Email {
		return nil, Unauthorized(msgBadCredentials)
	}
	if user.Status != 1 {
		return nil, Unauthorized(msgUserDisabled)
	}
	if err := s.sessions.MarkUsed(ctx, sess.Guid); err != nil {
		return nil, err
	}
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

// createStepSession 建两步验证会话：同用户同方法先 DeleteExisting（单活跃），
// guid 即对外 secret（共享知识 3），code 存可选验证码载体（如邮箱码）。
func (s *TfaService) createStepSession(ctx context.Context, userGuid, method, code string) (string, error) {
	if err := s.sessions.DeleteExisting(ctx, userGuid, method); err != nil {
		return "", err
	}
	secret := uuid.New().String()
	sess := &entity.LoginSession{
		Guid:      secret,
		UserGuid:  userGuid,
		Method:    method,
		Code:      code,
		ExpiresAt: time.Now().Add(twoStepTTL),
	}
	if err := s.sessions.Create(ctx, sess); err != nil {
		return "", err
	}
	return secret, nil
}
