package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// PasskeyService WebAuthn/Passkey：注册、免密登录、passkey 二次验证。
// 挑战统一存 login_sessions（method ∈ passkey_reg|passkey|passkey_tfa，
// 共享知识 7），code 列存放 base64url challenge。
type PasskeyService struct {
	web      *webauthn.WebAuthn
	users    *repository.UserRepo
	sessions *repository.LoginSessionRepo
	creds    *repository.PasskeyRepo
	tokens   *TokenService
	// mfa 强制 MFA 判定服务（GAP2 OQ-3：免密通道统一执行；nil 时无强制）。
	mfa *MfaService
	// audits 登录审计记录器（GAP2 G3；nil 时跳过）。
	audits *LoginAuditRecorder
}

// NewPasskeyService 构建服务（RPID 与可信 origins 来自 env，
// 批复事项 #7：M1 由 WEBAUTHN_RP_ID/WEBAUTHN_ORIGINS 承载）。
func NewPasskeyService(rpid string, origins []string, users *repository.UserRepo,
	sessions *repository.LoginSessionRepo, creds *repository.PasskeyRepo, tokens *TokenService) (*PasskeyService, error) {
	if len(origins) == 0 {
		return nil, errors.New("passkey: WEBAUTHN_ORIGINS must not be empty")
	}
	w, err := webauthn.New(&webauthn.Config{
		RPID:          rpid,
		RPDisplayName: "RustDesk Panel",
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: init webauthn failed: %w", err)
	}
	return &PasskeyService{web: w, users: users, sessions: sessions, creds: creds, tokens: tokens}, nil
}

// WithMfa 注入强制 MFA 服务与登录审计记录器（bootstrap 装配；GAP2）。
func (s *PasskeyService) WithMfa(mfa *MfaService, audits *LoginAuditRecorder) *PasskeyService {
	s.mfa = mfa
	s.audits = audits
	return s
}

// BeginRegistration 开始注册（§2.1 #8）：返回 PublicKeyCredentialCreationOptionsJSON，
// 挑战存 login_sessions(method=passkey_reg)。
func (s *PasskeyService) BeginRegistration(ctx context.Context, userGuid string) (map[string]any, error) {
	user, err := s.users.FindByGuidWithSecrets(ctx, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, NotFound("User not found")
		}
		return nil, err
	}
	records, err := s.creds.ListByUser(ctx, user.Guid)
	if err != nil {
		return nil, err
	}
	wu := webUserOf(user, convertCredentials(records))
	// 已注册凭据加入排除列表，防止同 authenticator 重复注册。
	exclusions := make([]protocol.CredentialDescriptor, 0, len(records))
	for _, r := range records {
		if raw, err := base64.RawURLEncoding.DecodeString(r.CredentialId); err == nil {
			exclusions = append(exclusions, protocol.CredentialDescriptor{
				Type:         protocol.PublicKeyCredentialType,
				CredentialID: raw,
			})
		}
	}
	opts := []webauthn.RegistrationOption{
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
		webauthn.WithConveyancePreference(protocol.PreferNoAttestation),
	}
	if len(exclusions) > 0 {
		opts = append(opts, webauthn.WithExclusions(exclusions))
	}
	creation, sess, err := s.web.BeginRegistration(wu, opts...)
	if err != nil {
		return nil, err
	}
	if _, err := s.createChallengeSession(ctx, user.Guid, sessionMethodPasskeyReg, sess.Challenge); err != nil {
		return nil, err
	}
	return structToMap(creation)
}

// VerifyRegistration 完成注册（§2.1 #9）：取该用户最近一条可用
// passkey_reg 挑战会话，校验通过后落凭据（含 counter 初始值）。
func (s *PasskeyService) VerifyRegistration(ctx context.Context, userGuid string, resp map[string]any, name string) (api.MessageResponse, error) {
	user, err := s.users.FindByGuidWithSecrets(ctx, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, NotFound("User not found")
		}
		return api.MessageResponse{}, err
	}
	sess, err := s.latestUsableSession(ctx, user.Guid, sessionMethodPasskeyReg)
	if err != nil {
		return api.MessageResponse{}, err
	}
	raw, err := json.Marshal(resp)
	if err != nil {
		return api.MessageResponse{}, BadRequest("Invalid credential response")
	}
	ccr := protocol.CredentialCreationResponse{}
	if err := json.Unmarshal(raw, &ccr); err != nil || ccr.ID == "" {
		return api.MessageResponse{}, BadRequest("Invalid credential response")
	}
	parsed, err := ccr.Parse()
	if err != nil {
		return api.MessageResponse{}, BadRequest("Invalid credential response")
	}
	records, err := s.creds.ListByUser(ctx, user.Guid)
	if err != nil {
		return api.MessageResponse{}, err
	}
	cred, err := s.web.CreateCredential(
		webUserOf(user, convertCredentials(records)),
		// CredParams 用默认算法集重建（与 BeginRegistration 一致），
		// 否则 Step16 算法匹配因空列表而拒绝 ES256。
		webauthn.SessionData{
			Challenge:  sess.Code,
			UserID:     []byte(user.Guid),
			Expires:    sess.ExpiresAt,
			CredParams: webauthn.CredentialParametersDefault(),
		},
		parsed,
	)
	if err != nil {
		return api.MessageResponse{}, Unauthorized(msgPasskeyRejected)
	}
	record := &entity.PasskeyCredential{
		Guid:                uuid.New().String(),
		UserGuid:            user.Guid,
		CredentialId:        base64.RawURLEncoding.EncodeToString(cred.ID),
		CredentialPublicKey: base64.StdEncoding.EncodeToString(cred.PublicKey),
		Counter:             cred.Authenticator.SignCount,
		Transports:          joinTransports(cred.Transport),
		DeviceType:          cred.AttestationFormat,
		BackedUp:            cred.Flags.BackupState,
		Name:                credentialName(name),
	}
	if err := s.creds.Create(ctx, record); err != nil {
		return api.MessageResponse{}, err
	}
	if err := s.sessions.MarkUsed(ctx, sess.Guid); err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Passkey registered"}, nil
}

// BeginAuthLogin 场景 C 前半段（§2.1 #10）：免密登录发现式断言，
// 会话 userGuid 为空串（用户未知，凭 userHandle 反查）。
func (s *PasskeyService) BeginAuthLogin(ctx context.Context) (dto.BeginAuthResult, error) {
	assertion, sess, err := s.web.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		return dto.BeginAuthResult{}, err
	}
	secret := uuid.New().String()
	record := &entity.LoginSession{
		Guid:      secret,
		UserGuid:  "",
		Method:    sessionMethodPasskey,
		Code:      sess.Challenge,
		ExpiresAt: time.Now().Add(twoStepTTL),
	}
	if err := s.sessions.Create(ctx, record); err != nil {
		return dto.BeginAuthResult{}, err
	}
	options, err := structToMap(assertion)
	if err != nil {
		return dto.BeginAuthResult{}, err
	}
	return dto.BeginAuthResult{Secret: secret, Options: options}, nil
}

// VerifyAuthLogin 场景 C 后半段（§2.1 #11）与 passkey_tfa 第二步共用：
// method=passkey → 发现式登录（凭 userHandle 反查用户）；
// method=passkey_tfa → 会话已绑定用户，凭据必须属于该用户。
// counter 递增校验防凭据克隆（设计场景 C 第 10 步）。
func (s *PasskeyService) VerifyAuthLogin(ctx context.Context, req dto.VerifyAuthRequest) (*api.LoginResponse, error) {
	sess, err := s.sessions.FindUsable(ctx, req.Secret,
		repository.StringSet{sessionMethodPasskey, sessionMethodPasskeyTfa})
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, Unauthorized(msgStepSessionInvalid)
		}
		return nil, err
	}
	raw, err := json.Marshal(req.Response)
	if err != nil {
		return nil, BadRequest("Invalid assertion response")
	}
	car := protocol.CredentialAssertionResponse{}
	if err := json.Unmarshal(raw, &car); err != nil || car.ID == "" {
		return nil, BadRequest("Invalid assertion response")
	}
	parsed, err := car.Parse()
	if err != nil {
		return nil, BadRequest("Invalid assertion response")
	}
	credRecord, err := s.creds.FindByCredentialId(ctx, car.ID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, Unauthorized(msgPasskeyRejected)
		}
		return nil, err
	}
	user, err := s.users.FindByGuidWithSecrets(ctx, credRecord.UserGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, Unauthorized(msgPasskeyRejected)
		}
		return nil, err
	}
	// passkey_tfa：会话绑定用户，凭据必须属于该用户（防跨账号令牌化）。
	if sess.Method == sessionMethodPasskeyTfa && sess.UserGuid != "" && sess.UserGuid != user.Guid {
		return nil, Unauthorized(msgStepSessionInvalid)
	}
	wu := webUserOf(user, []webauthn.Credential{credentialFromRecord(*credRecord)})
	// 发现式会话（BeginDiscoverableLogin）不带 UserID；ValidatePasskeyLogin
	// 以 UserID 为空作为"发现式发起"的标记（go-webauthn 约定）。
	sessionData := webauthn.SessionData{
		Challenge:            sess.Code,
		Expires:              sess.ExpiresAt,
		AllowedCredentialIDs: [][]byte{},
		// 挑战会话仅持久化 challenge 字符串；verify 侧以 go-webauthn
		// 默认算法集重建（与 BeginRegistration 的默认生成一致），
		// 否则注册校验因 CredParams 为空而拒绝 ES256。
		CredParams: webauthn.CredentialParametersDefault(),
	}
	var cred *webauthn.Credential
	if sess.Method == sessionMethodPasskeyTfa {
		sessionData.UserID = []byte(user.Guid)
		// 断言须命中会话用户的凭据（AllowedCredentials 限定）。
		credRaw, err := base64.RawURLEncoding.DecodeString(credRecord.CredentialId)
		if err != nil {
			return nil, Unauthorized(msgPasskeyRejected)
		}
		sessionData.AllowedCredentialIDs = [][]byte{credRaw}
		cred, err = s.web.ValidateLogin(wu, sessionData, parsed)
		if err != nil {
			return nil, Unauthorized(msgPasskeyRejected)
		}
	} else {
		// 发现式：userHandle 必须与凭据归属用户一致（防账号接管）。
		if len(parsed.Response.UserHandle) > 0 &&
			string(parsed.Response.UserHandle) != user.Guid {
			return nil, Unauthorized(msgPasskeyRejected)
		}
		if _, cred, err = s.web.ValidatePasskeyLogin(
			func(rawID, userHandle []byte) (webauthn.User, error) { return wu, nil },
			sessionData, parsed,
		); err != nil {
			return nil, Unauthorized(msgPasskeyRejected)
		}
	}
	// counter 回退检测：非零计数器不递增即视为克隆（测试场景覆盖）。
	newCount := cred.Authenticator.SignCount
	oldCount := credRecord.Counter
	if (newCount != 0 || oldCount != 0) && newCount <= oldCount {
		s.recordLoginAudit(ctx, entity.LoginAuditResultFailed, sess.Method, user, auditReasonPasskeyFailed)
		return nil, Unauthorized(msgPasskeyRejected)
	}
	if err := s.creds.UpdateCounter(ctx, credRecord.Guid, newCount); err != nil {
		return nil, err
	}
	// GAP2 OQ-3：passkey 免密通道统一执行强制 MFA 判定——策略命中且
	// 无 TOTP/passkey-2FA（本分支用户 passkey-2FA 必然未开启，否则
	// 走 passkey_tfa 分支）→ 转入 mfa_enroll 绑定步会话，不发 access_token。
	if sess.Method == sessionMethodPasskey && s.mfa != nil {
		enforced, err := s.mfa.Enforced(ctx, user)
		if err != nil {
			return nil, err
		}
		if enforced {
			s.recordLoginAudit(ctx, entity.LoginAuditResultMfaEnrollRequired, entity.LoginAuditMethodPasskey, user, "")
			return s.mfa.BeginMfaEnrollment(ctx, user)
		}
	}
	if err := s.sessions.MarkUsed(ctx, sess.Guid); err != nil {
		return nil, err
	}
	token, err := s.tokens.Generate(ctx, user, req.Device)
	if err != nil {
		return nil, err
	}
	// GAP2 G3：免密/passkey-2FA 成功审计（method 归一 passkey 枚举）。
	s.recordLoginAudit(ctx, entity.LoginAuditResultSuccess, entity.LoginAuditMethodPasskey, user, "")
	payload := dto.BuildUserPayload(user)
	return &api.LoginResponse{
		AccessToken: &token,
		Type:        api.AccessToken,
		User:        &payload,
	}, nil
}

// recordLoginAudit passkey 路径的 best-effort 审计（GAP2 G3）。
func (s *PasskeyService) recordLoginAudit(ctx context.Context, result, method string, user *entity.User, reason string) {
	s.audits.Record(ctx, LoginAuditEntry{
		UserGuid: strPtr(user.Guid), Username: user.Username,
		Result: result, Method: method, Reason: reason,
	})
}

// BeginTfaLogin passkey 二次验证第一步：为已认证用户生成断言挑战
// （AllowCredentials 绑定其全部凭据），返回 passkey_check 形态响应
// （passkey_options 供客户端发起 navigator.credentials.get）。
func (s *PasskeyService) BeginTfaLogin(ctx context.Context, user *entity.User) (*api.LoginResponse, error) {
	records, err := s.creds.ListByUser(ctx, user.Guid)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, BadRequest("No passkey registered")
	}
	wu := webUserOf(user, convertCredentials(records))
	assertion, sess, err := s.web.BeginLogin(wu)
	if err != nil {
		return nil, err
	}
	secret, err := s.createChallengeSession(ctx, user.Guid, sessionMethodPasskeyTfa, sess.Challenge)
	if err != nil {
		return nil, err
	}
	// options 必须是 PublicKeyCredentialRequestOptions JSON（含 publicKey 包装），
	// 与 BeginAuthLogin 一致；session 结构体仅服务端内部使用。
	options, err := structToMap(assertion)
	if err != nil {
		return nil, err
	}
	tfaType := api.PasskeyCheck
	payload := dto.BuildUserPayload(user)
	return &api.LoginResponse{
		Type:           api.EmailCheck,
		TfaType:        &tfaType,
		Secret:         &secret,
		PasskeyOptions: &options,
		User:           &payload,
	}, nil
}

// List 当前用户凭据列表（§2.1 #12）。
func (s *PasskeyService) List(ctx context.Context, userGuid string) ([]api.PasskeyView, error) {
	records, err := s.creds.ListByUser(ctx, userGuid)
	if err != nil {
		return nil, err
	}
	out := make([]api.PasskeyView, 0, len(records))
	for _, r := range records {
		view := api.PasskeyView{Guid: r.Guid}
		name := r.Name
		view.Name = &name
		backedUp := r.BackedUp
		view.BackedUp = &backedUp
		deviceType := r.DeviceType
		view.DeviceType = &deviceType
		out = append(out, view)
	}
	return out, nil
}

// Delete 删除凭据；不属于当前用户时报 404（不泄漏存在性）。
func (s *PasskeyService) Delete(ctx context.Context, userGuid, guid string) error {
	record, err := s.creds.FindByID(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return NotFound("Passkey not found")
		}
		return err
	}
	if record.UserGuid != userGuid {
		return NotFound("Passkey not found")
	}
	return s.creds.Delete(ctx, repository.Clause{Field: "guid", Op: repository.OpEq, Value: guid})
}

// ToggleTfa passkey 作为二次验证的开关（§2.1 #14）。
// 开启前置条件：至少已注册一把 passkey。
func (s *PasskeyService) ToggleTfa(ctx context.Context, userGuid string, enabled bool) (api.MessageResponse, error) {
	user, err := s.users.FindByGuidWithSecrets(ctx, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, NotFound("User not found")
		}
		return api.MessageResponse{}, err
	}
	info := user.ParseUserInfo()
	if enabled {
		records, err := s.creds.ListByUser(ctx, userGuid)
		if err != nil {
			return api.MessageResponse{}, err
		}
		if len(records) == 0 {
			return api.MessageResponse{}, BadRequest("No passkey registered")
		}
		info.SetPasskeyTfaEnabled(true)
	} else {
		info.SetPasskeyTfaEnabled(false)
	}
	if err := s.users.UpdateColumns(ctx, user.Guid, map[string]any{"info": marshalInfo(info)}); err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Passkey two-factor updated"}, nil
}

// ---- 内部辅助 ----

// createChallengeSession 建 passkey 挑战会话（单活跃：同用户同方法先清理；
// 免密登录 userGuid 为空串不清理，允许并发发起）。
func (s *PasskeyService) createChallengeSession(ctx context.Context, userGuid, method, challenge string) (string, error) {
	if userGuid != "" {
		if err := s.sessions.DeleteExisting(ctx, userGuid, method); err != nil {
			return "", err
		}
	}
	secret := uuid.New().String()
	record := &entity.LoginSession{
		Guid:      secret,
		UserGuid:  userGuid,
		Method:    method,
		Code:      challenge,
		ExpiresAt: time.Now().Add(twoStepTTL),
	}
	if err := s.sessions.Create(ctx, record); err != nil {
		return "", err
	}
	return secret, nil
}

// latestUsableSession 按用户+方法取最近一条未用未过期会话
// （注册 verify 请求只带 response 不带 secret，挑战按用户回溯）。
func (s *PasskeyService) latestUsableSession(ctx context.Context, userGuid, method string) (*entity.LoginSession, error) {
	var list []entity.LoginSession
	// login_sessions 无 createdAt 列（迁移契约）；同 TTL 会话中
	// expiresAt 最晚者即最近创建，语义等价。
	err := s.sessions.Scoped(ctx,
		repository.Clause{Field: "userGuid", Op: repository.OpEq, Value: userGuid},
		repository.Clause{Field: "method", Op: repository.OpEq, Value: method},
		repository.Clause{Field: "used", Op: repository.OpEq, Value: false},
		repository.Clause{Field: "expiresAt", Op: repository.OpGt, Value: time.Now()},
	).Order("expiresAt DESC").Limit(1).Find(&list).Error
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, Unauthorized(msgStepSessionInvalid)
	}
	return &list[0], nil
}

// webUserOf 适配 entity.User 满足 webauthn.User。
func webUserOf(u *entity.User, creds []webauthn.Credential) *webUser {
	return &webUser{guid: u.Guid, name: u.Username, displayName: u.DisplayName, creds: creds}
}

// webUser webauthn.User 实现：WebAuthnID = guid 字节（userHandle）。
type webUser struct {
	guid        string
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte          { return []byte(u.guid) }
func (u *webUser) WebAuthnName() string        { return u.name }
func (u *webUser) WebAuthnDisplayName() string { return u.displayName }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential {
	if u.creds == nil {
		return []webauthn.Credential{}
	}
	return u.creds
}

// convertCredentials 实体记录 → webauthn.Credential。
func convertCredentials(records []entity.PasskeyCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(records))
	for _, r := range records {
		out = append(out, credentialFromRecord(r))
	}
	return out
}

// credentialFromRecord 单条记录转换（public key base64 std 存储，id base64url）。
func credentialFromRecord(r entity.PasskeyCredential) webauthn.Credential {
	cred := webauthn.Credential{
		Authenticator: webauthn.Authenticator{SignCount: r.Counter},
		Flags: webauthn.CredentialFlags{
			BackupEligible: r.BackedUp,
			BackupState:    r.BackedUp,
		},
		Transport: parseTransports(r.Transports),
	}
	if cred.Transport == nil {
		cred.Transport = []protocol.AuthenticatorTransport{}
	}
	if id, err := base64.RawURLEncoding.DecodeString(r.CredentialId); err == nil {
		cred.ID = id
	}
	if pub, err := base64.StdEncoding.DecodeString(r.CredentialPublicKey); err == nil {
		cred.PublicKey = pub
	}
	return cred
}

// parseTransports 还原 transports 逗号串。
func parseTransports(s string) []protocol.AuthenticatorTransport {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]protocol.AuthenticatorTransport, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, protocol.AuthenticatorTransport(p))
		}
	}
	return out
}

// joinTransports 序列化 transports 为逗号串（落库）。
func joinTransports(transport []protocol.AuthenticatorTransport) string {
	parts := make([]string, 0, len(transport))
	for _, t := range transport {
		parts = append(parts, string(t))
	}
	return strings.Join(parts, ",")
}

// credentialName 兜底凭据显示名。
func credentialName(name string) string {
	if name == "" {
		return "Passkey"
	}
	return name
}

// structToMap 结构体 → 通用 JSON map（options 契约为开放对象）。
func structToMap(v any) (map[string]any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
