package user

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// 固定文案（契约 §4.1 verify 三态 + accept/invite 响应，测试逐字节断言）。
const (
	msgInvalidToken   = "Invalid invitation token"
	msgInvitationUsed = "Invitation has already been used"
	msgInvitationExp  = "Invitation has expired"
	msgInvitationSent = "Invitation sent"
	msgActivated      = "Account activated, please log in"
	msgPasswordMin    = "Password must be at least 6 characters"
)

// Invite POST /api/users/invite（users.create 中间件已过；body 携带
// user_group_guid 时追加 user_groups.membership 条件授权）：
// 建用户 password=”、status=-1（UNVERIFIED）+ invitations 行
// （token=32B hex、expiresAt=+7d）；邮件失败不阻断，token 明文降级。
func (s *Service) Invite(ctx context.Context, actorGuid string, req api.InviteUserRequest) (api.InviteResult, error) {
	// 必填防御（spec required [email, name]；生成类型无 validate 标签）。
	if req.Email == "" || req.Name == "" {
		return api.InviteResult{}, authsvc.BadRequest("Email and name are required")
	}
	username := string(req.Email)
	if req.UserGroupGuid != nil && *req.UserGroupGuid != "" {
		if _, err := s.authz.RequirePermission(ctx, actorGuid, rbac.CodeUserGroupsMembership); err != nil {
			return api.InviteResult{}, err
		}
		if err := s.assertGroupExists(ctx, *req.UserGroupGuid); err != nil {
			return api.InviteResult{}, err
		}
	}
	// username=email：重名/重邮箱均 400（与 POST users 同文案）。
	if dup, err := s.users.FindByUsername(ctx, username); err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			return api.InviteResult{}, err
		}
	} else if dup != nil {
		return api.InviteResult{}, authsvc.BadRequest("Username already exists")
	}
	if dup, err := s.users.FindByEmail(ctx, username); err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			return api.InviteResult{}, err
		}
	} else if dup != nil {
		return api.InviteResult{}, authsvc.BadRequest("Email is already in use")
	}

	token, err := newInviteToken()
	if err != nil {
		return api.InviteResult{}, err
	}
	now := time.Now()
	u := &entity.User{
		Guid:          uuid.New().String(),
		Username:      username,
		DisplayName:   req.Name,
		Email:         username,
		Password:      "", // 接受邀请前无口令（禁止登录）
		Note:          derefOrEmpty(req.Note),
		Status:        -1, // UNVERIFIED
		UserGroupGuid: req.UserGroupGuid,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	inv := &entity.Invitation{
		Guid:          uuid.New().String(),
		Token:         token,
		Email:         username,
		Name:          req.Name,
		DisplayName:   req.DisplayName,
		UserGroupGuid: req.UserGroupGuid,
		Note:          derefOrEmpty(req.Note),
		ExpiresAt:     now.Add(inviteTTL),
		CreatedAt:     now,
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(u).Error; err != nil {
			return err
		}
		inv.UserGuid = &u.Guid
		return tx.Create(inv).Error
	}); err != nil {
		return api.InviteResult{}, err
	}

	// 邮件旁路发送：失败降级 token 明文回退给管理员（设计事实①）。
	link := s.effectiveFrontendURL() + "/register?token=" + token
	sent := false
	if s.mailer != nil {
		sent = s.mailer.SendInvitation(username, req.Name, link)
	}
	res := api.InviteResult{Message: msgInvitationSent}
	if !sent {
		res.Token = &token
	}
	return res, nil
}

// newInviteToken 32 字节 CSPRNG → 64 字符 hex。
func newInviteToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Verify POST /api/invitations/verify（Public）：token 无效/已用/过期
// → 400 固定文案；成功返回 {name, display_name(可空串), email}。
func (s *Service) Verify(ctx context.Context, token string) (api.InvitationInfo, error) {
	inv, err := s.findActiveInvitation(ctx, token)
	if err != nil {
		return api.InvitationInfo{}, err
	}
	return api.InvitationInfo{
		DisplayName: derefOrEmpty(inv.DisplayName),
		Email:       openapi_types.Email(inv.Email),
		Name:        inv.Name,
	}, nil
}

// Accept POST /api/invitations/accept（Public）：password≥6；
// 事务内 bcrypt(10) + status=1（ACTIVE）+ usedAt=now + 撤 token 兜底。
func (s *Service) Accept(ctx context.Context, req api.InvitationAcceptRequest) (api.MessageResponse, error) {
	if len(req.Password) < 6 {
		return api.MessageResponse{}, authsvc.BadRequest(msgPasswordMin)
	}
	inv, err := s.findActiveInvitation(ctx, req.Token)
	if err != nil {
		return api.MessageResponse{}, err
	}
	if inv.UserGuid == nil || *inv.UserGuid == "" {
		// 邀请引用的用户已被删除（应用层级联置空）→ 无效。
		return api.MessageResponse{}, authsvc.BadRequest(msgInvalidToken)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		return api.MessageResponse{}, err
	}
	userGuid := *inv.UserGuid
	now := time.Now()
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&entity.User{}).
			Where("guid = ?", userGuid).
			Updates(map[string]any{"password": string(hash), "status": 1, "updatedAt": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return authsvc.BadRequest(msgInvalidToken)
		}
		if err := s.invites.MarkUsedTx(tx, inv.Guid, now); err != nil {
			return err
		}
		// 激活兜底：撤销历史 token/未使用会话（设计 §4.1 时序）。
		return s.revokeActiveTokens(ctx, tx, userGuid)
	}); err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: msgActivated}, nil
}

// findActiveInvitation 查邀请并复核三态（无效/已用/过期 → 400 固定文案）。
func (s *Service) findActiveInvitation(ctx context.Context, token string) (*entity.Invitation, error) {
	inv, err := s.invites.FindByToken(ctx, token)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, authsvc.BadRequest(msgInvalidToken)
		}
		return nil, err
	}
	if inv.IsUsed() {
		return nil, authsvc.BadRequest(msgInvitationUsed)
	}
	if inv.IsExpired(time.Now()) {
		return nil, authsvc.BadRequest(msgInvitationExp)
	}
	return inv, nil
}
