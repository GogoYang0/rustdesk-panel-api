// Package user 实现 user 域服务：当前用户资料维护与头像管理。
package user

import (
	"context"
	"errors"
	"net/mail"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// ProfileService 当前用户资料：PATCH users/me 与改密。
type ProfileService struct {
	db       *gorm.DB
	users    *repository.UserRepo
	tokens   *repository.UserTokenRepo
	sessions *repository.LoginSessionRepo
}

// NewProfileService 构建服务。db 用于改密事务；tokens/sessions 语义由
// revokeActiveTokensTx 承担（保留字段供其他自助端点扩展）。
func NewProfileService(db *gorm.DB, users *repository.UserRepo, tokens *repository.UserTokenRepo, sessions *repository.LoginSessionRepo) *ProfileService {
	return &ProfileService{db: db, users: users, tokens: tokens, sessions: sessions}
}

// UpdateMe 更新 display_name / email / note（nil 字段不更新）。
// email 需合法且唯一（409 冲突）；返回更新后的完整 payload。
func (s *ProfileService) UpdateMe(ctx context.Context, guid string, req dto.UpdateMeRequest) (api.UserPayload, error) {
	if _, err := s.users.FindByGuidWithSecrets(ctx, guid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.UserPayload{}, authsvc.NotFound("User not found")
		}
		return api.UserPayload{}, err
	}

	updates := map[string]any{}
	if req.Email != nil {
		email := *req.Email
		if email != "" {
			if _, err := mail.ParseAddress(email); err != nil {
				return api.UserPayload{}, authsvc.BadRequest("Email is invalid")
			}
			if owner, err := s.users.FindByUsernameOrEmail(ctx, email); err == nil && owner.Guid != guid {
				return api.UserPayload{}, authsvc.Conflict("Email is already in use")
			} else if err != nil && !errors.Is(err, repository.ErrNotFound) {
				return api.UserPayload{}, err
			}
		}
		updates["email"] = email
	}
	if req.DisplayName != nil {
		updates["displayName"] = *req.DisplayName
	}
	if req.Note != nil {
		updates["note"] = *req.Note
	}

	if err := s.users.UpdateColumns(ctx, guid, updates); err != nil {
		return api.UserPayload{}, err
	}

	// 重新加载全列，payload 的敏感标志位（has_password 等）保持准确。
	fresh, err := s.users.FindByGuidWithSecrets(ctx, guid)
	if err != nil {
		return api.UserPayload{}, err
	}
	return dto.BuildUserPayload(fresh), nil
}

// ChangePassword 修改密码：bcrypt 复核旧密码；新密码至少 6 位。
// 改密与撤销在**同一 DB 事务**内执行（MIN-04）：user_tokens 全量置
// isRevoked + 清理未使用的两步登录中间态，撤销失败整体回滚，强制所有
// 端重新登录。
func (s *ProfileService) ChangePassword(ctx context.Context, guid string, req dto.ChangePasswordRequest) (api.MessageResponse, error) {
	if req.CurrentPassword == "" || req.NewPassword == "" {
		return api.MessageResponse{}, authsvc.BadRequest("Current and new password are required")
	}
	if len(req.NewPassword) < 6 {
		return api.MessageResponse{}, authsvc.BadRequest("New password must be at least 6 characters")
	}
	user, err := s.users.FindByGuidWithSecrets(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, authsvc.NotFound("User not found")
		}
		return api.MessageResponse{}, err
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword)) != nil {
		return api.MessageResponse{}, authsvc.Unauthorized("Current password is incorrect")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 10)
	if err != nil {
		return api.MessageResponse{}, err
	}
	// MIN-04：改密与撤销合并同一 DB 事务——user_tokens 撤销或
	// login_sessions 清理任一失败，密码更新一并回滚，杜绝
	// "密码已改而旧会话仍有效"的漏撤销窗口。
	now := time.Now()
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&entity.User{}).
			Where("guid = ?", guid).
			Updates(map[string]any{"password": string(hash), "updatedAt": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return repository.ErrNotFound
		}
		// 会话撤销：改密后旧 token 一律失效（含当前请求方），客户端须重新登录。
		return revokeActiveTokensTx(tx, guid)
	}); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, authsvc.NotFound("User not found")
		}
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Password changed"}, nil
}
