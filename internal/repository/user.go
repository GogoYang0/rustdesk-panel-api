package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// PublicUserColumns 公共列清单（顺序稳定，供 Select 与列断言测试）。
// 敏感列（password/verifier/tfaSecret/emailVerificationCode）经白名单
// 方式默认排除，凭 WithSecrets 系列方法显式加载。
var PublicUserColumns = []string{
	"guid", "username", "displayName", "email", "note", "status", "isAdmin",
	"info", "thirdAuthType", "oidcSubject", "avatar", "strategyGuid",
	"userGroupGuid", "createdAt", "updatedAt",
}

// UserRepo users 表仓储。
type UserRepo struct {
	*GenericRepository[entity.User]
}

// NewUserRepo 构建仓储。
func NewUserRepo(db *gorm.DB) *UserRepo {
	return &UserRepo{GenericRepository: New[entity.User](db)}
}

// publicSelect 公共列查询链（排除敏感列）。
func (r *UserRepo) publicSelect(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx).Model(&entity.User{}).Select(PublicUserColumns)
}

// WithSecrets 返回全列查询链（显式加载敏感列，对齐参考 select:false 语义）。
func (r *UserRepo) WithSecrets(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx).Model(&entity.User{})
}

// FindByGuid 公共列查询（payload 场景）。
func (r *UserRepo) FindByGuid(ctx context.Context, guid string) (*entity.User, error) {
	var u entity.User
	err := r.publicSelect(ctx).Where("guid = ?", guid).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByUsernameOrEmail 登录路径：username 或 email 匹配，全列加载
// （含 password/tfaSecret，设计场景 A）。
func (r *UserRepo) FindByUsernameOrEmail(ctx context.Context, ident string) (*entity.User, error) {
	var u entity.User
	err := r.WithSecrets(ctx).Where("username = ? OR email = ?", ident, ident).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByGuidWithSecrets 全列加载（两步登录复核等场景）。
func (r *UserRepo) FindByGuidWithSecrets(ctx context.Context, guid string) (*entity.User, error) {
	var u entity.User
	err := r.WithSecrets(ctx).Where("guid = ?", guid).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByOidcSubject 按 OIDC subject 绑定查找（全列，findOrCreate 场景）。
func (r *UserRepo) FindByOidcSubject(ctx context.Context, subject string) (*entity.User, error) {
	var u entity.User
	err := r.WithSecrets(ctx).Where("oidcSubject = ?", subject).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ProfilePatch 局部更新补丁；nil 表示不更新该字段。
type ProfilePatch struct {
	DisplayName *string
	Email       *string
	Note        *string
}

// UpdateProfile 局部更新资料（updatedAt 由 GORM 维护）。
func (r *UserRepo) UpdateProfile(ctx context.Context, guid string, p ProfilePatch) error {
	updates := map[string]any{}
	if p.DisplayName != nil {
		updates["displayName"] = *p.DisplayName
	}
	if p.Email != nil {
		updates["email"] = *p.Email
	}
	if p.Note != nil {
		updates["note"] = *p.Note
	}
	if len(updates) == 0 {
		return nil
	}
	err := r.db.WithContext(ctx).Model(&entity.User{}).Where("guid = ?", guid).Updates(updates).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// UpdateColumns 通用列更新（avatar / info / tfaSecret / oidcSubject 等场景）。
func (r *UserRepo) UpdateColumns(ctx context.Context, guid string, updates map[string]any) error {
	if len(updates) == 0 {
		return nil
	}
	err := r.db.WithContext(ctx).Model(&entity.User{}).Where("guid = ?", guid).Updates(updates).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}
