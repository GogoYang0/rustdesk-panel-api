// Package settings 本文件：mfa.* 键目录与强制 MFA 策略读写
// （GAP2 设计 §3.1，共享知识 G4）。
//
// 2 键：mfa.enforceGlobal（系统级强制）/ mfa.enforceUserGroupGuids
// （组级强制，换行列表）。category=mfa；端点 /api/settings/mfa 为
// AdminGuard 管理员档（OQ-5，与 general/smtp/ldap 一致，不新增权限码）。
// 判定语义：MfaEnforced(user) = enforceGlobal || user.userGroupGuid ∈
// enforceUserGroupGuids；owner/isAdmin 不豁免（OQ-2）。
package settings

import (
	"context"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
)

// mfa.* 键目录（共享知识 G4）。
const (
	KeyMfaEnforceGlobal        = "mfa.enforceGlobal"
	KeyMfaEnforceUserGroupGuid = "mfa.enforceUserGroupGuids"
)

// mfaCategory system_settings.category 归段。
const mfaCategory = "mfa"

// MfaService mfa.* 设置读写与强制判定。
type MfaService struct {
	store *Store
}

// NewMfaService 构建服务。
func NewMfaService(store *Store) *MfaService {
	return &MfaService{store: store}
}

// Get 组装策略视图（库值缺失逐键回退缺省：双关不强制）。
func (s *MfaService) Get(ctx context.Context) (dto.MfaSettings, error) {
	enforce, err := s.store.GetBool(ctx, KeyMfaEnforceGlobal, false)
	if err != nil {
		return dto.MfaSettings{}, err
	}
	guids, err := s.store.GetStringList(ctx, KeyMfaEnforceUserGroupGuid, []string{})
	if err != nil {
		return dto.MfaSettings{}, err
	}
	if guids == nil {
		guids = []string{}
	}
	return dto.MfaSettings{EnforceGlobal: enforce, UserGroupGuids: guids}, nil
}

// Update 写入策略（enforceGlobal 必填；userGroupGuids 可选，nil 不更新），
// 返回更新后视图。
func (s *MfaService) Update(ctx context.Context, req dto.UpdateMfaSettings) (dto.MfaSettings, error) {
	if err := s.store.SetBool(ctx, KeyMfaEnforceGlobal, req.EnforceGlobal, mfaCategory); err != nil {
		return dto.MfaSettings{}, err
	}
	if req.UserGroupGuids != nil {
		if err := s.store.SetStringList(ctx, KeyMfaEnforceUserGroupGuid, *req.UserGroupGuids, mfaCategory); err != nil {
			return dto.MfaSettings{}, err
		}
	}
	return s.Get(ctx)
}

// Enforced 强制判定（GAP2 设计 §3.1）：enforceGlobal 或用户所属
// userGroupGuid 命中 enforceUserGroupGuids。「已有 2FA」判定（TOTP 或
// passkey-2FA）由调用方（auth 域）完成——本方法只回答策略侧。
func (s *MfaService) Enforced(ctx context.Context, userGroupGuid string) (bool, error) {
	enforce, err := s.store.GetBool(ctx, KeyMfaEnforceGlobal, false)
	if err != nil || enforce {
		return enforce, err
	}
	if userGroupGuid == "" {
		return false, nil
	}
	guids, err := s.store.GetStringList(ctx, KeyMfaEnforceUserGroupGuid, []string{})
	if err != nil {
		return false, err
	}
	for _, g := range guids {
		if g == userGroupGuid {
			return true, nil
		}
	}
	return false, nil
}
