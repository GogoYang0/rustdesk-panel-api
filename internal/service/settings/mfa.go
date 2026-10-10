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
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
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
	// users/groups 强制前置校验依赖（v0.2.1：开启 enforceGlobal 或
	// 新增强制组时检查未绑定 2FA 用户；nil 时跳过校验——单测兼容）。
	users  *repository.UserRepo
	groups *repository.UserGroupRepo
}

// NewMfaService 构建服务。
func NewMfaService(store *Store) *MfaService {
	return &MfaService{store: store}
}

// WithRepos 注入强制前置校验仓储（bootstrap 装配；users/groups 任一
// 为 nil 时该路径校验静默跳过）。
func (s *MfaService) WithRepos(users *repository.UserRepo, groups *repository.UserGroupRepo) *MfaService {
	s.users = users
	s.groups = groups
	return s
}

// MfaConflictUser 强制前置校验冲突名单行。
type MfaConflictUser struct {
	Guid         string
	Username     string
	DisplayName  string
	UserGroupName string
}

// EnforcementConflictError 强制 MFA 策略更新被拒（400 + 未绑定名单）。
type EnforcementConflictError struct {
	Users []MfaConflictUser
}

// Error 实现 error 接口（固定文案，契约 message）。
func (e *EnforcementConflictError) Error() string {
	return "MFA enforcement blocked: users without 2FA found"
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
//
// v0.2.1 强制前置校验：开启 enforceGlobal 或新增组级强制前，检查目标
// 用户中是否存在未绑定 TOTP 且未开启 passkey-2FA 的用户，存在则
// 400 拒绝（EnforcementConflictError，handler 输出未绑定名单）。
func (s *MfaService) Update(ctx context.Context, req dto.UpdateMfaSettings) (dto.MfaSettings, error) {
	if err := s.checkConflicts(ctx, req); err != nil {
		return dto.MfaSettings{}, err
	}
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

// checkConflicts 强制前置校验（未注入仓储时跳过；仓储查询失败原样
// 上抛——校验路径不可静默降级）。
func (s *MfaService) checkConflicts(ctx context.Context, req dto.UpdateMfaSettings) error {
	if s.users == nil {
		return nil
	}
	current, err := s.Get(ctx)
	if err != nil {
		return err
	}
	// 命中范围：全局新开启 → 全量用户；新增组 → 组内用户。
	checkAll := req.EnforceGlobal && !current.EnforceGlobal
	newGuids := make([]string, 0)
	if req.UserGroupGuids != nil {
		had := make(map[string]struct{}, len(current.UserGroupGuids))
		for _, g := range current.UserGroupGuids {
			had[g] = struct{}{}
		}
		for _, g := range *req.UserGroupGuids {
			if _, ok := had[g]; !ok {
				newGuids = append(newGuids, g)
			}
		}
	}
	if !checkAll && len(newGuids) == 0 {
		return nil
	}
	all, err := s.users.ListAllWithSecrets(ctx)
	if err != nil {
		return err
	}
	inScope := func(u entity.User) bool {
		if checkAll {
			return true
		}
		group := ""
		if u.UserGroupGuid != nil {
			group = *u.UserGroupGuid
		}
		for _, g := range newGuids {
			if group == g {
				return true
			}
		}
		return false
	}
	conflicts := make([]MfaConflictUser, 0)
	// 组名标注（仅组级命中路径需要；全局路径组名为空串）。
	groupNames := make(map[string]string)
	if len(newGuids) > 0 && s.groups != nil {
		groupNames, err = s.groups.NameMapByGuids(ctx, newGuids)
		if err != nil {
			return err
		}
	}
	for i := range all {
		u := &all[i]
		if !inScope(*u) {
			continue
		}
		if u.TfaEnabled() || u.ParseUserInfo().PasskeyTfaEnabled() {
			continue
		}
		groupGuid := ""
		if u.UserGroupGuid != nil {
			groupGuid = *u.UserGroupGuid
		}
		conflicts = append(conflicts, MfaConflictUser{
			Guid: u.Guid, Username: u.Username,
			DisplayName: u.DisplayName,
			UserGroupName: groupNames[groupGuid],
		})
	}
	if len(conflicts) > 0 {
		return &EnforcementConflictError{Users: conflicts}
	}
	return nil
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
