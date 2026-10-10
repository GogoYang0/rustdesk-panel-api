// Package addressbook 通讯录域服务（M3 T05，事实⑦）。
// 本文件：AddressBookPermissionService——访问权限判定（owner 全权 ∪
// 规则并集取最大；EXTERNAL_GRANT_EXISTS 的服务侧配套）。
package addressbook

import (
	"context"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// requiredRuleName 档位中文名（403 文案组装，参考复刻）。
func requiredRuleName(required int) string {
	switch required {
	case entity.ShareRuleReadWrite:
		return "Read-write"
	case entity.ShareRuleFullControl:
		return "Full control"
	default:
		return "Read"
	}
}

// PermissionService 通讯录访问权限服务。
type PermissionService struct {
	books *repository.AddressBookRepo
	rules *repository.AddressBookRuleRepo
	users *repository.UserRepo
}

// NewPermissionService 构建权限服务。
func NewPermissionService(
	books *repository.AddressBookRepo,
	rules *repository.AddressBookRuleRepo,
	users *repository.UserRepo,
) *PermissionService {
	return &PermissionService{books: books, rules: rules, users: users}
}

// CheckAccess 访问复核（参考复刻）：书 404 'Address book does not
// exist'；owner 全权直通；非 owner 取「targetUserId=我 ∪ 双空=
// everyone ∪ targetGroupId∈我所在组」规则并集最大值——0 → 403
// 'No permission to access this address book'，低于 required →
// 403 '{Read-write|Full control} permission required'。
func (s *PermissionService) CheckAccess(ctx context.Context, bookGuid, userGuid string, required int) (*entity.AddressBook, error) {
	book, err := s.books.FindByID(ctx, bookGuid)
	if err != nil {
		if err == repository.ErrNotFound {
			return nil, rbac.ErrNotFoundErr("Address book does not exist")
		}
		return nil, err
	}
	if book.Owner == userGuid {
		return book, nil
	}

	maxRule, err := s.MaxRule(ctx, bookGuid, userGuid)
	if err != nil {
		return nil, err
	}
	if maxRule == 0 {
		return nil, rbac.ErrForbidden("No permission to access this address book")
	}
	if maxRule < required {
		return nil, rbac.ErrForbidden(requiredRuleName(required) + " permission required")
	}
	return book, nil
}

// MaxRule 当前用户对书的等效档位：owner → FULL_CONTROL；非 owner →
// 命中规则并集最大值（无命中 0）。
func (s *PermissionService) MaxRule(ctx context.Context, bookGuid, userGuid string) (int, error) {
	book, err := s.books.FindByID(ctx, bookGuid)
	if err != nil {
		if err == repository.ErrNotFound {
			return 0, rbac.ErrNotFoundErr("Address book does not exist")
		}
		return 0, err
	}
	if book.Owner == userGuid {
		return entity.ShareRuleFullControl, nil
	}
	user, err := s.users.FindByGuid(ctx, userGuid)
	if err != nil {
		// 用户不存在：无组归属，仅 everyone/user 两路规则可命中。
		if err == repository.ErrNotFound {
			return s.rules.MaxRuleForUser(ctx, bookGuid, userGuid, nil)
		}
		return 0, err
	}
	groupGuids := make([]string, 0, 1)
	if user.UserGroupGuid != nil && *user.UserGroupGuid != "" {
		groupGuids = append(groupGuids, *user.UserGroupGuid)
	}
	return s.rules.MaxRuleForUser(ctx, bookGuid, userGuid, groupGuids)
}

// GroupGuidsOf 用户的组归属（并集判定的 targetGroupId 集合）。
func (s *PermissionService) GroupGuidsOf(ctx context.Context, userGuid string) ([]string, error) {
	user, err := s.users.FindByGuid(ctx, userGuid)
	if err != nil {
		if err == repository.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	if user.UserGroupGuid == nil || *user.UserGroupGuid == "" {
		return nil, nil
	}
	return []string{*user.UserGroupGuid}, nil
}
