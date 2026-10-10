// Package addressbook 通讯录域服务族（M3 T05，事实⑦）。
// 服务分工（类图）：AddressBookService（本文件 BookService：settings/
// personal/profiles 列表/access）+ AddressBookRuleService（rule.go）+
// LegacyService（legacy.go）+ 设备/标签子服务（peer.go/tag.go）。
// 权限判定统一收敛于 PermissionService（permission.go）。
package addressbook

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// jsonMarshal JSON 编码包装（info.password 落库用）。
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// timeNow 应用层时钟（统一包装点）。
func timeNow() time.Time { return time.Now() }

// newGUID 应用层 uuid v4（GUID 由服务层生成，共享知识 9）。
func newGUID() string { return uuid.New().String() }

// pageOr 指针页码缺省（nil→def；非法值 handler 已拦截）。
func pageOr(v *int, def int) int {
	if v == nil || *v < 1 {
		return def
	}
	return *v
}

// pageSizeOr 指针页大小（nil→def；0 = 不分页）。
func pageSizeOr(v *int, def int) int {
	if v == nil {
		return def
	}
	return *v
}

// strPtrOrNull 空串→nil（可选字符串列输出语义）。
func strPtrOrNull(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// usernamesByGuids 批量解析 guid→username（SharedBookRow.owner 列）。
func usernamesByGuids(ctx context.Context, users *repository.UserRepo, guids []string) (map[string]string, error) {
	out := make(map[string]string, len(guids))
	if len(guids) == 0 {
		return out, nil
	}
	rows, err := users.FindByGuids(ctx, guids)
	if err != nil {
		return nil, err
	}
	for _, u := range rows {
		out[u.Guid] = u.Username
	}
	return out, nil
}

// maxRuleOf 行级等效档位：owner → FULL_CONTROL；否则规则并集原值。
func maxRuleOf(isOwner bool, effectiveRule int) int {
	if isOwner {
		return entityShareRuleFullControl
	}
	return effectiveRule
}

// BookService 通讯录核心服务（settings/personal/profiles/access）。
type BookService struct {
	books  *repository.AddressBookRepo
	rules  *repository.AddressBookRuleRepo
	users  *repository.UserRepo
	perms  *PermissionService
	legacy *LegacyService
}

// NewBookService 构建核心服务。
func NewBookService(
	books *repository.AddressBookRepo,
	rules *repository.AddressBookRuleRepo,
	users *repository.UserRepo,
	perms *PermissionService,
	legacy *LegacyService,
) *BookService {
	return &BookService{books: books, rules: rules, users: users, perms: perms, legacy: legacy}
}

// usernameOf 单用户 guid→username（custom 行 owner 列）。
func (s *BookService) usernameOf(ctx context.Context, guid string) (string, error) {
	names, err := usernamesByGuids(ctx, s.users, []string{guid})
	if err != nil {
		return "", err
	}
	return names[guid], nil
}

// ownerNames 行集 owner guid→username 批量解析。
func (s *BookService) ownerNames(ctx context.Context, rows []repository.AddressBookWithRule) (map[string]string, error) {
	guids := make([]string, 0, len(rows))
	for _, row := range rows {
		guids = append(guids, row.Owner)
	}
	return usernamesByGuids(ctx, s.users, guids)
}

// SharedAccess 404/403 语义错误（文案即 HTTP 响应 message，
// handler 侧 writeAuditError 统一映射）。
var (
	ErrNotFoundShared  = rbac.ErrNotFoundErr("Shared address book does not exist")
	ErrForbiddenAccess = rbac.ErrForbidden("No permission to access this address book")
)

// entityShareRuleFullControl FULL_CONTROL 档位值（避免服务层直接
// 依赖 entity 的重复 import 噪音，实体常量同步）。
const entityShareRuleFullControl = 3
