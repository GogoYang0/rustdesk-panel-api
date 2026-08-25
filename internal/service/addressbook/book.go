// Package addressbook 本文件：AddressBookService——通讯录核心协调
// （settings 占位 / personal 幂等 / custom·shared profiles 列表 /
// peers·tags 委托入口；书级写路径在 RuleService，事实⑦类图分工）。
package addressbook

import (
	"context"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// AbSettings 兼容占位（怪癖三件套之三：恒 max_peer_one_ab=0）。
func (s *BookService) Settings() api.AbSettings {
	return api.AbSettings{MaxPeerOneAb: api.AbSettingsMaxPeerOneAbN0}
}

// Personal GET/POST /api/ab/personal：幂等取/建个人书，返回
// {guid, name}（AddressBookRef）。
func (s *BookService) Personal(ctx context.Context, userGuid string) (api.AddressBookRef, error) {
	book, err := s.legacy.EnsurePersonal(ctx, userGuid)
	if err != nil {
		return api.AddressBookRef{}, err
	}
	return api.AddressBookRef{Guid: book.Guid, Name: book.Name}, nil
}

// CustomProfiles GET /api/ab/custom/profiles：owner=我 AND isPersonal=0
// AND isShared=0 AND NOT(EXTERNAL_GRANT_EXISTS)；行形 SharedBookRow
// （owner=自己、rule=FULL_CONTROL、is_owner）。
func (s *BookService) CustomProfiles(ctx context.Context, userGuid string, q dto.BookListQuery) (api.SharedBookPage, error) {
	rows, total, err := s.books.ListAccessible(ctx, userGuid, nil, repository.AddressBookFilter{
		Name:            q.Name,
		Note:            q.Note,
		Current:         pageOr(q.Current, 1),
		PageSize:        pageSizeOr(q.PageSize, 0),
		ExcludePersonal: true,
	})
	if err != nil {
		return api.SharedBookPage{}, err
	}

	// custom 过滤：owner=我 + isShared=0 + 无外部授权（内存过滤——
	// custom 定义为 owner 私域子集，行数有限；owner 恒真由用户名
	// 反查兜底校验）。
	username, err := s.usernameOf(ctx, userGuid)
	if err != nil {
		return api.SharedBookPage{}, err
	}
	data := make([]api.SharedBookRow, 0, len(rows))
	for _, row := range rows {
		if row.Owner != userGuid || row.IsShared {
			continue
		}
		granted, err := s.books.ExistsExternalGrant(ctx, row.Guid)
		if err != nil {
			return api.SharedBookPage{}, err
		}
		if granted {
			continue
		}
		isOwner := true
		data = append(data, api.SharedBookRow{
			Guid:    row.Guid,
			Name:    row.Name,
			Owner:   username,
			Note:    strPtrOrNull(row.Note),
			Rule:    api.SharedBookRowRule(entity.ShareRuleFullControl),
			IsOwner: &isOwner,
		})
	}
	return api.SharedBookPage{Data: data, Total: int(total)}, nil
}

// SharedProfiles GET/POST /api/ab/shared/profiles：isPersonal=0 且
// （owner=我 ∪ 规则可见）；行 rule=MAX(owner→3, 并集)；含 info 串。
func (s *BookService) SharedProfiles(ctx context.Context, userGuid string, q dto.BookListQuery) (api.SharedBookPage, error) {
	groups, err := s.perms.GroupGuidsOf(ctx, userGuid)
	if err != nil {
		return api.SharedBookPage{}, err
	}
	rows, total, err := s.books.ListAccessible(ctx, userGuid, groups, repository.AddressBookFilter{
		Name:            q.Name,
		Note:            q.Note,
		Current:         pageOr(q.Current, 1),
		PageSize:        pageSizeOr(q.PageSize, 0),
		ExcludePersonal: true,
	})
	if err != nil {
		return api.SharedBookPage{}, err
	}
	names, err := s.ownerNames(ctx, rows)
	if err != nil {
		return api.SharedBookPage{}, err
	}
	data := make([]api.SharedBookRow, 0, len(rows))
	for _, row := range rows {
		isOwner := row.Owner == userGuid
		data = append(data, api.SharedBookRow{
			Guid:    row.Guid,
			Name:    row.Name,
			Owner:   names[row.Owner],
			Note:    strPtrOrNull(row.Note),
			Rule:    api.SharedBookRowRule(maxRuleOf(isOwner, row.EffectiveRule)),
			Info:    strPtrOrNull(row.Info),
			IsOwner: nil, // shared/profiles 行不带 is_owner（参考形态）。
		})
	}
	return api.SharedBookPage{Data: data, Total: int(total)}, nil
}

// SharedList GET /api/ab/shared/list：sharedOnly 形态（isShared=1 OR
// EXTERNAL_GRANT_EXISTS），无分页；行含 is_owner 不含 info。
func (s *BookService) SharedList(ctx context.Context, userGuid string) (api.SharedBookList, error) {
	groups, err := s.perms.GroupGuidsOf(ctx, userGuid)
	if err != nil {
		return api.SharedBookList{}, err
	}
	rows, _, err := s.books.ListAccessible(ctx, userGuid, groups, repository.AddressBookFilter{
		ExcludePersonal: true,
		SharedOnly:      true,
	})
	if err != nil {
		return api.SharedBookList{}, err
	}
	names, err := s.ownerNames(ctx, rows)
	if err != nil {
		return api.SharedBookList{}, err
	}
	data := make([]api.SharedBookRow, 0, len(rows))
	for _, row := range rows {
		isOwner := row.Owner == userGuid
		data = append(data, api.SharedBookRow{
			Guid:    row.Guid,
			Name:    row.Name,
			Owner:   names[row.Owner],
			Note:    strPtrOrNull(row.Note),
			Rule:    api.SharedBookRowRule(maxRuleOf(isOwner, row.EffectiveRule)),
			IsOwner: &isOwner,
		})
	}
	return api.SharedBookList{Data: data}, nil
}

// SharedAccess GET /api/ab/shared/{guid}/access：单书访问视图（规则
// 并集判定）；书不存在或非共享形态 404，无权 403。
func (s *BookService) SharedAccess(ctx context.Context, guid, userGuid string) (api.SharedBookRow, error) {
	book, err := s.books.FindSharedForm(ctx, guid)
	if err != nil {
		if err == repository.ErrNotFound {
			return api.SharedBookRow{}, ErrNotFoundShared
		}
		return api.SharedBookRow{}, err
	}
	groups, err := s.perms.GroupGuidsOf(ctx, userGuid)
	if err != nil {
		return api.SharedBookRow{}, err
	}
	maxRule, err := s.rules.MaxRuleForUser(ctx, guid, userGuid, groups)
	if err != nil {
		return api.SharedBookRow{}, err
	}
	isOwner := book.Owner == userGuid
	if !isOwner && maxRule == 0 {
		return api.SharedBookRow{}, ErrForbiddenAccess
	}
	names, err := s.ownerNames(ctx, []repository.AddressBookWithRule{{
		AddressBook: *book, EffectiveRule: maxRule,
	}})
	if err != nil {
		return api.SharedBookRow{}, err
	}
	return api.SharedBookRow{
		Guid:    book.Guid,
		Name:    book.Name,
		Owner:   names[book.Owner],
		Note:    strPtrOrNull(book.Note),
		Rule:    api.SharedBookRowRule(maxRuleOf(isOwner, maxRule)),
		IsOwner: &isOwner,
	}, nil
}
