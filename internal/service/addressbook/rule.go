// Package addressbook 本文件：AddressBookRuleService——书级写路径
// （custom/shared 建改删 + share-candidates）与共享规则 CRUD
// （参考 rule.service 复刻，固定文案逐字节）。
package addressbook

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// RuleService 书级写路径与共享规则服务。
type RuleService struct {
	db     *gorm.DB
	books  *repository.AddressBookRepo
	rules  *repository.AddressBookRuleRepo
	users  *repository.UserRepo
	groups *repository.UserGroupRepo
	perms  *PermissionService
}

// NewRuleService 构建规则服务。
func NewRuleService(
	db *gorm.DB,
	books *repository.AddressBookRepo,
	rules *repository.AddressBookRuleRepo,
	users *repository.UserRepo,
	groups *repository.UserGroupRepo,
	perms *PermissionService,
) *RuleService {
	return &RuleService{db: db, books: books, rules: rules, users: users, groups: groups, perms: perms}
}

// bookPasswordInfo password → info JSON 串（空串不清除——参考
// Object.assign(undefined) 语义）。
func bookPasswordInfo(password *string) (string, bool) {
	if password == nil || *password == "" {
		return "", false
	}
	return `{"password":` + jsonString(*password) + `}`, true
}

// infoPassword 提取 info.password（create 请求 password 缺省回退）。
func infoPassword(req *api.CreateBookProfileRequest) *string {
	if req.Password != nil {
		return req.Password
	}
	if req.Info != nil && req.Info.Password != nil {
		return req.Info.Password
	}
	return nil
}

// jsonString JSON 字符串字面量编码（info.password 单键落库用）。
func jsonString(s string) string {
	b, err := jsonMarshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// checkProfileName 建书名校验：trim 空 400，重名（owner+非 personal）
// 409；返回 trim 后的名字。
func (s *RuleService) checkProfileName(ctx context.Context, owner, name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", rbac.ErrBadRequest("Address book name cannot be empty")
	}
	if _, err := s.books.FindByName(ctx, owner, trimmed); err == nil {
		return "", rbac.ErrConflictMsg("Address book name already exists")
	} else if !errors.Is(err, repository.ErrNotFound) {
		return "", err
	}
	return trimmed, nil
}

// AddCustom POST /api/ab/custom/add：建自定义书（isShared=0）。
func (s *RuleService) AddCustom(ctx context.Context, userGuid string, req api.CreateBookProfileRequest) (api.AddressBookRef, error) {
	return s.createBookProfile(ctx, userGuid, req, false)
}

// AddShared POST /api/ab/shared/add：建共享书（isShared=1）。
func (s *RuleService) AddShared(ctx context.Context, userGuid string, req api.CreateBookProfileRequest) (api.AddressBookRef, error) {
	return s.createBookProfile(ctx, userGuid, req, true)
}

// createBookProfile 建书公共路径（custom/shared 共用）。
func (s *RuleService) createBookProfile(ctx context.Context, userGuid string, req api.CreateBookProfileRequest, isShared bool) (api.AddressBookRef, error) {
	name, err := s.checkProfileName(ctx, userGuid, req.Name)
	if err != nil {
		return api.AddressBookRef{}, err
	}
	now := timeNow()
	book := &entity.AddressBook{
		Guid:      newGUID(),
		Owner:     userGuid,
		IsShared:  isShared,
		Name:      name,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if note := req.Note; note != nil {
		book.Note = *note
	}
	if info, ok := bookPasswordInfo(infoPassword(&req)); ok {
		book.Info = info
	}
	if err := s.books.Create(ctx, book); err != nil {
		return api.AddressBookRef{}, err
	}
	return api.AddressBookRef{Guid: book.Guid, Name: book.Name}, nil
}

// UpdateCustom PUT /api/ab/custom/update/profile：私有书 profile 更新
// （owner 复核；至少一键否则 400；password 与 info.password 对称合并）。
func (s *RuleService) UpdateCustom(ctx context.Context, userGuid string, req api.UpdateBookProfileRequest) error {
	password := req.Password
	if password == nil && req.Info != nil {
		password = req.Info.Password
	}
	if req.Name == nil && req.Note == nil && password == nil {
		return rbac.ErrBadRequest("At least one field must be updated")
	}
	book, err := s.books.FindCustomOwned(ctx, req.Guid, userGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return rbac.ErrNotFoundErr("Private custom address book does not exist")
		}
		return err
	}
	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			return rbac.ErrBadRequest("Address book name cannot be empty")
		}
		if _, err := s.books.FindByName(ctx, userGuid, trimmed); err == nil {
			return rbac.ErrConflictMsg("Address book name already exists")
		} else if !errors.Is(err, repository.ErrNotFound) {
			return err
		}
		book.Name = trimmed
	}
	if req.Note != nil {
		book.Note = *req.Note
	}
	if info, ok := bookPasswordInfo(password); ok {
		book.Info = info
	}
	book.UpdatedAt = timeNow()
	return s.books.Update(ctx, book)
}

// DeleteCustom DELETE /api/ab/custom：逐条私有书复核（数量不符 404）；
// 事务级联 rules/peers/tags/peer_tags（契约 summary）。
func (s *RuleService) DeleteCustom(ctx context.Context, userGuid string, guids []string) error {
	unique := dedup(guids)
	for _, guid := range unique {
		if _, err := s.books.FindCustomOwned(ctx, guid, userGuid); err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return rbac.ErrNotFoundErr("One or more private custom address books do not exist")
			}
			return err
		}
	}
	return s.books.DeleteByGuids(ctx, unique)
}

// UpdateShared PUT /api/ab/shared/update/profile：共享书更新——
// 改 owner 需 FULL_CONTROL（先给新 owner 授 FULL_CONTROL 规则）；
// 改 name/note/password 需 READ_WRITE；重名 409。
func (s *RuleService) UpdateShared(ctx context.Context, userGuid string, req api.UpdateSharedBookRequest) error {
	book, err := s.books.FindSharedForm(ctx, req.Guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return rbac.ErrNotFoundErr("Address book does not exist")
		}
		return err
	}

	changingOwner := req.Owner != nil && *req.Owner != book.Owner
	required := entity.ShareRuleReadWrite
	if changingOwner {
		required = entity.ShareRuleFullControl
	}
	if _, err := s.perms.CheckAccess(ctx, req.Guid, userGuid, required); err != nil {
		return err
	}

	newOwnerGuid := book.Owner
	if changingOwner {
		newOwner, err := s.users.FindByGuid(ctx, *req.Owner)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return rbac.ErrNotFoundErr("New owner user does not exist")
			}
			return err
		}
		newOwnerGuid = newOwner.Guid

		// 新 owner 无既有 user 维度规则时先授 FULL_CONTROL（参考语义）。
		if _, err := s.rules.FindByBookAndTarget(ctx, req.Guid, &newOwnerGuid, nil); errors.Is(err, repository.ErrNotFound) {
			now := timeNow()
			if err := s.rules.Upsert(ctx, &entity.AddressBookRule{
				Guid:            uuid.New().String(),
				AddressBookGuid: req.Guid,
				TargetUserId:    &newOwnerGuid,
				Rule:            entity.ShareRuleFullControl,
				CreatedAt:       now,
			}); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}

	if req.Name != nil {
		trimmed := strings.TrimSpace(*req.Name)
		if trimmed == "" {
			return rbac.ErrBadRequest("Address book name cannot be empty")
		}
		if _, err := s.books.FindByName(ctx, newOwnerGuid, trimmed); err == nil {
			return rbac.ErrConflictMsg("Address book name already exists")
		} else if !errors.Is(err, repository.ErrNotFound) {
			return err
		}
		book.Name = trimmed
	}
	if req.Note != nil {
		book.Note = *req.Note
	}
	if info, ok := bookPasswordInfo(req.Password); ok {
		book.Info = info
	}
	book.Owner = newOwnerGuid
	book.UpdatedAt = timeNow()
	return s.books.Update(ctx, book)
}

// DeleteShared DELETE /api/ab/shared：逐条 owner 校验（不存在跳过、
// 非 owner 403）；事务删 rules+books（参考语义，peers/tags 留孤儿）。
func (s *RuleService) DeleteShared(ctx context.Context, userGuid string, guids []string) error {
	unique := dedup(guids)
	toDelete := make([]string, 0, len(unique))
	for _, guid := range unique {
		book, err := s.books.FindSharedForm(ctx, guid)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				continue // 不存在跳过（参考语义）。
			}
			return err
		}
		if book.Owner != userGuid {
			return rbac.ErrForbidden("No permission to delete address book '" + book.Name + "'")
		}
		toDelete = append(toDelete, guid)
	}
	if len(toDelete) == 0 {
		return nil
	}
	return s.books.DeleteSharedTx(ctx, toDelete)
}

// ShareCandidates GET /api/ab/shared/{guid}/share-candidates：FULL_CONTROL
// 复核；users（username/displayName LIKE）+ groups（name LIKE）。
func (s *RuleService) ShareCandidates(ctx context.Context, guid, userGuid, name string) (api.ShareCandidates, error) {
	if _, err := s.perms.CheckAccess(ctx, guid, userGuid, entity.ShareRuleFullControl); err != nil {
		return api.ShareCandidates{}, err
	}
	users, err := s.users.ListForShare(ctx, name)
	if err != nil {
		return api.ShareCandidates{}, err
	}
	groups, err := s.groups.ListForShare(ctx, name)
	if err != nil {
		return api.ShareCandidates{}, err
	}
	userRows := make([]struct {
		Guid     string  `json:"guid"`
		Name     *string `json:"name,omitempty"`
		Username string  `json:"username"`
	}, 0, len(users))
	for _, u := range users {
		display := u.DisplayName
		if display == "" {
			display = u.Username
		}
		userRows = append(userRows, struct {
			Guid     string  `json:"guid"`
			Name     *string `json:"name,omitempty"`
			Username string  `json:"username"`
		}{Guid: u.Guid, Name: &display, Username: u.Username})
	}
	groupRows := make([]struct {
		Guid string `json:"guid"`
		Name string `json:"name"`
	}, 0, len(groups))
	for _, g := range groups {
		groupRows = append(groupRows, struct {
			Guid string `json:"guid"`
			Name string `json:"name"`
		}{Guid: g.Guid, Name: g.Name})
	}
	return api.ShareCandidates{Users: userRows, Groups: groupRows}, nil
}

// ListRules GET /api/ab/rules：ab 缺省=我的全部可见书；提供=READ 复核
// 后单书规则。行形 AbRule（toResponseFormat 的 spec 规范化）。
func (s *RuleService) ListRules(ctx context.Context, userGuid, ab string) (api.AbRuleList, error) {
	var rows []entity.AddressBookRule
	if ab == "" {
		groups, err := s.perms.GroupGuidsOf(ctx, userGuid)
		if err != nil {
			return api.AbRuleList{}, err
		}
		books, _, err := s.books.ListAccessible(ctx, userGuid, groups, repository.AddressBookFilter{})
		if err != nil {
			return api.AbRuleList{}, err
		}
		guids := make([]string, 0, len(books))
		for _, b := range books {
			guids = append(guids, b.Guid)
		}
		rows, err = s.rules.ListByBooks(ctx, guids)
		if err != nil {
			return api.AbRuleList{}, err
		}
	} else {
		if _, err := s.perms.CheckAccess(ctx, ab, userGuid, entity.ShareRuleRead); err != nil {
			return api.AbRuleList{}, err
		}
		found, err := s.rules.ListByBooks(ctx, []string{ab})
		if err != nil {
			return api.AbRuleList{}, err
		}
		rows = found
	}
	data := make([]api.AbRule, 0, len(rows))
	for _, r := range rows {
		data = append(data, api.AbRule{
			Guid:            r.Guid,
			AddressBookGuid: r.AddressBookGuid,
			TargetUserId:    r.TargetUserId,
			TargetGroupId:   r.TargetGroupId,
			Rule:            api.AbRuleRule(r.Rule),
		})
	}
	return api.AbRuleList{Data: data}, nil
}

// CreateRule POST /api/ab/rule：FULL_CONTROL 复核；user/group 互斥
// 409；目标 404；重复 409 'This rule already exists'。返回规则行。
func (s *RuleService) CreateRule(ctx context.Context, userGuid string, req api.AbRuleUpsertRequest) (api.AbRule, error) {
	if _, err := s.perms.CheckAccess(ctx, req.Guid, userGuid, entity.ShareRuleFullControl); err != nil {
		return api.AbRule{}, err
	}
	if req.User != nil && req.Group != nil {
		return api.AbRule{}, rbac.ErrConflictMsg("User and group cannot both be specified")
	}

	var targetUser, targetGroup *string
	if req.User != nil && *req.User != "" {
		guid, err := s.resolveUser(ctx, *req.User)
		if err != nil {
			return api.AbRule{}, err
		}
		targetUser = &guid
	}
	if req.Group != nil && *req.Group != "" {
		g, err := s.groups.FindByID(ctx, *req.Group)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return api.AbRule{}, rbac.ErrNotFoundErr("User group does not exist")
			}
			return api.AbRule{}, err
		}
		targetGroup = &g.Guid
	}

	if _, err := s.rules.FindByBookAndTarget(ctx, req.Guid, targetUser, targetGroup); err == nil {
		return api.AbRule{}, rbac.ErrConflictMsg("This rule already exists")
	} else if !errors.Is(err, repository.ErrNotFound) {
		return api.AbRule{}, err
	}

	rule := req.Rule
	if rule == 0 {
		rule = api.AbRuleUpsertRequestRule(entity.ShareRuleRead)
	}
	row := &entity.AddressBookRule{
		Guid:            uuid.New().String(),
		AddressBookGuid: req.Guid,
		TargetUserId:    targetUser,
		TargetGroupId:   targetGroup,
		Rule:            int(rule),
		CreatedAt:       timeNow(),
	}
	if err := s.rules.Upsert(ctx, row); err != nil {
		return api.AbRule{}, err
	}
	return api.AbRule{
		Guid:            row.Guid,
		AddressBookGuid: row.AddressBookGuid,
		TargetUserId:    row.TargetUserId,
		TargetGroupId:   row.TargetGroupId,
		Rule:            api.AbRuleRule(row.Rule),
	}, nil
}

// resolveUser 规则目标用户解析：uuid 形态按 guid，否则按 username
// （参考 isUUID 分支复刻）；不存在 404 'User does not exist'。
func (s *RuleService) resolveUser(ctx context.Context, ident string) (string, error) {
	if _, err := uuid.Parse(ident); err == nil {
		u, err := s.users.FindByGuid(ctx, ident)
		if err == nil {
			return u.Guid, nil
		}
		if !errors.Is(err, repository.ErrNotFound) {
			return "", err
		}
		return "", rbac.ErrNotFoundErr("User does not exist")
	}
	u, err := s.users.FindByUsernameOrEmail(ctx, ident)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", rbac.ErrNotFoundErr("User does not exist")
		}
		return "", err
	}
	return u.Guid, nil
}

// UpdateRule PATCH /api/ab/rule：规则存在 404 'Rule does not exist' +
// FULL_CONTROL 复核；响应 'Updated successfully'。
func (s *RuleService) UpdateRule(ctx context.Context, userGuid string, req api.AbRuleUpdateRequest) error {
	rule, err := s.rules.FindByID(ctx, req.Guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return rbac.ErrNotFoundErr("Rule does not exist")
		}
		return err
	}
	if _, err := s.perms.CheckAccess(ctx, rule.AddressBookGuid, userGuid, entity.ShareRuleFullControl); err != nil {
		return err
	}
	rule.Rule = int(req.Rule)
	return s.rules.Update(ctx, rule)
}

// DeleteRules DELETE /api/ab/rules：空/非法 guid 400；缺行 404
// 'No rules found'；逐条 FULL_CONTROL 复核。
func (s *RuleService) DeleteRules(ctx context.Context, userGuid string, guids []string) error {
	if len(guids) == 0 {
		return rbac.ErrBadRequest("At least one rule GUID is required")
	}
	unique := dedup(guids)
	for _, g := range unique {
		if _, err := uuid.Parse(g); err != nil {
			return rbac.ErrBadRequest("Invalid rule GUID format: " + g)
		}
	}
	rows := make([]entity.AddressBookRule, 0, len(unique))
	for _, g := range unique {
		rule, err := s.rules.FindByID(ctx, g)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				return rbac.ErrNotFoundErr("No rules found")
			}
			return err
		}
		rows = append(rows, *rule)
	}
	for _, rule := range rows {
		if _, err := s.perms.CheckAccess(ctx, rule.AddressBookGuid, userGuid, entity.ShareRuleFullControl); err != nil {
			return err
		}
	}
	return s.rules.DeleteByGuids(ctx, unique)
}

// dedup 保序去重（参考 [...new Set(guids)] 语义）。
func dedup(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
