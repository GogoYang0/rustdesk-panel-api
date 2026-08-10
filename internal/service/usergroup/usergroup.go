// Package usergroup 用户组域服务（设计 §3.1 UserGroupService）：组
// CRUD（重名 409、默认组保护、删除成员回落默认组）、成员查询、成员
// 移动（AssertUsersMutation 复用）。
package usergroup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// 业务文案（共享知识 1 固定文案逐字节；msgDefaultGroupUndeletable 为
// 未锁定文案，契约测试同源锁定）。
const (
	msgGroupNotFound  = "User group does not exist"
	msgGroupNameExist = "User group name already exists" // 409
	msgDefaultGroup   = "Default user group cannot be deleted"
	deletedRulesZero  = int64(0) // M2 无 address_book_rules（M3 域）
)

// Service 用户组域服务。
type Service struct {
	authz  *rbac.AuthorizationService
	db     gormDB
	groups *repository.UserGroupRepo
	users  *repository.UserRepo
	now    func() time.Time // 注入时钟（单测可控）
}

// gormDB 是事务编排所需的最小接口（*gorm.DB 满足）。
type gormDB interface {
	WithContext(ctx context.Context) *gorm.DB
}

// NewService 构建服务。
func NewService(
	authz *rbac.AuthorizationService,
	db *gorm.DB,
	groups *repository.UserGroupRepo,
	users *repository.UserRepo,
) *Service {
	return &Service{authz: authz, db: db, groups: groups, users: users, now: time.Now}
}

// List GET /api/user-groups：name LIKE、normalizedName ASC + guid ASC
// 决胜排序；user_count 批量计数防行级 N+1。
func (s *Service) List(ctx context.Context, q dto.UserGroupListQuery) (dto.UserGroupPage, error) {
	rows, total, err := s.groups.ListPaged(ctx, q.Name, repository.Query{
		Limit:  q.PageSize,
		Offset: pageOffset(q.Current, q.PageSize),
	})
	if err != nil {
		return dto.UserGroupPage{}, fmt.Errorf("usergroup: list: %w", err)
	}
	counts, err := s.users.CountByGroups(ctx, guidsOf(rows))
	if err != nil {
		return dto.UserGroupPage{}, fmt.Errorf("usergroup: counts: %w", err)
	}
	data := make([]dto.UserGroupView, 0, len(rows))
	for i := range rows {
		g := rows[i]
		data = append(data, dto.UserGroupView{
			Guid:      g.Guid,
			Name:      g.Name,
			Note:      g.Note,
			IsDefault: g.IsDefault,
			UserCount: counts[g.Guid],
		})
	}
	return dto.UserGroupPage{Data: data, Total: total}, nil
}

// Create POST /api/user-groups：重名 409；normalizedName 维护为大写
// 规范化形式（重名比对列）。
func (s *Service) Create(ctx context.Context, req dto.UserGroupUpsertRequest) (dto.UserGroupView, error) {
	if err := s.assertNameFree(ctx, req.Name, ""); err != nil {
		return dto.UserGroupView{}, err
	}
	note := ""
	if req.Note != nil {
		note = *req.Note
	}
	g := &entity.UserGroup{
		Guid:           uuid.NewString(),
		Name:           req.Name,
		NormalizedName: strings.ToUpper(req.Name),
		Note:           note,
	}
	if err := s.groups.Create(ctx, g); err != nil {
		return dto.UserGroupView{}, fmt.Errorf("usergroup: create: %w", err)
	}
	return s.view(ctx, *g), nil
}

// Update PUT /api/user-groups/{guid}：404 + 重名 409（排除自身）；
// note 三态（nil=保持原值，提供即覆盖）。
func (s *Service) Update(ctx context.Context, guid string, req dto.UserGroupUpsertRequest) (dto.UserGroupView, error) {
	g, err := s.groups.FindByID(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.UserGroupView{}, rbac.ErrNotFoundErr(msgGroupNotFound)
		}
		return dto.UserGroupView{}, err
	}
	if err := s.assertNameFree(ctx, req.Name, g.Name); err != nil {
		return dto.UserGroupView{}, err
	}
	g.Name = req.Name
	g.NormalizedName = strings.ToUpper(req.Name)
	if req.Note != nil {
		g.Note = *req.Note
	}
	if err := s.groups.Update(ctx, g); err != nil {
		return dto.UserGroupView{}, fmt.Errorf("usergroup: update: %w", err)
	}
	return s.view(ctx, *g), nil
}

// Delete DELETE /api/user-groups/{guid}：404；默认组禁删 400；事务内
// 成员回落默认组（moved_user_count）+ 删组；deleted_rule_count 恒 0。
func (s *Service) Delete(ctx context.Context, guid string) (dto.DeleteUserGroupResult, error) {
	g, err := s.groups.FindByID(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.DeleteUserGroupResult{}, rbac.ErrNotFoundErr(msgGroupNotFound)
		}
		return dto.DeleteUserGroupResult{}, err
	}
	if g.IsDefault {
		return dto.DeleteUserGroupResult{}, rbac.ErrBadRequest(msgDefaultGroup)
	}
	// 回落目标组：默认组缺失时置 NULL（防御分支，seed 保证存在）。
	fallback := ""
	if def, err := s.groups.FindDefault(ctx); err == nil {
		fallback = def.Guid
	}
	var moved int64
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		n, err := s.users.DetachMembersTx(tx, guid, fallback)
		if err != nil {
			return err
		}
		moved = n
		return s.groups.DeleteTx(tx, guid)
	})
	if err != nil {
		return dto.DeleteUserGroupResult{}, fmt.Errorf("usergroup: delete: %w", err)
	}
	return dto.DeleteUserGroupResult{MovedUserCount: moved, DeletedRuleCount: deletedRulesZero}, nil
}

// Members GET /api/user-groups/{guid}/users：search LIKE 匹配
// username/email，分页 username ASC。
func (s *Service) Members(ctx context.Context, guid string, q dto.MemberListQuery) (dto.MemberPage, error) {
	if _, err := s.groups.FindByID(ctx, guid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.MemberPage{}, rbac.ErrNotFoundErr(msgGroupNotFound)
		}
		return dto.MemberPage{}, err
	}
	rows, total, err := s.users.ListByGroup(ctx, guid, q.Search, q.Current, q.PageSize)
	if err != nil {
		return dto.MemberPage{}, fmt.Errorf("usergroup: members: %w", err)
	}
	data := make([]dto.MemberView, 0, len(rows))
	for i := range rows {
		u := rows[i]
		data = append(data, dto.MemberView{
			Guid:        u.Guid,
			Username:    u.Username,
			DisplayName: u.DisplayName,
			Email:       u.Email,
		})
	}
	return dto.MemberPage{Data: data, Total: total}, nil
}

// MoveUsers POST /api/user-groups/{guid}/users：组存在 404 →
// AssertUsersMutation（批量 404 / 保护账号 403）→ 批量移入；
// moved_user_count = 实际移动数。
func (s *Service) MoveUsers(ctx context.Context, actorGuid, guid string, req dto.MoveUsersRequest) (dto.MoveUsersResult, error) {
	if _, err := s.groups.FindByID(ctx, guid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return dto.MoveUsersResult{}, rbac.ErrNotFoundErr(msgGroupNotFound)
		}
		return dto.MoveUsersResult{}, err
	}
	guids := dedup(req.UserGuids)
	if err := s.authz.AssertUsersMutation(ctx, actorGuid, guids, rbac.CodeUserGroupsMembership); err != nil {
		return dto.MoveUsersResult{}, err
	}
	moved, err := s.users.MoveToGroup(ctx, guids, guid)
	if err != nil {
		return dto.MoveUsersResult{}, fmt.Errorf("usergroup: move: %w", err)
	}
	return dto.MoveUsersResult{MovedUserCount: moved}, nil
}

// ==================== 内部辅助 ====================

// assertNameFree 重名 409 判定（大小写不敏感，比 normalizedName）；
// exclude 为自身现名（改名保持原值不算冲突）。
func (s *Service) assertNameFree(ctx context.Context, name, exclude string) error {
	existing, err := s.groups.FindByNameCI(ctx, name)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil
		}
		return err
	}
	if exclude != "" && existing.Name == exclude {
		return nil
	}
	return rbac.ErrConflictMsg(msgGroupNameExist)
}

// view 实体 → 行视图（user_count 单组计数）。
func (s *Service) view(ctx context.Context, g entity.UserGroup) dto.UserGroupView {
	counts, err := s.users.CountByGroups(ctx, []string{g.Guid})
	if err != nil {
		counts = map[string]int64{}
	}
	return dto.UserGroupView{
		Guid:      g.Guid,
		Name:      g.Name,
		Note:      g.Note,
		IsDefault: g.IsDefault,
		UserCount: counts[g.Guid],
	}
}

// guidsOf 提取组 guid 列表。
func guidsOf(rows []entity.UserGroup) []string {
	out := make([]string, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].Guid)
	}
	return out
}

// dedup guid 去重（保持首次出现顺序）。
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

// pageOffset 分页偏移换算。
func pageOffset(current, pageSize int) int {
	if pageSize <= 0 || current <= 1 {
		return 0
	}
	return (current - 1) * pageSize
}
