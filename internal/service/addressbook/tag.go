// Package addressbook 本文件：地址簿标签（ab tags）子服务——列表
// （tag_colors 双层 JSON 串）/全量替换/增改名改色删（级联清
// peer_tags，事实⑦）。
package addressbook

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// TagService 地址簿标签子服务。
type TagService struct {
	db         *gorm.DB
	abTags     *repository.AddressBookTagRepo
	abPeerTags *repository.AddressBookPeerTagRepo
	perms      *PermissionService
}

// NewTagService 构建标签子服务。
func NewTagService(
	db *gorm.DB,
	abTags *repository.AddressBookTagRepo,
	abPeerTags *repository.AddressBookPeerTagRepo,
	perms *PermissionService,
) *TagService {
	return &TagService{db: db, abTags: abTags, abPeerTags: abPeerTags, perms: perms}
}

// tagListOut AbTagList 组装（tag_colors 为 JSON 编码串——客户端
// 硬依赖的双重编码形态）。
func tagListOut(rows []entity.AddressBookTag) api.AbTagList {
	data := make([]api.AbTag, 0, len(rows))
	colors := make(map[string]uint32, len(rows))
	for _, t := range rows {
		data = append(data, api.AbTag{Guid: t.Guid, Name: t.Name, Color: int32(t.Color)})
		colors[t.Name] = t.Color
	}
	var colorsStr *string
	if len(rows) > 0 {
		if b, err := json.Marshal(colors); err == nil {
			s := string(b)
			colorsStr = &s
		}
	}
	return api.AbTagList{Data: data, TagColors: colorsStr}
}

// tagOut 单标签行输出。
func tagOut(t *entity.AddressBookTag) api.AbTag {
	return api.AbTag{Guid: t.Guid, Name: t.Name, Color: int32(t.Color)}
}

// Tags GET /api/ab/tags/{guid}：READ 复核；全量标签 + tag_colors。
func (s *TagService) Tags(ctx context.Context, userGuid, bookGuid string) (api.AbTagList, error) {
	if _, err := s.perms.CheckAccess(ctx, bookGuid, userGuid, entity.ShareRuleRead); err != nil {
		return api.AbTagList{}, err
	}
	rows, err := s.abTags.ListByBook(ctx, bookGuid)
	if err != nil {
		return api.AbTagList{}, err
	}
	return tagListOut(rows), nil
}

// ReplaceTags POST /api/ab/tags/{guid}：READ_WRITE 复核；事务全量
// 替换书内标签（关联随标签清空重建语义：peer_tags 清书内全部）。
func (s *TagService) ReplaceTags(ctx context.Context, userGuid, bookGuid string, req api.AbTagsReplaceRequest) (api.AbTagList, error) {
	if _, err := s.perms.CheckAccess(ctx, bookGuid, userGuid, entity.ShareRuleReadWrite); err != nil {
		return api.AbTagList{}, err
	}
	inputs := make([]repository.TagColorInput, 0, len(req.Tags))
	for _, t := range req.Tags {
		inputs = append(inputs, repository.TagColorInput{Name: t.Name, Color: uint32(t.Color)})
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.abTags.ReplaceBookTagsTx(tx, bookGuid, inputs)
	})
	if err != nil {
		return api.AbTagList{}, err
	}
	rows, err := s.abTags.ListByBook(ctx, bookGuid)
	if err != nil {
		return api.AbTagList{}, err
	}
	return tagListOut(rows), nil
}

// AddTag POST /api/ab/tag/add/{guid}：READ_WRITE 复核；同名 409
// 'Tag already exists'。
func (s *TagService) AddTag(ctx context.Context, userGuid, bookGuid string, req api.AbTagUpsertRequest) (api.AbTag, error) {
	if _, err := s.perms.CheckAccess(ctx, bookGuid, userGuid, entity.ShareRuleReadWrite); err != nil {
		return api.AbTag{}, err
	}
	if _, err := s.abTags.FindByBookAndName(ctx, bookGuid, req.Name); err == nil {
		return api.AbTag{}, rbac.ErrConflictMsg("Tag already exists")
	} else if !errors.Is(err, repository.ErrNotFound) {
		return api.AbTag{}, err
	}
	row := &entity.AddressBookTag{
		Guid:            uuid.New().String(),
		AddressBookGuid: bookGuid,
		Name:            req.Name,
		Color:           uint32(req.Color),
		CreatedAt:       timeNow(),
	}
	if err := s.abTags.Create(ctx, row); err != nil {
		return api.AbTag{}, err
	}
	return tagOut(row), nil
}

// RenameTag PUT /api/ab/tag/rename/{guid}：查行 404 'Tag does not
// exist'；新名冲突 400 'New tag name already exists'。
func (s *TagService) RenameTag(ctx context.Context, userGuid, tagGuid string, req api.AbTagRenameRequest) (api.AbTag, error) {
	row, err := s.abTags.FindByID(ctx, tagGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.AbTag{}, rbac.ErrNotFoundErr("Tag does not exist")
		}
		return api.AbTag{}, err
	}
	if _, err := s.perms.CheckAccess(ctx, row.AddressBookGuid, userGuid, entity.ShareRuleReadWrite); err != nil {
		return api.AbTag{}, err
	}
	if _, err := s.abTags.FindByBookAndName(ctx, row.AddressBookGuid, req.Name); err == nil {
		return api.AbTag{}, rbac.ErrBadRequest("New tag name already exists")
	} else if !errors.Is(err, repository.ErrNotFound) {
		return api.AbTag{}, err
	}
	if err := s.abTags.Rename(ctx, row.Guid, req.Name); err != nil {
		return api.AbTag{}, err
	}
	fresh, err := s.abTags.FindByID(ctx, tagGuid)
	if err != nil {
		return api.AbTag{}, err
	}
	return tagOut(fresh), nil
}

// UpdateTag PUT /api/ab/tag/update/{guid}：颜色更新。
func (s *TagService) UpdateTag(ctx context.Context, userGuid, tagGuid string, req api.AbTagUpsertRequest) (api.AbTag, error) {
	row, err := s.abTags.FindByID(ctx, tagGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.AbTag{}, rbac.ErrNotFoundErr("Tag does not exist")
		}
		return api.AbTag{}, err
	}
	if _, err := s.perms.CheckAccess(ctx, row.AddressBookGuid, userGuid, entity.ShareRuleReadWrite); err != nil {
		return api.AbTag{}, err
	}
	if err := s.abTags.UpdateColor(ctx, row.Guid, uint32(req.Color)); err != nil {
		return api.AbTag{}, err
	}
	fresh, err := s.abTags.FindByID(ctx, tagGuid)
	if err != nil {
		return api.AbTag{}, err
	}
	return tagOut(fresh), nil
}

// DeleteTag DELETE /api/ab/tag/{guid}：级联清 peer_tags + 删标签。
func (s *TagService) DeleteTag(ctx context.Context, userGuid, tagGuid string) error {
	row, err := s.abTags.FindByID(ctx, tagGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return rbac.ErrNotFoundErr("Tag does not exist")
		}
		return err
	}
	if _, err := s.perms.CheckAccess(ctx, row.AddressBookGuid, userGuid, entity.ShareRuleReadWrite); err != nil {
		return err
	}
	if err := s.abPeerTags.DeleteByTag(ctx, row.Guid); err != nil {
		return err
	}
	return s.abTags.DeleteByGuid(ctx, row.Guid)
}
