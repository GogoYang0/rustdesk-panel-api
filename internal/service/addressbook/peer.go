// Package addressbook 本文件：地址簿设备（ab peers）子服务——列表
// （id 反查 uuid / alias LIKE / 标签 union|intersection）与增删改
// （findOrCreatePeer 自动建 peers 行；tags 全量替换，事实⑦）。
package addressbook

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// PeerService 地址簿设备子服务。
type PeerService struct {
	books      *repository.AddressBookRepo
	abPeers    *repository.AddressBookPeerRepo
	abPeerTags *repository.AddressBookPeerTagRepo
	abTags     *repository.AddressBookTagRepo
	peers      *repository.PeerRepo
	sysinfos   *repository.SysinfoRepo
	perms      *PermissionService
}

// NewPeerService 构建设备子服务。
func NewPeerService(
	books *repository.AddressBookRepo,
	abPeers *repository.AddressBookPeerRepo,
	abPeerTags *repository.AddressBookPeerTagRepo,
	abTags *repository.AddressBookTagRepo,
	peers *repository.PeerRepo,
	sysinfos *repository.SysinfoRepo,
	perms *PermissionService,
) *PeerService {
	return &PeerService{
		books: books, abPeers: abPeers, abPeerTags: abPeerTags,
		abTags: abTags, peers: peers, sysinfos: sysinfos, perms: perms,
	}
}

// tagGuids 逗号分隔 tag guid 列表解析（GET peers tags 参数）。
func tagGuids(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// Peers GET /api/ab/peers：READ 复核（404/403 由权限服务语义承载）；
// 行含 username/hostname/platform 兼容字段。
func (s *PeerService) Peers(ctx context.Context, userGuid string, q dto.PeersListQuery) (api.AbPeerList, error) {
	if q.AB == "" {
		return api.AbPeerList{}, rbac.ErrBadRequest("Invalid request parameters")
	}
	if _, err := s.perms.CheckAccess(ctx, q.AB, userGuid, entity.ShareRuleRead); err != nil {
		return api.AbPeerList{}, err
	}

	filter := repository.ABPeerFilter{
		Alias:    q.Alias,
		TagGuids: tagGuids(q.Tags),
		TagMode:  q.TagMode,
		Current:  pageOr(q.Current, 1),
		PageSize: pageSizeOr(q.PageSize, 0),
	}
	if q.ID != "" {
		// id 为 RustDesk ID：deviceId 引用 peers.uuid，先模糊反查。
		uuids, err := s.peers.FindUUIDsByIDLike(ctx, q.ID)
		if err != nil {
			return api.AbPeerList{}, err
		}
		filter.DeviceUUIDs = uuids
	}
	rows, total, err := s.abPeers.ListByBook(ctx, q.AB, filter)
	if err != nil {
		return api.AbPeerList{}, err
	}
	data, err := s.assembleRows(ctx, q.AB, rows)
	if err != nil {
		return api.AbPeerList{}, err
	}
	return api.AbPeerList{Data: data, Total: int(total)}, nil
}

// PeersQuery POST /api/ab/peers（body 传 ab/id/alias/tags/tagMode，
// 分页仍走 query 参数——参考 @Query() 同源语义）。
func (s *PeerService) PeersQuery(ctx context.Context, userGuid string, req api.AbPeersQueryRequest, current, pageSize *int) (api.AbPeerList, error) {
	q := dto.PeersListQuery{AB: req.Ab, Current: current, PageSize: pageSize}
	if req.Id != nil {
		q.ID = *req.Id
	}
	if req.Alias != nil {
		q.Alias = *req.Alias
	}
	if req.TagMode != nil {
		q.TagMode = string(*req.TagMode)
	}
	if req.Tags != nil {
		q.Tags = strings.Join(*req.Tags, ",")
	}
	return s.Peers(ctx, userGuid, q)
}

// assembleRows 设备行组装：AbPeer 全字段 + sysinfo 反查兼容字段
// （username/hostname/platform，platform 按 os 前段映射）。
func (s *PeerService) assembleRows(ctx context.Context, bookGuid string, rows []entity.AddressBookPeer) ([]api.AbPeer, error) {
	deviceUUIDs := make([]string, 0, len(rows))
	for _, r := range rows {
		deviceUUIDs = append(deviceUUIDs, r.DeviceId)
	}
	sysinfos, err := s.sysinfos.FindByUUIDs(ctx, deviceUUIDs)
	if err != nil {
		return nil, err
	}
	sysByUUID := make(map[string]entity.Sysinfo, len(sysinfos))
	for _, si := range sysinfos {
		sysByUUID[si.UUID] = si
	}

	tagNames, err := s.tagNamesFor(ctx, bookGuid, rows)
	if err != nil {
		return nil, err
	}

	data := make([]api.AbPeer, 0, len(rows))
	for _, r := range rows {
		si := sysByUUID[r.DeviceId]
		tags := tagNames[r.Guid]
		if tags == nil {
			tags = []string{}
		}
		data = append(data, api.AbPeer{
			Guid:            r.Guid,
			AddressBookGuid: &r.AddressBookGuid,
			DeviceId:        r.DeviceId,
			Hash:            r.Hash,
			Password:        r.Password,
			Alias:           r.Alias,
			Note:            &r.Note,
			Tags:            tags,
			Username:        &si.Username,
			Hostname:        &si.Hostname,
			Platform:        &si.OS,
		})
		// platform 覆盖为映射结果（OS 原串仅作中间值）。
		mapped := MapOsToPlatform(si.OS)
		data[len(data)-1].Platform = &mapped
	}
	return data, nil
}

// tagNamesFor 设备 guid→标签名称集合（批量组装）。
func (s *PeerService) tagNamesFor(ctx context.Context, bookGuid string, rows []entity.AddressBookPeer) (map[string][]string, error) {
	out := make(map[string][]string, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	links, err := s.abPeerTags.ListByBook(ctx, bookGuid)
	if err != nil {
		return nil, err
	}
	tags, err := s.abTags.ListByBook(ctx, bookGuid)
	if err != nil {
		return nil, err
	}
	nameByGuid := make(map[string]string, len(tags))
	for _, t := range tags {
		nameByGuid[t.Guid] = t.Name
	}
	for _, l := range links {
		if name, ok := nameByGuid[l.TagGuid]; ok {
			out[l.PeerGuid] = append(out[l.PeerGuid], name)
		}
	}
	return out, nil
}

// AddPeer POST /api/ab/peer/add/{guid}：READ_WRITE 复核；未注册设备
// 自动建 peers 行（uuid 随机/ver=0）；重复 400 'Device already exists
// in the address book'。
func (s *PeerService) AddPeer(ctx context.Context, userGuid, bookGuid string, req api.AbPeerUpsertRequest) (api.AbPeer, error) {
	if _, err := s.perms.CheckAccess(ctx, bookGuid, userGuid, entity.ShareRuleReadWrite); err != nil {
		return api.AbPeer{}, err
	}
	record, err := s.peers.FindOrCreateByID(ctx, req.Id)
	if err != nil {
		return api.AbPeer{}, err
	}
	exists, err := s.abPeers.ExistsInBook(ctx, bookGuid, record.UUID)
	if err != nil {
		return api.AbPeer{}, err
	}
	if exists {
		return api.AbPeer{}, rbac.ErrBadRequest("Device already exists in the address book")
	}

	now := timeNow()
	row := &entity.AddressBookPeer{
		Guid:            uuid.New().String(),
		AddressBookGuid: bookGuid,
		DeviceId:        record.UUID,
		Hash:            req.Hash,
		Password:        req.Password,
		Alias:           req.Alias,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if req.Note != nil {
		row.Note = *req.Note
	}
	if err := s.abPeers.Create(ctx, row); err != nil {
		return api.AbPeer{}, err
	}
	var tagNames []string
	if req.Tags != nil {
		tagNames = *req.Tags
	}
	if err := s.replaceTagLinks(ctx, bookGuid, row.Guid, tagNames); err != nil {
		return api.AbPeer{}, err
	}
	return s.rowOut(ctx, row)
}

// UpdatePeer PUT /api/ab/peer/update/{guid}：按 peer guid 定位行；
// hash/password/alias/note 提供即覆盖；tags 提供即全量替换
// （req.id 为客户端兼容字段——保留解析，行定位以路径 guid 为准）。
func (s *PeerService) UpdatePeer(ctx context.Context, userGuid, peerGuid string, req api.AbPeerUpsertRequest) (api.AbPeer, error) {
	row, err := s.abPeers.FindByID(ctx, peerGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return api.AbPeer{}, rbac.ErrNotFoundErr("Device does not exist in this address book")
		}
		return api.AbPeer{}, err
	}
	if _, err := s.perms.CheckAccess(ctx, row.AddressBookGuid, userGuid, entity.ShareRuleReadWrite); err != nil {
		return api.AbPeer{}, err
	}

	updates := map[string]any{"updatedAt": timeNow()}
	if req.Hash != nil {
		updates["hash"] = *req.Hash
	}
	if req.Password != nil {
		updates["password"] = *req.Password
	}
	if req.Alias != nil {
		updates["alias"] = *req.Alias
	}
	if req.Note != nil {
		updates["note"] = *req.Note
	}
	if err := s.abPeers.UpdateColumns(ctx, row.Guid, updates); err != nil {
		return api.AbPeer{}, err
	}
	if req.Tags != nil {
		if err := s.replaceTagLinks(ctx, row.AddressBookGuid, row.Guid, *req.Tags); err != nil {
			return api.AbPeer{}, err
		}
	}

	fresh, err := s.abPeers.FindByID(ctx, peerGuid)
	if err != nil {
		return api.AbPeer{}, err
	}
	return s.rowOut(ctx, fresh)
}

// DeletePeer DELETE /api/ab/peer/{guid}：READ_WRITE 复核；删关联 +
// 删行；响应 'Deleted successfully'（handler 侧）。
func (s *PeerService) DeletePeer(ctx context.Context, userGuid, peerGuid string) error {
	row, err := s.abPeers.FindByID(ctx, peerGuid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return rbac.ErrNotFoundErr("Device does not exist in this address book")
		}
		return err
	}
	if _, err := s.perms.CheckAccess(ctx, row.AddressBookGuid, userGuid, entity.ShareRuleReadWrite); err != nil {
		return err
	}
	if err := s.abPeerTags.ReplaceForPeer(ctx, row.Guid, nil); err != nil {
		return err
	}
	return s.abPeers.DeleteByGuid(ctx, row.Guid)
}

// replaceTagLinks tags 全量替换：按名 getOrCreate（color=0）后
// ReplaceForPeer 全量重写关联。
func (s *PeerService) replaceTagLinks(ctx context.Context, bookGuid, peerGuid string, tagNames []string) error {
	guids := make([]string, 0, len(tagNames))
	for _, name := range tagNames {
		tag, err := s.abTags.FindOrCreate(ctx, bookGuid, name, 0)
		if err != nil {
			return err
		}
		guids = append(guids, tag.Guid)
	}
	return s.abPeerTags.ReplaceForPeer(ctx, peerGuid, guids)
}

// rowOut 行输出（tags 名称集合组装）。
func (s *PeerService) rowOut(ctx context.Context, row *entity.AddressBookPeer) (api.AbPeer, error) {
	names, err := s.tagNamesFor(ctx, row.AddressBookGuid, []entity.AddressBookPeer{*row})
	if err != nil {
		return api.AbPeer{}, err
	}
	tags := names[row.Guid]
	if tags == nil {
		tags = []string{}
	}
	return api.AbPeer{
		Guid:            row.Guid,
		AddressBookGuid: &row.AddressBookGuid,
		DeviceId:        row.DeviceId,
		Hash:            row.Hash,
		Password:        row.Password,
		Alias:           row.Alias,
		Note:            &row.Note,
		Tags:            tags,
	}, nil
}
