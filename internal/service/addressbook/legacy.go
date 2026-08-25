// Package addressbook 本文件：AddressBookLegacyService——legacy 双端点
// （GET/POST /api/ab，RustDesk 客户端硬依赖，事实⑦兼容怪癖三件套）。
//
// 兼容契约（逐字节）：
//  1. GET 空数据 → 字符串 'null'（JSON 序列化输出 "null"）；
//     非空 → {licensed_devices:100, data:"<双重 JSON 编码>"}，data 内
//     tag_colors 又是一层 JSON 串；
//  2. POST（body {data}）事务全删全插 + findOrCreatePeer 自动建
//     peers 行（uuid 随机/ver=0）；成功返回 'null'；错误经 handler
//     try/catch 语义转为 {error: msg} 且 HTTP 仍 200（仅此端点）。
package addressbook

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// legacyLicensedDevices licensed_devices 恒 100（兼容占位）。
const legacyLicensedDevices = 100

// dangerousTagNames legacy 全量保存跳过的危险标签名（原型链污染防御，
// 参考复刻）。
var dangerousTagNames = map[string]struct{}{
	"__proto__":   {},
	"constructor": {},
	"prototype":   {},
}

// MapOsToPlatform sysinfo.os → 平台常量（参考 platform.util 复刻）：
// 取 "distribution_id / long_os_version" 前段匹配，未命中回退全串。
func MapOsToPlatform(os string) string {
	if os == "" {
		return ""
	}
	head := strings.ToLower(strings.TrimSpace(os))
	if idx := strings.Index(os, " / "); idx >= 0 {
		head = strings.ToLower(strings.TrimSpace(os[:idx]))
	}
	switch {
	case strings.Contains(head, "windows") || head == "win":
		return "Windows"
	case strings.Contains(head, "mac") || strings.Contains(head, "darwin") ||
		head == "macos" || head == "osx":
		return "Mac OS"
	case strings.Contains(head, "android"):
		return "Android"
	case strings.Contains(head, "linux"):
		return "Linux"
	}
	lower := strings.ToLower(os)
	switch {
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "mac") || strings.Contains(lower, "darwin"):
		return "Mac OS"
	case strings.Contains(lower, "android"):
		return "Android"
	case strings.Contains(lower, "linux"):
		return "Linux"
	}
	return ""
}

// legacyPeerData legacy data 内层设备行（键序随 JSON 序列化，值语义
// 与参考一致：缺省空串）。
type legacyPeerData struct {
	ID       string   `json:"id"`
	Hash     string   `json:"hash"`
	Username string   `json:"username"`
	Hostname string   `json:"hostname"`
	Platform string   `json:"platform"`
	Alias    string   `json:"alias"`
	Tags     []string `json:"tags"`
}

// legacyPayload POST body data 的解析形状（tags 名称数组 + peers +
// tag_colors 内层 JSON 串）。
type legacyPayload struct {
	Tags      []string `json:"tags"`
	Peers     []struct {
		ID       string   `json:"id"`
		Hash     string   `json:"hash"`
		Username string   `json:"username"`
		Hostname string   `json:"hostname"`
		Platform string   `json:"platform"`
		Alias    string   `json:"alias"`
		Tags     []string `json:"tags"`
	} `json:"peers"`
	TagColors string `json:"tag_colors"`
}

// LegacyService legacy 兼容服务。
type LegacyService struct {
	db         *gorm.DB
	books      *repository.AddressBookRepo
	abPeers    *repository.AddressBookPeerRepo
	abTags     *repository.AddressBookTagRepo
	abPeerTags *repository.AddressBookPeerTagRepo
	peers      *repository.PeerRepo
	sysinfos   *repository.SysinfoRepo
	perms      *PermissionService
}

// NewLegacyService 构建 legacy 兼容服务。
func NewLegacyService(
	db *gorm.DB,
	books *repository.AddressBookRepo,
	abPeers *repository.AddressBookPeerRepo,
	abTags *repository.AddressBookTagRepo,
	abPeerTags *repository.AddressBookPeerTagRepo,
	peers *repository.PeerRepo,
	sysinfos *repository.SysinfoRepo,
	perms *PermissionService,
) *LegacyService {
	return &LegacyService{
		db: db, books: books, abPeers: abPeers, abTags: abTags,
		abPeerTags: abPeerTags, peers: peers, sysinfos: sysinfos, perms: perms,
	}
}

// EnsurePersonal 个人书幂等取/建（personal 端点与 legacy 共用；
// name='Personal', isPersonal=1，每用户至多一本）。
func (s *LegacyService) EnsurePersonal(ctx context.Context, owner string) (*entity.AddressBook, error) {
	book, err := s.books.FindPersonal(ctx, owner)
	if err == nil {
		return book, nil
	}
	if err != repository.ErrNotFound {
		return nil, err
	}
	now := timeNow()
	fresh := &entity.AddressBook{
		Guid:       newGUID(),
		Owner:      owner,
		IsPersonal: true,
		Name:       "Personal",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.books.Create(ctx, fresh); err != nil {
		// 并发竞态兜底：重查。
		if again, qErr := s.books.FindPersonal(ctx, owner); qErr == nil {
			return again, nil
		}
		return nil, err
	}
	return fresh, nil
}

// GetLegacy GET /api/ab：空数据返回哨兵 ErrLegacyNull（handler 输出
// 字符串 'null'）；非空返回 legacy 载荷结构。
func (s *LegacyService) GetLegacy(ctx context.Context, userGuid string) (map[string]any, error) {
	book, err := s.EnsurePersonal(ctx, userGuid)
	if err != nil {
		return nil, err
	}

	tags, err := s.abTags.ListByBook(ctx, book.Guid)
	if err != nil {
		return nil, err
	}
	peerRows, _, err := s.abPeers.ListByBook(ctx, book.Guid, repository.ABPeerFilter{})
	if err != nil {
		return nil, err
	}
	if len(tags) == 0 && len(peerRows) == 0 {
		return nil, ErrLegacyNull
	}

	// 设备增强信息：deviceId（uuid）→ peers.id 与 sysinfo 兼容字段。
	deviceUUIDs := make([]string, 0, len(peerRows))
	for _, p := range peerRows {
		deviceUUIDs = append(deviceUUIDs, p.DeviceId)
	}
	peerRecords, err := s.peers.FindByUUIDs(ctx, deviceUUIDs)
	if err != nil {
		return nil, err
	}
	idByUUID := make(map[string]string, len(peerRecords))
	for _, p := range peerRecords {
		idByUUID[p.UUID] = p.ID
	}
	sysinfos, err := s.sysinfos.FindByUUIDs(ctx, deviceUUIDs)
	if err != nil {
		return nil, err
	}
	sysByUUID := make(map[string]entity.Sysinfo, len(sysinfos))
	for _, si := range sysinfos {
		sysByUUID[si.UUID] = si
	}

	// 设备→标签关联（名称数组）。
	links, err := s.abPeerTags.ListByBook(ctx, book.Guid)
	if err != nil {
		return nil, err
	}
	tagNameByGuid := make(map[string]string, len(tags))
	for _, t := range tags {
		tagNameByGuid[t.Guid] = t.Name
	}
	tagsByPeer := make(map[string][]string, len(links))
	for _, l := range links {
		if name, ok := tagNameByGuid[l.TagGuid]; ok {
			tagsByPeer[l.PeerGuid] = append(tagsByPeer[l.PeerGuid], name)
		}
	}

	peersOut := make([]legacyPeerData, 0, len(peerRows))
	for _, p := range peerRows {
		si := sysByUUID[p.DeviceId]
		hash, alias := "", ""
		if p.Hash != nil {
			hash = *p.Hash
		}
		if p.Alias != nil {
			alias = *p.Alias
		}
		peersOut = append(peersOut, legacyPeerData{
			ID:       idByUUID[p.DeviceId],
			Hash:     hash,
			Username: si.Username,
			Hostname: si.Hostname,
			Platform: MapOsToPlatform(si.OS),
			Alias:    alias,
			Tags:     tagsByPeer[p.Guid],
		})
		if peersOut[len(peersOut)-1].Tags == nil {
			peersOut[len(peersOut)-1].Tags = []string{}
		}
	}

	tagNames := make([]string, 0, len(tags))
	tagColors := make(map[string]uint32, len(tags))
	for _, t := range tags {
		tagNames = append(tagNames, t.Name)
		tagColors[t.Name] = t.Color
	}

	// tag_colors 内层 JSON 串（双重编码怪癖，客户端硬依赖）。
	colorsJSON, err := json.Marshal(tagColors)
	if err != nil {
		return nil, err
	}
	inner := map[string]any{
		"tags":       tagNames,
		"peers":      peersOut,
		"tag_colors": string(colorsJSON),
	}
	innerJSON, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"licensed_devices": legacyLicensedDevices,
		"data":             string(innerJSON),
	}, nil
}

// UpdateLegacy POST /api/ab：data 空串视为无操作（参考返回 'null'）；
// 解析失败 400 'Invalid JSON data'（handler 转为 {error} 200）；
// 事务内全删全插：清 peer_tags/tags/peers → 按 tag_colors 建标签
// （危险名跳过）→ findOrCreatePeer（按 RustDesk ID，未注册自动建
// peers 行）→ 建 ab peer 与标签关联。
func (s *LegacyService) UpdateLegacy(ctx context.Context, userGuid, data string) error {
	if data == "" {
		return nil
	}
	var payload legacyPayload
	if err := json.Unmarshal([]byte(data), &payload); err != nil {
		return rbac.ErrBadRequest("Invalid JSON data")
	}

	// tag_colors 解析失败忽略（参考即如此）。
	tagColors := make(map[string]uint32)
	if payload.TagColors != "" {
		var colors map[string]uint32
		if err := json.Unmarshal([]byte(payload.TagColors), &colors); err == nil {
			tagColors = colors
		}
	}

	book, err := s.EnsurePersonal(ctx, userGuid)
	if err != nil {
		return err
	}

	// 过滤危险标签名。
	tagNames := make([]string, 0, len(payload.Tags))
	for _, name := range payload.Tags {
		if _, bad := dangerousTagNames[name]; bad {
			continue
		}
		tagNames = append(tagNames, name)
	}

	// 合法化设备行（id 空跳过）。
	type peerIn struct {
		ID    string
		Hash  string
		Alias string
		Tags  []string
	}
	peersIn := make([]peerIn, 0, len(payload.Peers))
	for _, p := range payload.Peers {
		if p.ID == "" {
			continue
		}
		peersIn = append(peersIn, peerIn{ID: p.ID, Hash: p.Hash, Alias: p.Alias, Tags: p.Tags})
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.abPeers.DeleteByBookTx(tx, book.Guid); err != nil {
			return err
		}
		guidByName := make(map[string]string, len(tagNames))
		for _, name := range tagNames {
			tag, err := s.abPeers.InsertTagTx(tx, book.Guid, name, tagColors[name])
			if err != nil {
				return err
			}
			guidByName[name] = tag.Guid
		}
		for _, p := range peersIn {
			record, err := s.peers.FindOrCreateByIDTx(tx, p.ID)
			if err != nil {
				return err
			}
			row, err := s.abPeers.InsertPeerTx(tx, book.Guid, record.UUID, p.Hash, p.Alias)
			if err != nil {
				return err
			}
			for _, tagName := range p.Tags {
				tagGuid, ok := guidByName[tagName]
				if !ok {
					// 关联了未在 tags 列表声明的标签：按名补建（参考
					// getOrCreateTag 语义）。
					tag, err := s.abPeers.InsertTagTx(tx, book.Guid, tagName, tagColors[tagName])
					if err != nil {
						return err
					}
					tagGuid = tag.Guid
					guidByName[tagName] = tag.Guid
				}
				if err := s.abPeers.LinkTagTx(tx, row.Guid, tagGuid); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ErrLegacyNull GET legacy 空数据哨兵（handler 据此输出字符串 'null'）。
var ErrLegacyNull = fmt.Errorf("legacy null")

// timeNow 与 newGUID 由主文件提供（clock/uuid 注入点）。
