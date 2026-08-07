// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：PeerRepo——peers 表仓储（设备 = peers 行，/peers 与 /devices
// 同表两视图；过滤语义差异由 PeerFilter/DeviceFilter 分别承载，禁止混用）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// OnlineWindow 在线判定窗口（共享知识 6：lastHeartbeat > now-60s）。
const OnlineWindow = 60 * time.Second

// like 子串匹配包裹（LIKE 语义统一，调用方不自行拼 %）。
func like(s string) string { return "%" + s + "%" }

// nowOr 返回参考时刻（零值回退 time.Now()，is_online 过滤测试可控）。
func nowOr(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}

// PeerFilter /peers 可见设备列表过滤（openapi /api/peers 参数契约）。
// 全部 LIKE 语义字段：id/user_name/device_group_name/os；
// 精确字段：device_group_guid。
type PeerFilter struct {
	ID              string    // LIKE peers.id
	Status          *int      // peers.status（0|1）
	IsOnline        *bool     // lastHeartbeat 与 now-OnlineWindow 比较
	UserName        string    // LIKE users.username
	DeviceGroupGuid string    // 精确 peers.deviceGroupGuid
	DeviceGroupName string    // LIKE device_groups.name
	OS              string    // LIKE sysinfos.os
	Now             time.Time // is_online 参考时刻（零值取 time.Now()）
	Current         int       // 页码（1 起）
	PageSize        int       // 页大小（0 = 不分页）
}

// DeviceFilter /devices 管理设备列表过滤（openapi /api/devices 参数契约）。
// 语义差异（对齐 spec，禁止规范化）：id/user_name/os/device_group_name
// 精确；device_name/device_username LIKE sysinfos 列；group_name LIKE 组名。
type DeviceFilter struct {
	ID              string    // 精确 peers.id
	Status          *int      // peers.status（0|1）
	IsOnline        *bool     // lastHeartbeat 与 now-OnlineWindow 比较
	DeviceName      string    // LIKE sysinfos.hostname
	UserName        string    // 精确 users.username
	DeviceUsername  string    // LIKE sysinfos.username
	OS              string    // 精确 sysinfos.os
	DeviceGroupName string    // 精确 device_groups.name
	DeviceGroupGuid string    // 精确 peers.deviceGroupGuid
	GroupName       string    // LIKE device_groups.name
	Now             time.Time // is_online 参考时刻
	Current         int       // 页码（1 起）
	PageSize        int       // 页大小（0 = 不分页）
}

// GuidSet RBAC scope 边界的仓储侧视图（与 rbac.PermissionScope 等价，
// 避免 repository 反向依赖 rbac 包）。
type GuidSet struct {
	Global bool
	Guids  []string
}

// PeerRepo peers 表仓储。
type PeerRepo struct {
	*GenericRepository[entity.Peer]
}

// NewPeerRepo 构建仓储。
func NewPeerRepo(db *gorm.DB) *PeerRepo {
	return &PeerRepo{GenericRepository: New[entity.Peer](db)}
}

// FindByUUID 按 uuid 主键查询；未找到返回 ErrNotFound。
func (r *PeerRepo) FindByUUID(ctx context.Context, uuid string) (*entity.Peer, error) {
	var p entity.Peer
	err := r.db.WithContext(ctx).Where("uuid = ?", uuid).First(&p).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// UpsertHeartbeat 心跳落库（并发首跳安全，设计 §4.1 步骤 4-5）：
// 不存在则 INSERT（status 走 DB 默认 1=active），存在则仅更新心跳列
// id/ver/modifiedAt/lastHeartbeat——status/userGuid/deviceGroupGuid/
// strategyGuid/note 不被心跳报文覆盖。
func (r *PeerRepo) UpsertHeartbeat(ctx context.Context, uuid, id string, ver, modifiedAt int64, at time.Time) error {
	p := &entity.Peer{UUID: uuid, ID: id, Ver: ver, ModifiedAt: modifiedAt, LastHeartbeat: &at}
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "uuid"}},
		DoUpdates: clause.Assignments(map[string]any{
			"id":            id,
			"ver":           ver,
			"modifiedAt":    modifiedAt,
			"lastHeartbeat": at,
		}),
	}).Create(p).Error
}

// UpdateHeartbeat 显式心跳 UPDATE（服务层已确认设备存在的路径）。
func (r *PeerRepo) UpdateHeartbeat(ctx context.Context, uuid, id string, ver, modifiedAt int64, at time.Time) error {
	return r.db.WithContext(ctx).Model(&entity.Peer{}).
		Where("uuid = ?", uuid).
		Updates(map[string]any{
			"id":            id,
			"ver":           ver,
			"modifiedAt":    modifiedAt,
			"lastHeartbeat": at,
		}).Error
}

// DiffSyncConns 事务内将 active_connections 同步至客户端上报快照：
// 消失者 DELETE、新增者 INSERT（共享知识 9：请求内 diff，设计 §4.1 步骤 6）。
func (r *PeerRepo) DiffSyncConns(ctx context.Context, uuid string, conns []int64) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing []int64
		if err := tx.Model(&entity.ActiveConnection{}).
			Where("deviceUuid = ?", uuid).
			Pluck("connId", &existing).Error; err != nil {
			return err
		}
		want := make(map[int64]struct{}, len(conns))
		for _, c := range conns {
			want[c] = struct{}{}
		}
		have := make(map[int64]struct{}, len(existing))
		for _, c := range existing {
			have[c] = struct{}{}
		}
		toDelete := make([]int64, 0, len(existing))
		for _, c := range existing {
			if _, ok := want[c]; !ok {
				toDelete = append(toDelete, c)
			}
		}
		toInsert := make([]int64, 0, len(conns))
		for _, c := range conns {
			if _, ok := have[c]; !ok {
				toInsert = append(toInsert, c)
			}
		}
		if len(toDelete) > 0 {
			if err := tx.Where("deviceUuid = ? AND connId IN ?", uuid, toDelete).
				Delete(&entity.ActiveConnection{}).Error; err != nil {
				return err
			}
		}
		for _, c := range toInsert {
			if err := tx.Create(&entity.ActiveConnection{ConnID: c, DeviceUuid: uuid}).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// ListAccessiblePeers 三源可见性分页（/peers，非管理员）：
// 自己名下 ∪ device_group_user_permissions 授权组内 ∪
// user_user_permissions 被授权用户名下。排序 peer.id ASC（字符串序，契约）。
func (r *PeerRepo) ListAccessiblePeers(ctx context.Context, userGuid string, f PeerFilter) ([]entity.Peer, int64, error) {
	base := r.db.WithContext(ctx).Table("peers p").Where(
		"p.userGuid = ? OR EXISTS (SELECT 1 FROM device_group_user_permissions dgup"+
			" WHERE dgup.userGuid = ? AND dgup.deviceGroupGuid = p.deviceGroupGuid)"+
			" OR EXISTS (SELECT 1 FROM user_user_permissions uup"+
			" WHERE uup.userGuid = ? AND uup.targetUserGuid = p.userGuid)",
		userGuid, userGuid, userGuid)
	return listPeersPage(base, applyPeerFilter(f), f.Current, f.PageSize)
}

// ListScoped scope 边界分页（/devices）：Global 全量（含未分组设备）；
// 非 Global 仅授权设备组并集内（未分组设备天然排除，设计 §4.3）。
// scope 组集为空且非全局时直接返回空页（不产生无效 SQL）。
func (r *PeerRepo) ListScoped(ctx context.Context, scope GuidSet, f DeviceFilter) ([]entity.Peer, int64, error) {
	if !scope.Global && len(scope.Guids) == 0 {
		return []entity.Peer{}, 0, nil
	}
	base := r.db.WithContext(ctx).Table("peers p")
	if !scope.Global {
		base = base.Where("p.deviceGroupGuid IN ?", scope.Guids)
	}
	return listPeersPage(base, applyDeviceFilter(f), f.Current, f.PageSize)
}

// ListAll 全量分页（/peers 管理员视图，无 scope 限制；过滤语义同
// PeerFilter）。与 ListScoped/ListAccessiblePeers 共用分页执行器。
func (r *PeerRepo) ListAll(ctx context.Context, f PeerFilter) ([]entity.Peer, int64, error) {
	return listPeersPage(r.db.WithContext(ctx).Table("peers p"), applyPeerFilter(f), f.Current, f.PageSize)
}

// SetStatus 启停设备（PATCH /api/devices/status 单目标写入）。
func (r *PeerRepo) SetStatus(ctx context.Context, uuid string, status int) error {
	return r.db.WithContext(ctx).Model(&entity.Peer{}).
		Where("uuid = ?", uuid).
		Update("status", status).Error
}

// UpdateColumnsByUUID 按列名映射更新设备（设备关联变更）。
// updates 的键必须是实体 tag 中的 DB 列名（服务层仅传常量键）；
// nil 值置 NULL（外键解绑语义）。
func (r *PeerRepo) UpdateColumnsByUUID(ctx context.Context, uuid string, updates map[string]any) error {
	if len(updates) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).Model(&entity.Peer{}).
		Where("uuid = ?", uuid).
		Updates(updates).Error
}

// UpdateDeviceGroupGuid 关联设备组（sysinfo preset-device-group-name
// 命中时回写 peers.deviceGroupGuid）。
func (r *PeerRepo) UpdateDeviceGroupGuid(ctx context.Context, uuid, guid string) error {
	return r.db.WithContext(ctx).Model(&entity.Peer{}).
		Where("uuid = ?", uuid).
		Update("deviceGroupGuid", guid).Error
}

// FillNoteIfEmpty note 兜底写入（sysinfo preset-note 语义：
// 仅当 peers.note 为空时写入，不覆盖已有注记）。
func (r *PeerRepo) FillNoteIfEmpty(ctx context.Context, uuid, note string) error {
	return r.db.WithContext(ctx).Model(&entity.Peer{}).
		Where("uuid = ? AND (note IS NULL OR note = '')", uuid).
		Update("note", note).Error
}

// DeleteWithConns 事务删除设备并显式级联删除 active_connections
// （共享知识 9：应用层事务显式级联，SQLite/MySQL 行为统一，
// 不依赖 DB FK 的 CASCADE 声明）。
func (r *PeerRepo) DeleteWithConns(ctx context.Context, uuid string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("deviceUuid = ?", uuid).
			Delete(&entity.ActiveConnection{}).Error; err != nil {
			return err
		}
		return tx.Where("uuid = ?", uuid).Delete(&entity.Peer{}).Error
	})
}

// listPeersPage 通用分页执行：count 与 fetch 独立语句（互不污染），
// 排序固定 peer.id ASC（契约）。
func listPeersPage(base *gorm.DB, apply func(*gorm.DB) *gorm.DB, current, pageSize int) ([]entity.Peer, int64, error) {
	var total int64
	if err := apply(base.Session(&gorm.Session{})).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := apply(base.Session(&gorm.Session{})).Order("p.id ASC")
	if pageSize > 0 {
		fetch = fetch.Limit(pageSize)
		if current > 1 {
			fetch = fetch.Offset((current - 1) * pageSize)
		}
	}
	out := make([]entity.Peer, 0)
	if err := fetch.Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// applyPeerFilter 构建 /peers 过滤链（EXISTS 子查询避免 JOIN 别名冲突，
// 过滤字段可任意组合）。
func applyPeerFilter(f PeerFilter) func(*gorm.DB) *gorm.DB {
	return func(q *gorm.DB) *gorm.DB {
		if f.ID != "" {
			q = q.Where("p.id LIKE ?", like(f.ID))
		}
		if f.Status != nil {
			q = q.Where("p.status = ?", *f.Status)
		}
		if f.IsOnline != nil {
			cutoff := nowOr(f.Now).Add(-OnlineWindow)
			if *f.IsOnline {
				q = q.Where("p.lastHeartbeat > ?", cutoff)
			} else {
				q = q.Where("(p.lastHeartbeat <= ? OR p.lastHeartbeat IS NULL)", cutoff)
			}
		}
		if f.UserName != "" {
			q = q.Where("EXISTS (SELECT 1 FROM users u WHERE u.guid = p.userGuid AND u.username LIKE ?)", like(f.UserName))
		}
		if f.DeviceGroupGuid != "" {
			q = q.Where("p.deviceGroupGuid = ?", f.DeviceGroupGuid)
		}
		if f.DeviceGroupName != "" {
			q = q.Where("EXISTS (SELECT 1 FROM device_groups dg WHERE dg.guid = p.deviceGroupGuid AND dg.name LIKE ?)", like(f.DeviceGroupName))
		}
		if f.OS != "" {
			q = q.Where("EXISTS (SELECT 1 FROM sysinfos si WHERE si.uuid = p.uuid AND si.os LIKE ?)", like(f.OS))
		}
		return q
	}
}

// applyDeviceFilter 构建 /devices 过滤链（精确/LIKE 语义见 DeviceFilter）。
func applyDeviceFilter(f DeviceFilter) func(*gorm.DB) *gorm.DB {
	return func(q *gorm.DB) *gorm.DB {
		if f.ID != "" {
			q = q.Where("p.id = ?", f.ID)
		}
		if f.Status != nil {
			q = q.Where("p.status = ?", *f.Status)
		}
		if f.IsOnline != nil {
			cutoff := nowOr(f.Now).Add(-OnlineWindow)
			if *f.IsOnline {
				q = q.Where("p.lastHeartbeat > ?", cutoff)
			} else {
				q = q.Where("(p.lastHeartbeat <= ? OR p.lastHeartbeat IS NULL)", cutoff)
			}
		}
		if f.DeviceName != "" {
			q = q.Where("EXISTS (SELECT 1 FROM sysinfos si WHERE si.uuid = p.uuid AND si.hostname LIKE ?)", like(f.DeviceName))
		}
		if f.UserName != "" {
			q = q.Where("EXISTS (SELECT 1 FROM users u WHERE u.guid = p.userGuid AND u.username = ?)", f.UserName)
		}
		if f.DeviceUsername != "" {
			q = q.Where("EXISTS (SELECT 1 FROM sysinfos si WHERE si.uuid = p.uuid AND si.username LIKE ?)", like(f.DeviceUsername))
		}
		if f.OS != "" {
			q = q.Where("EXISTS (SELECT 1 FROM sysinfos si WHERE si.uuid = p.uuid AND si.os = ?)", f.OS)
		}
		if f.DeviceGroupGuid != "" {
			q = q.Where("p.deviceGroupGuid = ?", f.DeviceGroupGuid)
		}
		if f.DeviceGroupName != "" {
			q = q.Where("EXISTS (SELECT 1 FROM device_groups dg WHERE dg.guid = p.deviceGroupGuid AND dg.name = ?)", f.DeviceGroupName)
		}
		if f.GroupName != "" {
			q = q.Where("EXISTS (SELECT 1 FROM device_groups dg WHERE dg.guid = p.deviceGroupGuid AND dg.name LIKE ?)", like(f.GroupName))
		}
		return q
	}
}
