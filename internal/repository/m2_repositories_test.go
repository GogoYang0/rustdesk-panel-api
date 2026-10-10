// Package repository M2 仓储行为测试：peer 心跳/差量/三源可见性/scope
// 边界、角色与指派替换、策略删除置空、组 accessible、sysinfo upsert、
// 审计落库。全部基于内存 SQLite + 真实迁移。
package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// openM2Empty 迁移就绪的空内存库（自建小 fixture 的测试用）。
func openM2Empty(t *testing.T) (context.Context, *gorm.DB) {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	testutil.MigrateUpForTest(t, db)
	return context.Background(), db
}

// openM2 迁移 + M2 fixture 就绪的内存库。
func openM2(t *testing.T) (context.Context, *gorm.DB, *testutil.SeedM2Data) {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	data := testutil.SeedM2(t, db)
	return context.Background(), db, data
}

// TestPeerUpsertHeartbeat 首跳注册与二次心跳更新（状态/归属不被覆盖）。
func TestPeerUpsertHeartbeat(t *testing.T) {
	ctx, db := openM2Empty(t)
	repo := NewPeerRepo(db)
	now := time.Now()

	// 首跳：INSERT。
	if err := repo.UpsertHeartbeat(ctx, "hb-1", "900001", 1001000, now.UnixMilli(), now); err != nil {
		t.Fatalf("first heartbeat: %v", err)
	}
	p, err := repo.FindByUUID(ctx, "hb-1")
	if err != nil {
		t.Fatalf("FindByUUID: %v", err)
	}
	if p.Status != entity.PeerStatusActive {
		t.Errorf("status = %d, want default active 1", p.Status)
	}
	if p.UserGuid != nil || p.DeviceGroupGuid != nil {
		t.Errorf("first heartbeat should not set ownership, got %+v", p)
	}

	// 归属与状态注入后二次心跳：仅心跳列变化。
	owner := "hb-owner-user"
	p.UserGuid = &owner
	p.Status = entity.PeerStatusDisabled
	if err := repo.Update(ctx, p); err != nil {
		t.Fatalf("inject ownership: %v", err)
	}
	later := now.Add(time.Minute)
	if err := repo.UpsertHeartbeat(ctx, "hb-1", "900002", 1002000, later.UnixMilli(), later); err != nil {
		t.Fatalf("second heartbeat: %v", err)
	}
	p2, err := repo.FindByUUID(ctx, "hb-1")
	if err != nil {
		t.Fatalf("FindByUUID after: %v", err)
	}
	if p2.ID != "900002" || p2.Ver != 1002000 || p2.ModifiedAt != later.UnixMilli() {
		t.Errorf("heartbeat columns not updated: %+v", p2)
	}
	if p2.Status != entity.PeerStatusDisabled || p2.UserGuid == nil || *p2.UserGuid != owner {
		t.Errorf("heartbeat overwrote ownership/status: %+v", p2)
	}
}

// TestPeerDiffSyncConns 心跳 conns 差量同步（消失删除、新增插入、交集保留）。
func TestPeerDiffSyncConns(t *testing.T) {
	ctx, db := openM2Empty(t)
	peers := NewPeerRepo(db)
	conns := NewActiveConnectionRepo(db)
	now := time.Now()
	if err := peers.UpsertHeartbeat(ctx, "diff-1", "900003", 1, now.UnixMilli(), now); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
	if err := peers.DiffSyncConns(ctx, "diff-1", []int64{11, 12, 13}); err != nil {
		t.Fatalf("first diff: %v", err)
	}
	got, err := conns.ListConnIds(ctx, "diff-1")
	if err != nil {
		t.Fatalf("ListConnIds: %v", err)
	}
	if len(got) != 3 || got[0] != 11 || got[1] != 12 || got[2] != 13 {
		t.Fatalf("conns = %v, want [11 12 13]", got)
	}

	// 上报 {12,14}：11/13 消失、14 新增、12 保留。
	if err := peers.DiffSyncConns(ctx, "diff-1", []int64{12, 14}); err != nil {
		t.Fatalf("second diff: %v", err)
	}
	got, err = conns.ListConnIds(ctx, "diff-1")
	if err != nil {
		t.Fatalf("ListConnIds after: %v", err)
	}
	if len(got) != 2 || got[0] != 12 || got[1] != 14 {
		t.Errorf("conns = %v, want [12 14]", got)
	}
}

// TestPeerListAccessiblePeers 三源可见性 + /peers LIKE 过滤。
func TestPeerListAccessiblePeers(t *testing.T) {
	ctx, db, data := openM2(t)
	repo := NewPeerRepo(db)

	// scoped 用户：源一名下 PeerA；源二组授权 DG1（PeerA 同组）；
	// 源三 user_user_permissions（owner 授权可见 scoped 名下设备）。
	rows, total, err := repo.ListAccessiblePeers(ctx, data.Scoped.Guid, PeerFilter{})
	if err != nil {
		t.Fatalf("ListAccessiblePeers: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].UUID != data.PeerA.UUID {
		t.Fatalf("scoped accessible = %d rows %v, want PeerA only", total, uuidsOf(rows))
	}

	// owner：源一名下 PeerC + 源三被授权可见 scoped 名下 PeerA。
	rows, total, err = repo.ListAccessiblePeers(ctx, data.Owner.Guid, PeerFilter{})
	if err != nil {
		t.Fatalf("owner ListAccessiblePeers: %v", err)
	}
	if total != 2 {
		t.Fatalf("owner accessible = %d rows %v, want PeerA+PeerC", total, uuidsOf(rows))
	}

	// admin（无三源命中）得空。
	_, total, err = repo.ListAccessiblePeers(ctx, data.Admin.Guid, PeerFilter{})
	if err != nil {
		t.Fatalf("admin ListAccessiblePeers: %v", err)
	}
	if total != 0 {
		t.Errorf("admin accessible = %d, want 0", total)
	}

	// 过滤：id LIKE + os LIKE（sysinfos 关联语义）。
	online := true
	rows, total, err = repo.ListAccessiblePeers(ctx, data.Owner.Guid, PeerFilter{
		ID: "0001", OS: "windows", IsOnline: &online, Now: data.Now,
	})
	if err != nil {
		t.Fatalf("filtered ListAccessiblePeers: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].UUID != data.PeerA.UUID {
		t.Errorf("filtered = %d rows %v, want PeerA", total, uuidsOf(rows))
	}
}

// TestPeerListScoped scope 边界 + /devices 过滤语义差异。
func TestPeerListScoped(t *testing.T) {
	ctx, db, data := openM2(t)
	repo := NewPeerRepo(db)

	// global：全量含未分组。
	rows, total, err := repo.ListScoped(ctx, GuidSet{Global: true}, DeviceFilter{})
	if err != nil {
		t.Fatalf("global ListScoped: %v", err)
	}
	if total != 3 {
		t.Fatalf("global total = %d rows %v, want 3", total, uuidsOf(rows))
	}

	// scoped：仅 DG1（排除未分组 PeerB 与 DG2 的 PeerC）。
	rows, total, err = repo.ListScoped(ctx, GuidSet{Guids: []string{data.DG1.Guid}}, DeviceFilter{})
	if err != nil {
		t.Fatalf("scoped ListScoped: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].UUID != data.PeerA.UUID {
		t.Fatalf("scoped = %d rows %v, want PeerA", total, uuidsOf(rows))
	}

	// 空组集：直接空页。
	rows, total, err = repo.ListScoped(ctx, GuidSet{}, DeviceFilter{})
	if err != nil {
		t.Fatalf("empty scoped ListScoped: %v", err)
	}
	if total != 0 || len(rows) != 0 {
		t.Errorf("empty scope = %d rows, want 0", total)
	}

	// /devices device_group_name 精确。
	rows, total, err = repo.ListScoped(ctx, GuidSet{Global: true}, DeviceFilter{DeviceGroupName: "Alpha"})
	if err != nil {
		t.Fatalf("by group name: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].UUID != data.PeerA.UUID {
		t.Errorf("by group name = %d rows %v, want PeerA", total, uuidsOf(rows))
	}

	// /devices group_name LIKE：前缀 "Al" 命中 Alpha。
	rows, total, err = repo.ListScoped(ctx, GuidSet{Global: true}, DeviceFilter{GroupName: "Al"})
	if err != nil {
		t.Fatalf("by group_name like: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].UUID != data.PeerA.UUID {
		t.Errorf("group_name like = %d rows %v, want PeerA", total, uuidsOf(rows))
	}

	// 分页：pageSize=2 第 1 页 id ASC。
	rows, total, err = repo.ListScoped(ctx, GuidSet{Global: true}, DeviceFilter{Current: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("paged ListScoped: %v", err)
	}
	if total != 3 || len(rows) != 2 || rows[0].ID != "1000001" || rows[1].ID != "1000002" {
		t.Errorf("paged = %d rows %v, want first page of 2 (id ASC)", total, idsOf(rows))
	}
}

// TestStrategyDeleteWithDetach 删除策略置空三处引用 + 删除行。
func TestStrategyDeleteWithDetach(t *testing.T) {
	ctx, db, data := openM2(t)
	repo := NewStrategyRepo(db)
	peers := NewPeerRepo(db)
	users := NewUserRepo(db)
	groups := NewDeviceGroupRepo(db)

	guid := data.StrategyS.Guid
	if err := repo.DeleteWithDetach(ctx, guid); err != nil {
		t.Fatalf("DeleteWithDetach: %v", err)
	}
	if _, err := repo.FindByID(ctx, guid); !errors.Is(err, ErrNotFound) {
		t.Errorf("strategy should be gone, got %v", err)
	}
	p, err := peers.FindByUUID(ctx, data.PeerA.UUID)
	if err != nil {
		t.Fatalf("peer: %v", err)
	}
	if p.StrategyGuid != nil {
		t.Errorf("peer.strategyGuid should be NULL, got %s", *p.StrategyGuid)
	}
	u, err := users.FindByGuid(ctx, data.Scoped.Guid)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if u.StrategyGuid != nil {
		t.Errorf("user.strategyGuid should be NULL, got %s", *u.StrategyGuid)
	}
	g, err := groups.FindByID(ctx, data.DG1.Guid)
	if err != nil {
		t.Fatalf("device group: %v", err)
	}
	if g.StrategyGuid != nil {
		t.Errorf("device_groups.strategyGuid should be NULL, got %s", *g.StrategyGuid)
	}
}

// TestDeviceGroupListAccessibleAndRefs 组 accessible（scope ∪ 显式授权）与角色引用计数。
func TestDeviceGroupListAccessibleAndRefs(t *testing.T) {
	ctx, db, data := openM2(t)
	repo := NewDeviceGroupRepo(db)

	// global：全量。
	rows, total, err := repo.ListAccessible(ctx, data.Scoped.Guid, GuidSet{Global: true}, "", Query{})
	if err != nil {
		t.Fatalf("global accessible: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("global accessible = %d rows, want 2", total)
	}

	// scoped（assignment 组 = DG1 且显式授权 DG1）：仅 DG1。
	rows, total, err = repo.ListAccessible(ctx, data.Scoped.Guid, GuidSet{Guids: []string{data.DG1.Guid}}, "", Query{})
	if err != nil {
		t.Fatalf("scoped accessible: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Guid != data.DG1.Guid {
		t.Fatalf("scoped accessible = %d rows, want DG1", total)
	}

	// 纯显式授权源（scope 空、但 device_group_user_permissions 命中）。
	rows, total, err = repo.ListAccessible(ctx, data.Scoped.Guid, GuidSet{}, "", Query{})
	if err != nil {
		t.Fatalf("explicit-only accessible: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Guid != data.DG1.Guid {
		t.Errorf("explicit-only = %d rows, want DG1 via dgup", total)
	}

	// name LIKE（SQLite/MySQL 默认大小写不敏感，用无歧义子串断言）。
	_, total, err = repo.ListAccessible(ctx, data.Admin.Guid, GuidSet{Global: true}, "Alp", Query{})
	if err != nil {
		t.Fatalf("name filter: %v", err)
	}
	if total != 1 {
		t.Errorf("name LIKE 'Alp' total = %d, want 1", total)
	}

	// 角色引用计数：assignment 组关联引用 DG1 一次。
	n, err := repo.CountRoleRefs(ctx, data.DG1.Guid)
	if err != nil {
		t.Fatalf("CountRoleRefs: %v", err)
	}
	if n != 1 {
		t.Errorf("CountRoleRefs(DG1) = %d, want 1", n)
	}
	n, err = repo.CountRoleRefs(ctx, data.DG2.Guid)
	if err != nil {
		t.Fatalf("CountRoleRefs(DG2): %v", err)
	}
	if n != 0 {
		t.Errorf("CountRoleRefs(DG2) = %d, want 0", n)
	}
}

// TestRoleRepoAndPermissions 角色 CI 查询、指派计数、权限码替换。
func TestRoleRepoAndPermissions(t *testing.T) {
	ctx, db, data := openM2(t)
	roles := NewRoleRepo(db)
	perms := NewRolePermissionRepo(db)

	r, err := roles.FindByNameCI(ctx, "DEVICE-OPERATOR")
	if err != nil {
		t.Fatalf("FindByNameCI: %v", err)
	}
	if r.Guid != data.RoleDev.Guid {
		t.Errorf("FindByNameCI guid = %s, want %s", r.Guid, data.RoleDev.Guid)
	}
	if _, err := roles.FindByNameCI(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing role err = %v, want ErrNotFound", err)
	}

	n, err := roles.CountAssignments(ctx, data.RoleDev.Guid)
	if err != nil {
		t.Fatalf("CountAssignments: %v", err)
	}
	if n != 1 {
		t.Errorf("CountAssignments = %d, want 1", n)
	}

	rows, total, err := roles.ListPaged(ctx, "view", "", Query{OrderBy: "name ASC"})
	if err != nil {
		t.Fatalf("ListPaged: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Guid != data.RoleGlobal.Guid {
		t.Errorf("ListPaged(name~view) = %d rows, want RoleGlobal", total)
	}

	codes, err := perms.CodesByRoles(ctx, []string{data.RoleDev.Guid, "missing-role"})
	if err != nil {
		t.Fatalf("CodesByRoles: %v", err)
	}
	if len(codes) != 1 || len(codes[data.RoleDev.Guid]) != 2 {
		t.Errorf("CodesByRoles = %v, want dev role with 2 codes", codes)
	}

	if err := perms.ReplaceForRole(ctx, data.RoleDev.Guid, []string{"devices.view"}); err != nil {
		t.Fatalf("ReplaceForRole: %v", err)
	}
	codes, err = perms.CodesByRoles(ctx, []string{data.RoleDev.Guid})
	if err != nil {
		t.Fatalf("CodesByRoles after: %v", err)
	}
	if len(codes[data.RoleDev.Guid]) != 1 || codes[data.RoleDev.Guid][0] != "devices.view" {
		t.Errorf("codes after replace = %v, want [devices.view]", codes)
	}
	if err := perms.DeleteByRole(ctx, data.RoleDev.Guid); err != nil {
		t.Fatalf("DeleteByRole: %v", err)
	}
	codes, err = perms.CodesByRoles(ctx, []string{data.RoleDev.Guid})
	if err != nil {
		t.Fatalf("CodesByRoles after delete: %v", err)
	}
	if len(codes) != 0 {
		t.Errorf("codes after delete = %v, want empty", codes)
	}
}

// TestAssignmentReplaceAll 指派全量重建（含组关联）与清空。
func TestAssignmentReplaceAll(t *testing.T) {
	ctx, db, data := openM2(t)
	assignments := NewAssignmentRepo(db)
	groups := NewAssignmentGroupRepo(db)

	rows, err := assignments.ListByUser(ctx, data.Scoped.Guid)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(rows) != 1 || rows[0].Guid != "seed-asg-dev" {
		t.Fatalf("initial assignments = %+v", rows)
	}
	seedGuids, err := groups.GroupsByAssignments(ctx, []string{"seed-asg-dev"})
	if err != nil {
		t.Fatalf("GroupsByAssignments: %v", err)
	}
	if len(seedGuids["seed-asg-dev"]) != 1 || seedGuids["seed-asg-dev"][0] != data.DG1.Guid {
		t.Fatalf("initial groups = %v", seedGuids)
	}

	// 全量替换为 global 指派（组关联清空）。
	repl := []AssignmentWithGroups{
		{Assignment: entity.UserRoleAssignment{Guid: "repl-asg-1", UserGuid: data.Scoped.Guid, RoleGuid: data.RoleGlobal.Guid, ScopeType: entity.ScopeTypeGlobal}},
	}
	if err := assignments.ReplaceAll(ctx, data.Scoped.Guid, repl); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	rows, err = assignments.ListByUser(ctx, data.Scoped.Guid)
	if err != nil {
		t.Fatalf("ListByUser after: %v", err)
	}
	if len(rows) != 1 || rows[0].Guid != "repl-asg-1" || rows[0].ScopeType != entity.ScopeTypeGlobal {
		t.Fatalf("after replace = %+v", rows)
	}
	seedGuids, err = groups.GroupsByAssignments(ctx, []string{"seed-asg-dev", "repl-asg-1"})
	if err != nil {
		t.Fatalf("GroupsByAssignments after: %v", err)
	}
	if len(seedGuids["seed-asg-dev"]) != 0 || len(seedGuids["repl-asg-1"]) != 0 {
		t.Errorf("groups after replace = %v, want stale purged", seedGuids)
	}

	// 清空。
	if err := assignments.ReplaceAll(ctx, data.Scoped.Guid, nil); err != nil {
		t.Fatalf("ReplaceAll(nil): %v", err)
	}
	rows, err = assignments.ListByUser(ctx, data.Scoped.Guid)
	if err != nil {
		t.Fatalf("ListByUser after purge: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("after purge = %+v, want empty", rows)
	}
}

// TestSysinfoUpsert 系统信息插入与全列覆盖。
func TestSysinfoUpsert(t *testing.T) {
	ctx, db, data := openM2(t)
	repo := NewSysinfoRepo(db)

	s, err := repo.FindByUUID(ctx, data.SysinfoA.UUID)
	if err != nil {
		t.Fatalf("FindByUUID: %v", err)
	}
	if s.Hostname != "alpha-host" || s.PresetUsername != "" {
		t.Fatalf("seed sysinfo = %+v", s)
	}

	// 全列覆盖（含 snake_case preset 列）。
	s.Hostname = "alpha-host-2"
	s.PresetUsername = "preset-u"
	s.PresetDeviceGroupName = "Alpha"
	if err := repo.Upsert(ctx, s); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	s2, err := repo.FindByUUID(ctx, data.SysinfoA.UUID)
	if err != nil {
		t.Fatalf("FindByUUID after: %v", err)
	}
	if s2.Hostname != "alpha-host-2" || s2.PresetUsername != "preset-u" || s2.PresetDeviceGroupName != "Alpha" {
		t.Errorf("after upsert = %+v", s2)
	}
}

// TestDeviceGroupPermissionReplace 组授权整删整插。
func TestDeviceGroupPermissionReplace(t *testing.T) {
	ctx, db, data := openM2(t)
	repo := NewDeviceGroupPermissionRepo(db)

	rows, err := repo.ListByUser(ctx, data.Scoped.Guid)
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(rows) != 1 || rows[0].DeviceGroupGuid != data.DG1.Guid {
		t.Fatalf("initial = %+v", rows)
	}

	if err := repo.ReplaceForGroup(ctx, data.DG2.Guid, []string{data.Scoped.Guid, data.Global.Guid}); err != nil {
		t.Fatalf("ReplaceForGroup: %v", err)
	}
	rows, err = repo.ListByUser(ctx, data.Scoped.Guid)
	if err != nil {
		t.Fatalf("ListByUser after: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("scoped rows = %d, want 2", len(rows))
	}

	// 清空 DG1 授权。
	if err := repo.ReplaceForGroup(ctx, data.DG1.Guid, nil); err != nil {
		t.Fatalf("ReplaceForGroup(DG1, nil): %v", err)
	}
	rows, err = repo.ListByUser(ctx, data.Scoped.Guid)
	if err != nil {
		t.Fatalf("ListByUser after purge: %v", err)
	}
	if len(rows) != 1 || rows[0].DeviceGroupGuid != data.DG2.Guid {
		t.Errorf("after purge = %+v, want DG2 only", rows)
	}
}

// TestConsoleAuditCreateAudit 审计适配写入（rbac.AuditStore 端口）。
func TestConsoleAuditCreateAudit(t *testing.T) {
	ctx, db, data := openM2(t)
	repo := NewConsoleAuditRepo(db)

	err := repo.CreateAudit(ctx, rbac.AuditRecord{
		ActorUserGuid: data.Admin.Guid,
		TargetType:    "route",
		Action:        "devices.view",
		Result:        rbac.AuditResultDenied,
		Reason:        "Access denied",
		BeforeState:   `{"a":1}`,
		AfterState:    `{"password":"x","note":"keep"}`,
		RequestID:     "req-1",
	})
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	var rows []entity.ConsoleAudit
	if err := db.WithContext(ctx).Find(&rows).Error; err != nil {
		t.Fatalf("read audits: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	row := rows[0]
	if row.ActorUserGuid == nil || *row.ActorUserGuid != data.Admin.Guid {
		t.Errorf("actor = %v", row.ActorUserGuid)
	}
	if row.Result != rbac.AuditResultDenied || row.RequestID != "req-1" ||
		row.BeforeState != `{"a":1}` || row.AfterState != `{"password":"x","note":"keep"}` {
		t.Errorf("audit row = %+v", row)
	}
	// 空 actor → NULL。
	if err := repo.CreateAudit(ctx, rbac.AuditRecord{TargetType: "route", Action: "a", Result: rbac.AuditResultAllowed}); err != nil {
		t.Fatalf("CreateAudit anonymous: %v", err)
	}
	var anon []entity.ConsoleAudit
	if err := db.WithContext(ctx).Where("actorUserGuid IS NULL").Find(&anon).Error; err != nil {
		t.Fatalf("read anon: %v", err)
	}
	if len(anon) != 1 {
		t.Errorf("anon rows = %d, want 1", len(anon))
	}
}

// uuidsOf 提取 uuid 列表（断言辅助）。
func uuidsOf(rows []entity.Peer) []string {
	out := make([]string, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].UUID)
	}
	return out
}

// idsOf 提取 id 列表（断言辅助）。
func idsOf(rows []entity.Peer) []string {
	out := make([]string, 0, len(rows))
	for i := range rows {
		out = append(out, rows[i].ID)
	}
	return out
}
