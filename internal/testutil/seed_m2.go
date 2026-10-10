// Package testutil M2 fixture（seed_m2）：角色+授权、设备组、
// peer/sysinfo 样本、assignment 与连接前置态（设计 §2 testutil/seed
// 注记）。供 T02+ 仓储/授权/契约测试复用；各测试取回句柄按需断言。
package testutil

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/migration"
)

// SeedM2Data M2 fixture 句柄。
type SeedM2Data struct {
	Admin    *entity.User // 超管（isAdmin=1，ACTIVE）
	Scoped   *entity.User // 持 RoleDev：devices.view+devices.disconnect @ DG1
	Global   *entity.User // 持 RoleGlobal：devices.view（global）
	Disabled *entity.User // status=0（被禁用户）
	Owner    *entity.User // 持保护角色 RoleProt（protectedAccount=true）

	RoleDev    *entity.Role // device_group 档样本角色
	RoleGlobal *entity.Role // global 档样本角色
	RoleProt   *entity.Role // 保护角色（protectedAccount=true）

	StrategyS *entity.Strategy    // 样本策略（DG1 引用、PeerA 直挂）
	DG1       *entity.DeviceGroup // 授权给 Scoped 的设备组
	DG2       *entity.DeviceGroup // scope 外设备组

	PeerA *entity.Peer // DG1 内、Scoped 名下、在线、连有 conn 11/12
	PeerB *entity.Peer // 未分组、Global 名下
	PeerC *entity.Peer // DG2 内、Owner 名下、离线（24h 前心跳）

	SysinfoA *entity.Sysinfo // PeerA 的系统信息
	SysinfoB *entity.Sysinfo // PeerB 的系统信息

	Now time.Time // fixture 铺设时刻（is_online 断言参考）
}

// MigrateUpForTest 执行全部迁移（内存库构造后调用一次）。
func MigrateUpForTest(t *testing.T, db *gorm.DB) {
	t.Helper()
	m, err := migration.New(db, "sqlite")
	if err != nil {
		t.Fatalf("testutil: migration.New failed: %v", err)
	}
	if err := m.Up(); err != nil {
		t.Fatalf("testutil: migration.Up failed: %v", err)
	}
}

// SeedM2 铺设 M2 fixture（先执行迁移）。GUID 为可读 seed-* 前缀
// （测试专用，生产 GUID=uuid v4 由服务层生成）。
func SeedM2(t *testing.T, db *gorm.DB) *SeedM2Data {
	t.Helper()
	MigrateUpForTest(t, db)

	ctx := context.Background()
	now := time.Now()
	heartbeat := now.Add(-10 * time.Second) // PeerA 在线窗口内
	offline := now.Add(-24 * time.Hour)     // PeerC 远超在线窗口

	// ---- 角色 ----
	roleDev := &entity.Role{Guid: "seed-role-dev", Name: "device-operator", Note: "scoped sample", CreatedAt: now, UpdatedAt: now}
	roleGlobal := &entity.Role{Guid: "seed-role-global", Name: "device-viewer-global", CreatedAt: now, UpdatedAt: now}
	roleProt := &entity.Role{Guid: "seed-role-prot", Name: "protected-role", ProtectedAccount: true, CreatedAt: now, UpdatedAt: now}
	perms := []*entity.RolePermission{
		{RoleGuid: roleDev.Guid, PermissionCode: "devices.view"},
		{RoleGuid: roleDev.Guid, PermissionCode: "devices.disconnect"},
		{RoleGuid: roleGlobal.Guid, PermissionCode: "devices.view"},
		{RoleGuid: roleProt.Guid, PermissionCode: "users.view"},
	}

	// ---- 用户 ----
	// email 必须唯一（UQ_users_email；空串非 NULL 会互相冲突），
	// oidcSubject 为指针零值 NULL 不受唯一索引影响。
	// 兼容 apptest 全栈场景：database.Seed 已产生唯一超管
	// （UQ_users_single_owner：isAdmin=1 部分唯一索引，全库至多一行），
	// 此时复用既有超管（databk）而非新建 seed-user-admin；全新库
	// （仓储级测试）则照常创建。
	admin := &entity.User{Guid: "seed-user-admin", Username: "seed-admin", Email: "seed-admin@example.com", Status: 1, IsAdmin: true, CreatedAt: now, UpdatedAt: now}
	var existingAdmin entity.User
	if err := db.WithContext(ctx).Where("isAdmin = ?", true).First(&existingAdmin).Error; err == nil {
		admin = &existingAdmin
	}
	scoped := &entity.User{Guid: "seed-user-scoped", Username: "scoped", Email: "seed-scoped@example.com", Status: 1, CreatedAt: now, UpdatedAt: now}
	global := &entity.User{Guid: "seed-user-global", Username: "global", Email: "seed-global@example.com", Status: 1, CreatedAt: now, UpdatedAt: now}
	disabled := &entity.User{Guid: "seed-user-disabled", Username: "disabled", Email: "seed-disabled@example.com", Status: 0, CreatedAt: now, UpdatedAt: now}
	owner := &entity.User{Guid: "seed-user-owner", Username: "owner", Email: "seed-owner@example.com", Status: 1, CreatedAt: now, UpdatedAt: now}

	// ---- 指派（scoped@DG1 / global / owner 保护角色）----
	asgDev := &entity.UserRoleAssignment{Guid: "seed-asg-dev", UserGuid: scoped.Guid, RoleGuid: roleDev.Guid, ScopeType: entity.ScopeTypeDeviceGroup, CreatedAt: now, UpdatedAt: now}
	asgGlobal := &entity.UserRoleAssignment{Guid: "seed-asg-global", UserGuid: global.Guid, RoleGuid: roleGlobal.Guid, ScopeType: entity.ScopeTypeGlobal, CreatedAt: now, UpdatedAt: now}
	asgProt := &entity.UserRoleAssignment{Guid: "seed-asg-prot", UserGuid: owner.Guid, RoleGuid: roleProt.Guid, ScopeType: entity.ScopeTypeGlobal, CreatedAt: now, UpdatedAt: now}
	asgGroups := []*entity.UserRoleAssignmentDeviceGroup{
		{AssignmentGuid: asgDev.Guid, DeviceGroupGuid: "seed-dg-1"},
	}

	// ---- 组显式授权 / 用户间授权（/peers 三源的另外两源）----
	dgPerm := &entity.DeviceGroupUserPermission{DeviceGroupGuid: "seed-dg-1", UserGuid: scoped.Guid, CreatedAt: now}
	uup := &entity.UserUserPermission{UserGuid: owner.Guid, TargetUserGuid: scoped.Guid, CreatedAt: now}

	// ---- 策略与设备组 ----
	strat := &entity.Strategy{Guid: "seed-strategy-1", Name: "sample-strategy", ConfigOptions: `{"allow_log_anonymous":true}`, CreatedAt: now, UpdatedAt: now}
	dg1 := &entity.DeviceGroup{Guid: "seed-dg-1", Name: "Alpha", StrategyGuid: &strat.Guid, CreatedAt: now, UpdatedAt: now}
	dg2 := &entity.DeviceGroup{Guid: "seed-dg-2", Name: "Beta", CreatedAt: now, UpdatedAt: now}

	// ---- 设备（peers）----
	peerA := &entity.Peer{UUID: "seed-peer-a", ID: "1000001", UserGuid: &scoped.Guid, DeviceGroupGuid: &dg1.Guid, StrategyGuid: &strat.Guid, Status: 1, Ver: 1001000, ModifiedAt: now.UnixMilli(), LastHeartbeat: &heartbeat, CreatedAt: now, UpdatedAt: now}
	peerB := &entity.Peer{UUID: "seed-peer-b", ID: "1000002", UserGuid: &global.Guid, Status: 1, Ver: 1001001, ModifiedAt: now.UnixMilli(), LastHeartbeat: &heartbeat, CreatedAt: now, UpdatedAt: now}
	peerC := &entity.Peer{UUID: "seed-peer-c", ID: "1000003", UserGuid: &owner.Guid, DeviceGroupGuid: &dg2.Guid, Status: 1, LastHeartbeat: &offline, CreatedAt: now, UpdatedAt: now}

	// ---- 系统信息 / 活跃连接 ----
	sysA := &entity.Sysinfo{UUID: peerA.UUID, Hostname: "alpha-host", Username: "alpha-user", OS: "windows 11", CPU: "x86", Memory: "16GB", CreatedAt: now, UpdatedAt: now}
	sysB := &entity.Sysinfo{UUID: peerB.UUID, Hostname: "beta-host", Username: "beta-user", OS: "linux", CPU: "arm64", Memory: "8GB", CreatedAt: now, UpdatedAt: now}
	conns := []entity.ActiveConnection{
		{ConnID: 11, DeviceUuid: peerA.UUID, CreatedAt: now},
		{ConnID: 12, DeviceUuid: peerA.UUID, CreatedAt: now},
	}

	// ---- 铺库（外键生效：先被引用后引用；复用超管时跳过 admin 行）----
	rows := []any{roleDev, roleGlobal, roleProt}
	if admin.Guid == "seed-user-admin" {
		rows = append(rows, admin)
	}
	rows = append(rows, scoped, global, disabled, owner,
		strat, dg1, dg2,
		asgDev, asgGlobal, asgProt,
		perms[0], perms[1], perms[2], perms[3],
		asgGroups[0],
		dgPerm, uup,
		peerA, peerB, peerC,
		sysA, sysB,
		&conns[0], &conns[1])
	for _, row := range rows {
		if err := db.WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("testutil: seed m2 create %T failed: %v", row, err)
		}
	}

	return &SeedM2Data{
		Admin: admin, Scoped: scoped, Global: global, Disabled: disabled, Owner: owner,
		RoleDev: roleDev, RoleGlobal: roleGlobal, RoleProt: roleProt,
		StrategyS: strat, DG1: dg1, DG2: dg2,
		PeerA: peerA, PeerB: peerB, PeerC: peerC,
		SysinfoA: sysA, SysinfoB: sysB,
		Now: now,
	}
}
