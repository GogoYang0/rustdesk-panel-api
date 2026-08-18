// Package testutil M3 fixture（seed_m3）：邀请/被邀请人、ab 三态
// （personal/custom/shared + peers/tags/关联/规则三档）、audit 样本行
// （conn 状态机五态/file/alarm）、nexus build/token（设计 §2
// testutil/seed 注记）。基于 SeedM2 复合铺设，供 T02+ 仓储/契约测试
// 复用；nexus 假上游（httptest）与 settings KV 随 T05/T07 任务补齐。
package testutil

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// SeedM3Data M3 fixture 句柄。
type SeedM3Data struct {
	*SeedM2Data // 复用 M2 用户/设备/组基座

	UserPending *entity.User // 邀请产生的 UNVERIFIED 用户（status=-1）

	InvitationPending *entity.Invitation // 未接受（expiresAt=+7d）
	InvitationUsed    *entity.Invitation // 已接受（usedAt=-24h）

	BookPersonal *entity.AddressBook // Owner 的个人书（name=Personal）
	BookCustom   *entity.AddressBook // Owner 的自定义书（无规则）
	BookShared   *entity.AddressBook // Admin 的共享书（规则三档）

	PeerAB1 *entity.AddressBookPeer // Personal 内（deviceId=PeerA.ID）
	PeerAB2 *entity.AddressBookPeer // Shared 内（deviceId=PeerB.ID）

	TagWork *entity.AddressBookTag // Personal 内标签（color ARGB）
	TagHome *entity.AddressBookTag // Shared 内标签

	RuleUser     *entity.AddressBookRule // Shared→scoped READ(1)
	RuleGroup    *entity.AddressBookRule // Shared→组 seed-ug-1 FULL_CONTROL(3)
	RuleEveryone *entity.AddressBookRule // Shared→everyone(双空) RW(2)

	ConnNew    *entity.ConnectionAudit // action=new（未迁移）
	ConnOpen   *entity.ConnectionAudit // action=open
	ConnActive *entity.ConnectionAudit // established 未关闭（active）
	ConnClosed *entity.ConnectionAudit // established 已关闭（success 口径）
	ConnFailed *entity.ConnectionAudit // closed 未 established（failure 口径）

	FileA1  *entity.FileAudit  // 带 nonce 样本
	AlarmA1 *entity.AlarmAudit // 带 nonce 样本

	Build1      *entity.NexusBuild // pending（轮询窗口内）
	TokenScoped *entity.NexusToken // Scoped 的绑定态
}

// SeedM3 铺设 M3 fixture（先执行 SeedM2；GUID 为可读 seed-* 前缀，
// 生产 GUID 由服务层生成 uuid v4）。
func SeedM3(t *testing.T, db *gorm.DB) *SeedM3Data {
	t.Helper()
	base := SeedM2(t, db)
	ctx := context.Background()
	now := time.Now()

	// ---- 邀请域 ----
	userPending := &entity.User{
		Guid: "seed-user-pending", Username: "seed-pending",
		Email: "seed-pending@example.com", Password: "", Status: -1,
		CreatedAt: now, UpdatedAt: now,
	}
	invPending := &entity.Invitation{
		Guid: "seed-inv-pending", Token: "seed-inv-token-pending-0123456789abcdef",
		Email: "pending@example.com", Name: "Pending",
		UserGuid:  &userPending.Guid,
		ExpiresAt: now.Add(7 * 24 * time.Hour), CreatedAt: now,
	}
	usedAt := now.Add(-24 * time.Hour)
	invUsed := &entity.Invitation{
		Guid: "seed-inv-used", Token: "seed-inv-token-used-0123456789abcdef",
		Email: "scoped@example.com", Name: "Scoped",
		UserGuid:  &base.Scoped.Guid,
		ExpiresAt: now.Add(6 * 24 * time.Hour), UsedAt: &usedAt,
		CreatedAt: now.Add(-8 * 24 * time.Hour),
	}

	// ---- 地址簿三态 ----
	bookPersonal := &entity.AddressBook{
		Guid: "seed-ab-personal", Owner: base.Owner.Guid, IsPersonal: true,
		Name: "Personal", CreatedAt: now, UpdatedAt: now,
	}
	bookCustom := &entity.AddressBook{
		Guid: "seed-ab-custom", Owner: base.Owner.Guid,
		Name: "Custom", Note: "custom sample", CreatedAt: now, UpdatedAt: now,
	}
	bookShared := &entity.AddressBook{
		Guid: "seed-ab-shared", Owner: base.Admin.Guid, IsShared: true,
		Name: "Team", CreatedAt: now, UpdatedAt: now,
	}

	peerAB1 := &entity.AddressBookPeer{
		Guid: "seed-abp-1", AddressBookGuid: bookPersonal.Guid,
		DeviceId: base.PeerA.ID, Alias: strPtr("alpha alias"),
		Password: strPtr("ab-pass-1"), CreatedAt: now, UpdatedAt: now,
	}
	peerAB2 := &entity.AddressBookPeer{
		Guid: "seed-abp-2", AddressBookGuid: bookShared.Guid,
		DeviceId: base.PeerB.ID, CreatedAt: now, UpdatedAt: now,
	}

	tagWork := &entity.AddressBookTag{
		Guid: "seed-abt-work", AddressBookGuid: bookPersonal.Guid,
		Name: "work", Color: 0xFF0000FF, CreatedAt: now,
	}
	tagHome := &entity.AddressBookTag{
		Guid: "seed-abt-home", AddressBookGuid: bookShared.Guid,
		Name: "home", CreatedAt: now,
	}
	peerTag := &entity.AddressBookPeerTag{
		PeerGuid: peerAB1.Guid, TagGuid: tagWork.Guid, CreatedAt: now,
	}

	// ---- 规则三档（scoped 视角并集 = MAX(1,3,2) = 3）----
	ruleUser := &entity.AddressBookRule{
		Guid: "seed-abr-user", AddressBookGuid: bookShared.Guid,
		TargetUserId: &base.Scoped.Guid, Rule: entity.ShareRuleRead, CreatedAt: now,
	}
	ruleGroup := &entity.AddressBookRule{
		Guid: "seed-abr-group", AddressBookGuid: bookShared.Guid,
		TargetGroupId: strPtr("seed-ug-1"), Rule: entity.ShareRuleFullControl, CreatedAt: now,
	}
	ruleEveryone := &entity.AddressBookRule{
		Guid: "seed-abr-every", AddressBookGuid: bookShared.Guid,
		Rule: entity.ShareRuleReadWrite, CreatedAt: now,
	}

	// ---- 连接审计状态机五态 ----
	uidA := base.PeerA.UUID
	idA := base.PeerA.ID
	auditNow := now
	connNew := &entity.ConnectionAudit{
		DeviceId: idA, DeviceUuid: &uidA, ConnId: strPtr("seed-c1"),
		Ip: strPtr("10.0.0.1"), Action: entity.ConnActionNew,
		RequestedAt: auditNow.Add(-1 * time.Hour),
	}
	connOpen := &entity.ConnectionAudit{
		DeviceId: idA, DeviceUuid: &uidA, ConnId: strPtr("seed-c2"),
		Action: entity.ConnActionOpen, RequestedAt: auditNow.Add(-50 * time.Minute),
	}
	connActive := &entity.ConnectionAudit{
		DeviceId: idA, DeviceUuid: &uidA, ConnId: strPtr("seed-c3"),
		Action:      entity.ConnActionEstablished,
		RequestedAt: auditNow.Add(-31 * time.Minute), EstablishedAt: ptrTime(auditNow.Add(-30 * time.Minute)),
	}
	connClosed := &entity.ConnectionAudit{
		DeviceId: idA, DeviceUuid: &uidA, ConnId: strPtr("seed-c4"),
		Action:      entity.ConnActionEstablished,
		RequestedAt: auditNow.Add(-125 * time.Minute), EstablishedAt: ptrTime(auditNow.Add(-2 * time.Hour)),
		ClosedAt: ptrTime(auditNow.Add(-1 * time.Hour)),
	}
	connFailed := &entity.ConnectionAudit{
		DeviceId: idA, DeviceUuid: &uidA, ConnId: strPtr("seed-c5"),
		Action:      entity.ConnActionNew,
		RequestedAt: auditNow.Add(-55 * time.Minute), ClosedAt: ptrTime(auditNow.Add(-50 * time.Minute)),
	}

	// ---- file/alarm 审计样本 ----
	fileA1 := &entity.FileAudit{
		DeviceId: idA, DeviceUuid: uidA, PeerId: idA,
		ConnId: strPtr("seed-c3"), IsFile: true, FileCount: 2,
		Files: `["a.txt","b.txt"]`, Nonce: strPtr("seed-file-nonce-1"),
		RequestedAt: auditNow.Add(-10 * time.Minute), CreatedAt: auditNow,
	}
	alarmA1 := &entity.AlarmAudit{
		DeviceId: idA, DeviceUuid: uidA, Typ: 1,
		InfoName: strPtr("rustdesk alarm"), Nonce: strPtr("seed-alarm-nonce-1"),
		CreatedAt: auditNow.Add(-5 * time.Minute),
	}

	// ---- nexus ----
	build1 := &entity.NexusBuild{
		Uuid: "seed-build-1", UserGuid: base.Scoped.Guid,
		Os: "windows", Arch: "x64", Status: entity.NexusStatusPending,
		CreatedAt: auditNow.Add(-5 * time.Minute),
	}
	tokenScoped := &entity.NexusToken{
		UserGuid: base.Scoped.Guid, NexusToken: "seed-nexus-token",
		ExpiresAt: now.Add(30 * 24 * time.Hour), CreatedAt: now, UpdatedAt: now,
	}

	// ---- 铺库（audit 表 id 自增，无跨表依赖顺序约束）----
	rows := []any{
		userPending, invPending, invUsed,
		bookPersonal, bookCustom, bookShared,
		peerAB1, peerAB2, tagWork, tagHome, peerTag,
		ruleUser, ruleGroup, ruleEveryone,
		connNew, connOpen, connActive, connClosed, connFailed,
		fileA1, alarmA1, build1, tokenScoped,
	}
	for _, row := range rows {
		if err := db.WithContext(ctx).Create(row).Error; err != nil {
			t.Fatalf("testutil: seed m3 create %T failed: %v", row, err)
		}
	}

	return &SeedM3Data{
		SeedM2Data:        base,
		UserPending:       userPending,
		InvitationPending: invPending, InvitationUsed: invUsed,
		BookPersonal: bookPersonal, BookCustom: bookCustom, BookShared: bookShared,
		PeerAB1: peerAB1, PeerAB2: peerAB2,
		TagWork: tagWork, TagHome: tagHome,
		RuleUser: ruleUser, RuleGroup: ruleGroup, RuleEveryone: ruleEveryone,
		ConnNew: connNew, ConnOpen: connOpen, ConnActive: connActive,
		ConnClosed: connClosed, ConnFailed: connFailed,
		FileA1: fileA1, AlarmA1: alarmA1,
		Build1: build1, TokenScoped: tokenScoped,
	}
}

// strPtr 字符串指针便捷函数（fixture 可空列）。
func strPtr(s string) *string { return &s }

// ptrTime 时间指针便捷函数（fixture 可空时间列）。
func ptrTime(t time.Time) *time.Time { return &t }
