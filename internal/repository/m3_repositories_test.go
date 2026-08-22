// Package repository M3 仓储行为测试：conn upsert 状态机、file/alarm
// nonce 幂等（冲突重查）、邀请 token、ab 规则并集 MAX / 级联删除、
// nexus 轮询窗口、settings KV。全部基于内存 SQLite + 真实迁移。
package repository

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// openM3Empty 迁移就绪的空内存库（自建小 fixture 的测试用）。
func openM3Empty(t *testing.T) (context.Context, *gorm.DB) {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	testutil.MigrateUpForTest(t, db)
	return context.Background(), db
}

// openM3 迁移 + M3 fixture 就绪的内存库。
func openM3(t *testing.T) (context.Context, *gorm.DB, *testutil.SeedM3Data) {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	data := testutil.SeedM3(t, db)
	return context.Background(), db, data
}

// TestConnectionAuditUpsertConnActionMachine 设计事实② 状态机逐态锁定：
// 首报落 'new' → 报文 'new' 迁移 'open' → 报文 ” 迁移 'established'
// +establishedAt → 重放幂等；不同 connId 独立成行。
func TestConnectionAuditUpsertConnActionMachine(t *testing.T) {
	ctx, db := openM3Empty(t)
	repo := NewConnectionAuditRepo(db)
	now := time.Now()

	uid, cid := "uuid-machine", "conn-1"
	report := &entity.ConnectionAudit{
		DeviceId: "dev-machine", DeviceUuid: &uid, ConnId: &cid,
		Ip: strRepoPtr("10.1.1.1"), Action: entity.ConnActionNew,
		RequestedAt: now,
	}

	// ① 首报：INSERT，action 恒落 'new'（不采信报文值）。
	row, created, err := repo.UpsertConn(ctx, report)
	if err != nil || !created {
		t.Fatalf("first report: created=%v err=%v", created, err)
	}
	if row.Action != entity.ConnActionNew {
		t.Errorf("first action = %q, want new", row.Action)
	}

	// ② 报文 action='new'：行迁移 'open'。
	report.Action = entity.ConnActionNew
	row, created, err = repo.UpsertConn(ctx, report)
	if err != nil || created {
		t.Fatalf("second report: created=%v err=%v", created, err)
	}
	if row.Action != entity.ConnActionOpen {
		t.Errorf("second action = %q, want open", row.Action)
	}

	// ③ 报文 action=''：迁移 'established' + establishedAt。
	report.Action = ""
	row, created, err = repo.UpsertConn(ctx, report)
	if err != nil || created {
		t.Fatalf("third report: created=%v err=%v", created, err)
	}
	if row.Action != entity.ConnActionEstablished {
		t.Errorf("third action = %q, want established", row.Action)
	}
	if row.EstablishedAt == nil {
		t.Error("establishedAt not set on '' transition")
	}

	// ④ 重放：established 行无操作（establishedAt 不被改写）。
	report.Action = ""
	again, _, err := repo.UpsertConn(ctx, report)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !again.EstablishedAt.Equal(*row.EstablishedAt) {
		t.Errorf("replay changed establishedAt: %v -> %v", row.EstablishedAt, again.EstablishedAt)
	}

	// ⑤ 不同 connId：独立成行。
	cid2 := "conn-2"
	row2, created, err := repo.UpsertConn(ctx, &entity.ConnectionAudit{
		DeviceId: "dev-machine", DeviceUuid: &uid, ConnId: &cid2, RequestedAt: now,
	})
	if err != nil || !created || row2.Action != entity.ConnActionNew {
		t.Fatalf("second conn: created=%v action=%q err=%v", created, row2.Action, err)
	}

	// ⑥ 同 deviceId 不同 deviceUuid：独立成行（定位键三列）。
	uid2 := "uuid-machine-2"
	row3, created, err := repo.UpsertConn(ctx, &entity.ConnectionAudit{
		DeviceId: "dev-machine", DeviceUuid: &uid2, ConnId: &cid, RequestedAt: now,
	})
	if err != nil || !created {
		t.Fatalf("second uuid: created=%v err=%v", created, err)
	}
	if row3.Id == row.Id {
		t.Error("different deviceUuid should create separate row")
	}
}

// TestConnectionAuditNoteOnlySession note-only 上报定位（无 uuid 有
// session_id；设计事实②：服务层据此 404 或更新）。
func TestConnectionAuditNoteOnlySession(t *testing.T) {
	ctx, db := openM3Empty(t)
	repo := NewConnectionAuditRepo(db)
	now := time.Now()

	sid := "sess-42"
	if _, _, err := repo.UpsertConn(ctx, &entity.ConnectionAudit{
		DeviceId: "dev-note", ConnId: strRepoPtr("conn-n"), SessionId: &sid,
		RequestedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	row, err := repo.FindBySession(ctx, "dev-note", "sess-42")
	if err != nil {
		t.Fatalf("FindBySession: %v", err)
	}
	if row.SessionId == nil || *row.SessionId != sid {
		t.Errorf("session mismatch: %+v", row)
	}
	if _, err := repo.FindBySession(ctx, "dev-note", "missing"); err != ErrNotFound {
		t.Errorf("missing session err = %v, want ErrNotFound", err)
	}
}

// TestAuditUpsertByNonce file/alarm 幂等键：冲突重查返回既有行
// （created=false），nonce 为 NULL 恒新建（唯一索引多 NULL 不冲突）。
func TestAuditUpsertByNonce(t *testing.T) {
	ctx, db := openM3Empty(t)
	files := NewFileAuditRepo(db)
	alarms := NewAlarmAuditRepo(db)
	now := time.Now()

	// ---- file：nonce 冲突重查 ----
	first := &entity.FileAudit{
		DeviceId: "dev-f", DeviceUuid: "uuid-f", PeerId: "900001",
		IsFile: true, FileCount: 1, Files: `["x.txt"]`,
		Nonce: strRepoPtr("nonce-f1"), RequestedAt: now, CreatedAt: now,
	}
	got, created, err := files.UpsertByNonce(ctx, first)
	if err != nil || !created {
		t.Fatalf("file first: created=%v err=%v", created, err)
	}
	replay := &entity.FileAudit{
		DeviceId: "dev-f", DeviceUuid: "uuid-f", PeerId: "900001",
		FileCount: 99, Nonce: strRepoPtr("nonce-f1"), // 改字段模拟重放
		RequestedAt: now, CreatedAt: now,
	}
	got2, created2, err := files.UpsertByNonce(ctx, replay)
	if err != nil {
		t.Fatalf("file replay: %v", err)
	}
	if created2 {
		t.Error("file replay should not create new row")
	}
	if got2.Id != got.Id || got2.FileCount != 1 {
		t.Errorf("file replay should return original row, got id=%d count=%d", got2.Id, got2.FileCount)
	}

	// ---- file：nonce NULL 恒新建 ----
	for i := 0; i < 2; i++ {
		_, created, err := files.UpsertByNonce(ctx, &entity.FileAudit{
			DeviceId: "dev-f", DeviceUuid: "uuid-f", PeerId: "900001",
			RequestedAt: now, CreatedAt: now, // Nonce=nil
		})
		if err != nil || !created {
			t.Fatalf("file nil-nonce #%d: created=%v err=%v", i, created, err)
		}
	}

	// ---- alarm：同语义 ----
	alarmFirst := &entity.AlarmAudit{
		DeviceId: "dev-a", DeviceUuid: "uuid-a", Typ: 1,
		Nonce: strRepoPtr("nonce-a1"), CreatedAt: now,
	}
	gotA0, created, err := alarms.UpsertByNonce(ctx, alarmFirst)
	if err != nil || !created {
		t.Fatalf("alarm first: created=%v err=%v", created, err)
	}
	gotA, createdA, errA := alarms.UpsertByNonce(ctx, &entity.AlarmAudit{
		DeviceId: "dev-a", DeviceUuid: "uuid-a", Typ: 2,
		Nonce: strRepoPtr("nonce-a1"), CreatedAt: now,
	})
	if errA != nil || createdA {
		t.Fatalf("alarm replay: created=%v err=%v", createdA, errA)
	}
	if gotA.Id != gotA0.Id || gotA.Typ != 1 {
		t.Errorf("alarm replay should return original row, got id=%d typ=%d", gotA.Id, gotA0.Id)
	}
}

// TestAuditCountByDay 按日聚合（DATE() 锚点双方言口径；空日不产生行，
// 补零由服务层组装）。
func TestAuditCountByDay(t *testing.T) {
	ctx, db := openM3Empty(t)
	repo := NewConnectionAuditRepo(db)
	now := time.Now()
	// 聚合锚点为 UTC 日界：glebarez 将 time.Time 以 UTC 文本落库，
	// DATE() 解析 UTC 串；MySQL 侧 DSN 默认 loc=UTC 同口径（双方言一致）。
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)

	// 三行：今晨 01:00、今晨 02:00（同日合并）、昨日 23:00（不计入窗口）。
	for _, at := range []time.Time{today.Add(time.Hour), today.Add(2 * time.Hour), today.Add(-time.Hour)} {
		if err := repo.Create(ctx, &entity.ConnectionAudit{
			DeviceId: "dev-day", RequestedAt: at, Action: entity.ConnActionNew,
		}); err != nil {
			t.Fatalf("seed %v: %v", at, err)
		}
	}
	rows, err := repo.CountByDay(ctx, today, today.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CountByDay: %v", err)
	}
	if len(rows) != 1 || rows[0].Count != 2 {
		t.Fatalf("rows = %+v, want single day count=2", rows)
	}
	if want := today.Format("2006-01-02"); rows[0].Date != want {
		t.Errorf("date = %q, want %q", rows[0].Date, want)
	}

	// 起点前移覆盖昨日行。
	rows, err = repo.CountByDay(ctx, today.Add(-24*time.Hour), today.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CountByDay wide: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("wide rows = %+v, want 2 days", rows)
	}
}

// TestInvitationRepoToken token 查询 + MarkUsed（verify/accept 底座）。
func TestInvitationRepoToken(t *testing.T) {
	ctx, db, data := openM3(t)
	repo := NewInvitationRepo(db)

	inv, err := repo.FindByToken(ctx, data.InvitationPending.Token)
	if err != nil {
		t.Fatalf("FindByToken: %v", err)
	}
	if inv.Guid != data.InvitationPending.Guid || inv.IsUsed() || inv.IsExpired(data.Now) {
		t.Errorf("pending invitation mismatch: %+v", inv)
	}
	if _, err := repo.FindByToken(ctx, "no-such-token"); err != ErrNotFound {
		t.Errorf("missing token err = %v, want ErrNotFound", err)
	}

	usedAt := time.Now()
	if err := repo.MarkUsedTx(db, data.InvitationPending.Guid, usedAt); err != nil {
		t.Fatalf("MarkUsedTx: %v", err)
	}
	inv, err = repo.FindByToken(ctx, data.InvitationPending.Token)
	if err != nil {
		t.Fatalf("FindByToken after: %v", err)
	}
	if !inv.IsUsed() || inv.UsedAt == nil {
		t.Errorf("invitation not marked used: %+v", inv)
	}
}

// TestAddressBookListAccessibleUnionMax 规则可见性 + 并集取最大
// （设计事实⑦）：owner 全见、规则命中（user/group/everyone 三源）
// 并集 MAX=3、无规则无归属不可见。owner 的 FULL_CONTROL 响应行提升
// 由服务层叠加（仓储输出规则侧原值）。
func TestAddressBookListAccessibleUnionMax(t *testing.T) {
	ctx, db, data := openM3(t)
	repo := NewAddressBookRepo(db)

	// scoped：Shared 命中三源规则（user=1 / group=3 / everyone=2）→ MAX=3。
	rows, _, err := repo.ListAccessible(ctx, data.Scoped.Guid, []string{"seed-ug-1"}, AddressBookFilter{})
	if err != nil {
		t.Fatalf("scoped ListAccessible: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("scoped rows = %d, want 1 (shared only)", len(rows))
	}
	if rows[0].EffectiveRule != entity.ShareRuleFullControl {
		t.Errorf("scoped effectiveRule = %d, want %d (MAX(1,3,2))", rows[0].EffectiveRule, entity.ShareRuleFullControl)
	}
	if rows[0].Guid != data.BookShared.Guid {
		t.Errorf("row guid = %q, want shared book", rows[0].Guid)
	}

	// owner：自有两本（规则侧原值 0，服务层提升 FULL_CONTROL）
	// + Shared 经 everyone 规则命中（rule=2）。
	rows, total, err := repo.ListAccessible(ctx, data.Owner.Guid, nil, AddressBookFilter{})
	if err != nil {
		t.Fatalf("owner ListAccessible: %v", err)
	}
	if total != 3 || len(rows) != 3 {
		t.Fatalf("owner rows = %d/%d, want 3/3", len(rows), total)
	}
	for _, row := range rows {
		want := 0
		if row.Guid == data.BookShared.Guid {
			want = entity.ShareRuleReadWrite
		}
		if row.EffectiveRule != want {
			t.Errorf("book %s effectiveRule = %d, want %d", row.Guid, row.EffectiveRule, want)
		}
	}

	// global（无归属无规则）：仅 everyone 命中 Shared（组集为空不影响 everyone 源）。
	rows, _, err = repo.ListAccessible(ctx, data.Global.Guid, nil, AddressBookFilter{})
	if err != nil {
		t.Fatalf("global ListAccessible: %v", err)
	}
	if len(rows) != 1 || rows[0].EffectiveRule != entity.ShareRuleReadWrite {
		t.Fatalf("global rows = %+v, want shared@%d", rows, entity.ShareRuleReadWrite)
	}

	// name 过滤（PaginationDto.name LIKE）。
	rows, _, err = repo.ListAccessible(ctx, data.Owner.Guid, nil, AddressBookFilter{Name: "usto"})
	if err != nil {
		t.Fatalf("owner filter: %v", err)
	}
	if len(rows) != 1 || rows[0].Name != "Custom" {
		t.Fatalf("owner filter rows = %+v, want Custom", rows)
	}
}

// TestAddressBookDeleteCascade 级联删除（事务显式，共享知识 9）：
// 书删后 peers/peer_tags/tags/rules 全清，其余书不受影响。
func TestAddressBookDeleteCascade(t *testing.T) {
	ctx, db, data := openM3(t)
	repo := NewAddressBookRepo(db)

	if err := repo.DeleteCascade(ctx, data.BookShared.Guid); err != nil {
		t.Fatalf("DeleteCascade: %v", err)
	}
	assertCount(t, db, "address_books", "guid = ?", data.BookShared.Guid, 0)
	assertCount(t, db, "address_book_peers", "addressBookGuid = ?", data.BookShared.Guid, 0)
	assertCount(t, db, "address_book_peer_tags", "tagGuid = ?", data.TagHome.Guid, 0)
	assertCount(t, db, "address_book_tags", "addressBookGuid = ?", data.BookShared.Guid, 0)
	assertCount(t, db, "address_book_rules", "addressBookGuid = ?", data.BookShared.Guid, 0)

	// Personal 不受影响。
	assertCount(t, db, "address_books", "guid = ?", data.BookPersonal.Guid, 1)
	assertCount(t, db, "address_book_peers", "guid = ?", data.PeerAB1.Guid, 1)
}

// TestAddressBookPeerFindOrCreateList findOrCreate 幂等 + Upsert 更新
// 语义 + 标签双模式过滤（union/intersection 关系除法）。
func TestAddressBookPeerFindOrCreateList(t *testing.T) {
	ctx, db, data := openM3(t)
	repo := NewAddressBookPeerRepo(db)

	// findOrCreate：命中既有（seed）。
	got, err := repo.FindOrCreate(ctx, data.BookPersonal.Guid, data.PeerA.ID)
	if err != nil || got.Guid != data.PeerAB1.Guid {
		t.Fatalf("FindOrCreate existing: %+v err=%v", got, err)
	}
	// findOrCreate：新建。
	fresh, err := repo.FindOrCreate(ctx, data.BookPersonal.Guid, "9999999")
	if err != nil || fresh.Guid == "" || fresh.DeviceId != "9999999" {
		t.Fatalf("FindOrCreate new: %+v err=%v", fresh, err)
	}
	again, err := repo.FindOrCreate(ctx, data.BookPersonal.Guid, "9999999")
	if err != nil || again.Guid != fresh.Guid {
		t.Fatalf("FindOrCreate idempotent: %+v err=%v", again, err)
	}

	// Upsert：更新凭据列（identity 不动）。
	updated, err := repo.Upsert(ctx, &entity.AddressBookPeer{
		AddressBookGuid: data.BookPersonal.Guid, DeviceId: data.PeerA.ID,
		Password: strRepoPtr("new-pass"), Alias: strRepoPtr("new-alias"),
	})
	if err != nil || updated.Guid != data.PeerAB1.Guid || updated.Password == nil || *updated.Password != "new-pass" {
		t.Fatalf("Upsert update: %+v err=%v", updated, err)
	}

	// union：PeerAB1 有 TagWork。
	rows, total, err := repo.ListByBook(ctx, data.BookPersonal.Guid, ABPeerFilter{
		TagGuids: []string{data.TagWork.Guid}, TagMode: TagModeUnion,
	})
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("union: rows=%d total=%d err=%v", len(rows), total, err)
	}
	// intersection：单标签同义。
	rows, total, err = repo.ListByBook(ctx, data.BookPersonal.Guid, ABPeerFilter{
		TagGuids: []string{data.TagWork.Guid}, TagMode: TagModeIntersection,
	})
	if err != nil || total != 1 {
		t.Fatalf("intersection: rows=%d total=%d err=%v", len(rows), total, err)
	}
	// 双标签 intersection：无设备同时命中 → 空。
	rows, total, err = repo.ListByBook(ctx, data.BookPersonal.Guid, ABPeerFilter{
		TagGuids: []string{data.TagWork.Guid, data.TagHome.Guid}, TagMode: TagModeIntersection,
	})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("intersection multi: rows=%d total=%d err=%v", len(rows), total, err)
	}

	// DeleteByBook：清 peers + 关联行。
	if err := repo.DeleteByBook(ctx, data.BookPersonal.Guid); err != nil {
		t.Fatalf("DeleteByBook: %v", err)
	}
	assertCount(t, db, "address_book_peers", "addressBookGuid = ?", data.BookPersonal.Guid, 0)
	assertCount(t, db, "address_book_peer_tags", "tagGuid = ?", data.TagWork.Guid, 0)
}

// TestAddressBookRuleOps 规则仓储：Upsert 冲突更新、everyone 判定、
// RulesForUser/MaxRuleForUser/ExistsForUser、targetGroup 计数删除
// （M2 批复 #4 配套）。
func TestAddressBookRuleOps(t *testing.T) {
	ctx, db, data := openM3(t)
	repo := NewAddressBookRuleRepo(db)

	// RulesForUser：scoped 命中三源（user/group/everyone）。
	rules, err := repo.RulesForUser(ctx, data.BookShared.Guid, data.Scoped.Guid, []string{"seed-ug-1"})
	if err != nil || len(rules) != 3 {
		t.Fatalf("RulesForUser: len=%d err=%v", len(rules), err)
	}
	max, err := repo.MaxRuleForUser(ctx, data.BookShared.Guid, data.Scoped.Guid, []string{"seed-ug-1"})
	if err != nil || max != entity.ShareRuleFullControl {
		t.Fatalf("MaxRuleForUser = %d err=%v", max, err)
	}
	// ExistsForUser：EXTERNAL_GRANT_EXISTS（仅 targetUserId=我）。
	ok, err := repo.ExistsForUser(ctx, data.BookShared.Guid, data.Scoped.Guid)
	if err != nil || !ok {
		t.Fatalf("ExistsForUser = %v err=%v", ok, err)
	}
	ok, err = repo.ExistsForUser(ctx, data.BookShared.Guid, data.Owner.Guid)
	if err != nil || ok {
		t.Fatalf("ExistsForUser(owner) = %v err=%v", ok, err)
	}

	// Upsert 复合 PK 冲突：更新 rule（不重复建行）。
	upd := &entity.AddressBookRule{
		Guid: data.RuleUser.Guid, AddressBookGuid: data.BookShared.Guid,
		TargetUserId: &data.Scoped.Guid, Rule: entity.ShareRuleReadWrite,
	}
	if err := repo.Upsert(ctx, upd); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	assertCount(t, db, "address_book_rules", "guid = ?", data.RuleUser.Guid, 1)

	// CountByTargetGroup / DeleteByTargetGroup（user-group 删除链）。
	n, err := repo.CountByTargetGroup(ctx, "seed-ug-1")
	if err != nil || n != 1 {
		t.Fatalf("CountByTargetGroup = %d err=%v", n, err)
	}
	if err := repo.DeleteByTargetGroup(ctx, "seed-ug-1"); err != nil {
		t.Fatalf("DeleteByTargetGroup: %v", err)
	}
	assertCount(t, db, "address_book_rules", "targetGroupId = ?", "seed-ug-1", 0)

	// RuleType 档位名（类图方法）。
	if got := (&entity.AddressBookRule{Rule: 3}).RuleType(); got != "full_control" {
		t.Errorf("RuleType(3) = %q", got)
	}
}

// TestAddressBookTagFindOrCreate 幂等创建：重名返回既有行且不覆盖颜色。
func TestAddressBookTagFindOrCreate(t *testing.T) {
	ctx, db, data := openM3(t)
	repo := NewAddressBookTagRepo(db)

	got, created, err := findOrCreateTag(ctx, repo, data.BookPersonal.Guid, "work", 0x11223344)
	if err != nil || created {
		t.Fatalf("existing tag: created=%v err=%v", created, err)
	}
	if got.Guid != data.TagWork.Guid || got.Color != 0xFF0000FF {
		t.Errorf("existing tag mismatch: %+v", got)
	}
	fresh, created, err := findOrCreateTag(ctx, repo, data.BookPersonal.Guid, "fresh", 0xAABBCCDD)
	if err != nil || !created || fresh.Guid == "" {
		t.Fatalf("new tag: created=%v err=%v", created, err)
	}
	if err := repo.UpdateColor(ctx, fresh.Guid, 0x01020304); err != nil {
		t.Fatalf("UpdateColor: %v", err)
	}
	tags, err := repo.ListByBook(ctx, data.BookPersonal.Guid)
	if err != nil || len(tags) != 2 {
		t.Fatalf("ListByBook: len=%d err=%v", len(tags), err)
	}
}

// findOrCreateTag 剥离 created 语义的包装（FindOrCreate 返回既有/新建行）。
func findOrCreateTag(ctx context.Context, repo *AddressBookTagRepo, bookGuid, name string, color uint32) (*entity.AddressBookTag, bool, error) {
	before, err := repo.ListByBook(ctx, bookGuid)
	if err != nil {
		return nil, false, err
	}
	tag, err := repo.FindOrCreate(ctx, bookGuid, name, color)
	if err != nil {
		return nil, false, err
	}
	for _, tg := range before {
		if tg.Guid == tag.Guid {
			return tag, false, nil
		}
	}
	return tag, true, nil
}

// TestNexusBuildAndToken 轮询窗口（pending|building）+ 终态落库 +
// token upsert/unbind。
func TestNexusBuildAndToken(t *testing.T) {
	ctx, db, data := openM3(t)
	builds := NewNexusBuildRepo(db)
	tokens := NewNexusTokenRepo(db)

	// fixture Build1 pending + 追加 done 行：仅 pending 进窗口。
	if err := builds.Create(ctx, &entity.NexusBuild{
		Uuid: "seed-build-2", UserGuid: data.Scoped.Guid,
		Os: "linux", Arch: "arm64", Status: entity.NexusStatusDone,
	}); err != nil {
		t.Fatalf("create done build: %v", err)
	}
	polling, err := builds.ListPolling(ctx)
	if err != nil || len(polling) != 1 || polling[0].Uuid != data.Build1.Uuid {
		t.Fatalf("ListPolling: %+v err=%v", polling, err)
	}

	// 轮询终态落库。
	files := `["client.exe"]`
	msg := "ok"
	if err := builds.UpdateResult(ctx, data.Build1.Uuid, entity.NexusStatusDone, &files, &msg); err != nil {
		t.Fatalf("UpdateResult: %v", err)
	}
	row, err := builds.FindByUUID(ctx, data.Build1.Uuid)
	if err != nil || row.Status != entity.NexusStatusDone || row.Files != files {
		t.Fatalf("after UpdateResult: %+v err=%v", row, err)
	}

	// UpdateStatus：取消语义。
	if err := builds.UpdateStatus(ctx, data.Build1.Uuid, entity.NexusStatusCanceled); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	polling, _ = builds.ListPolling(ctx)
	if len(polling) != 0 {
		t.Fatalf("canceled build still polling: %+v", polling)
	}

	// builds 列表按用户隔离。
	_, total, err := builds.ListByUser(ctx, data.Scoped.Guid, 1, 10)
	if err != nil || total != 2 {
		t.Fatalf("ListByUser total=%d err=%v", total, err)
	}

	// token：upsert 覆盖 + unbind。
	nt := &entity.NexusToken{
		UserGuid: data.Scoped.Guid, NexusToken: "token-2",
		ExpiresAt: time.Now().Add(time.Hour), CurrentUuid: strRepoPtr("login-1"),
	}
	if err := tokens.Upsert(ctx, nt); err != nil {
		t.Fatalf("Upsert token: %v", err)
	}
	got, err := tokens.FindByUser(ctx, data.Scoped.Guid)
	if err != nil || got.NexusToken != "token-2" {
		t.Fatalf("FindByUser: %+v err=%v", got, err)
	}
	assertCount(t, db, "nexus_tokens", "userGuid = ?", data.Scoped.Guid, 1)
	if err := tokens.DeleteByUser(ctx, data.Scoped.Guid); err != nil {
		t.Fatalf("DeleteByUser: %v", err)
	}
	if _, err := tokens.FindByUser(ctx, data.Scoped.Guid); err != ErrNotFound {
		t.Errorf("after unbind err = %v, want ErrNotFound", err)
	}
}

// TestSystemSettingKV KV 语义：Set upsert / Get / GetAllByPrefix / 删除。
func TestSystemSettingKV(t *testing.T) {
	ctx, db := openM3Empty(t)
	repo := NewSystemSettingRepo(db)

	if err := repo.Set(ctx, "smtp.host", "smtp.example.com", "smtp"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := repo.Set(ctx, "smtp.host", "smtp2.example.com", "smtp"); err != nil {
		t.Fatalf("Set overwrite: %v", err)
	}
	assertCount(t, db, "system_settings", "`key` = ?", "smtp.host", 1)

	got, err := repo.Get(ctx, "smtp.host")
	if err != nil || got.Value != "smtp2.example.com" || got.Category != "smtp" {
		t.Fatalf("Get: %+v err=%v", got, err)
	}
	if _, err := repo.Get(ctx, "missing.key"); err != ErrNotFound {
		t.Errorf("missing err = %v, want ErrNotFound", err)
	}

	if err := repo.Set(ctx, "smtp.port", "465", "smtp"); err != nil {
		t.Fatalf("Set port: %v", err)
	}
	if err := repo.Set(ctx, "general.site", "panel", "general"); err != nil {
		t.Fatalf("Set general: %v", err)
	}
	rows, err := repo.GetAllByPrefix(ctx, "smtp.")
	if err != nil || len(rows) != 2 {
		t.Fatalf("GetAllByPrefix: len=%d err=%v", len(rows), err)
	}
	if err := repo.DeleteByKey(ctx, "smtp.port"); err != nil {
		t.Fatalf("DeleteByKey: %v", err)
	}
	rows, _ = repo.GetAllByPrefix(ctx, "smtp.")
	if len(rows) != 1 {
		t.Fatalf("after delete len=%d, want 1", len(rows))
	}
}

// TestConnectionAuditListActiveScope 活跃连接 scope 语义：nil 全量 /
// 空集为空 / uuid 过滤 / closedAt IS NULL。
func TestConnectionAuditListActiveScope(t *testing.T) {
	ctx, db, data := openM3(t)
	repo := NewConnectionAuditRepo(db)

	// fixture：ConnNew/Open/Active 未关（closedAt=nil），ConnClosed/Failed 已关。
	all, err := repo.ListActive(ctx, nil)
	if err != nil {
		t.Fatalf("ListActive(nil): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("all = %d, want 3 (new/open/active)", len(all))
	}
	none, err := repo.ListActive(ctx, []string{})
	if err != nil || len(none) != 0 {
		t.Fatalf("empty scope: %d err=%v", len(none), err)
	}
	scoped, err := repo.ListActive(ctx, []string{*data.ConnActive.DeviceUuid})
	if err != nil || len(scoped) != 3 {
		t.Fatalf("uuid scope: %d err=%v", len(scoped), err)
	}
	other, err := repo.ListActive(ctx, []string{"uuid-other"})
	if err != nil || len(other) != 0 {
		t.Fatalf("other uuid: %d err=%v", len(other), err)
	}
}

// TestConnectionAuditListPagedFilters conn 过滤契约逐项（peer_id/uuid/
// type/start/end 精确语义 + 排序 requestedAt DESC）。
func TestConnectionAuditListPagedFilters(t *testing.T) {
	ctx, db := openM3Empty(t)
	repo := NewConnectionAuditRepo(db)
	now := time.Now()
	peerA, peerB := "900001", "900002"
	typ1 := 1
	rows := []*entity.ConnectionAudit{
		{DeviceId: "d1", DeviceUuid: strRepoPtr("u1"), ConnId: strRepoPtr("c1"), PeerId: &peerA, Type: 0, RequestedAt: now.Add(-3 * time.Hour)},
		{DeviceId: "d2", DeviceUuid: strRepoPtr("u1"), ConnId: strRepoPtr("c2"), PeerId: &peerA, Type: 1, RequestedAt: now.Add(-2 * time.Hour)},
		{DeviceId: "d3", DeviceUuid: strRepoPtr("u2"), ConnId: strRepoPtr("c3"), PeerId: &peerB, Type: 1, RequestedAt: now.Add(-time.Hour)},
	}
	for _, r := range rows {
		if err := repo.Create(ctx, r); err != nil {
			t.Fatalf("seed %+v: %v", r, err)
		}
	}

	// peer_id 精确。
	got, total, err := repo.ListPaged(ctx, ConnAuditFilter{PeerId: peerA})
	if err != nil || total != 2 || len(got) != 2 {
		t.Fatalf("peer filter: total=%d err=%v", total, err)
	}
	// uuid + type 组合。
	got, total, err = repo.ListPaged(ctx, ConnAuditFilter{Uuid: "u1", Type: &typ1})
	if err != nil || total != 1 || got[0].ConnId == nil || *got[0].ConnId != "c2" {
		t.Fatalf("uuid+type: %+v err=%v", got, err)
	}
	// start/end 时间窗（闭区间边界内）。
	start := now.Add(-90 * time.Minute)
	end := now.Add(-30 * time.Minute)
	got, total, err = repo.ListPaged(ctx, ConnAuditFilter{Start: &start, End: &end})
	if err != nil || total != 1 || got[0].PeerId == nil || *got[0].PeerId != peerB {
		t.Fatalf("time window: %+v err=%v", got, err)
	}
	// 分页 + 排序（requestedAt DESC）。
	got, total, err = repo.ListPaged(ctx, ConnAuditFilter{Current: 1, PageSize: 2})
	if err != nil || total != 3 || len(got) != 2 {
		t.Fatalf("page1: total=%d len=%d err=%v", total, len(got), err)
	}
	if got[0].RequestedAt.Before(got[1].RequestedAt) {
		t.Errorf("order violated: %v before %v", got[0].RequestedAt, got[1].RequestedAt)
	}
	page2, total, err := repo.ListPaged(ctx, ConnAuditFilter{Current: 2, PageSize: 2})
	if err != nil || total != 3 || len(page2) != 1 {
		t.Fatalf("page2: total=%d len=%d err=%v", total, len(page2), err)
	}
}

// TestConnectionAuditCountTodaySuccessFailure 仪表盘口径（§1.1⑥）：
// today=requestedAt 计数；success=双非空；failure=closedAt 有 establishedAt 无。
func TestConnectionAuditCountTodaySuccessFailure(t *testing.T) {
	ctx, db := openM3Empty(t)
	repo := NewConnectionAuditRepo(db)
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	seed := []*entity.ConnectionAudit{
		{DeviceId: "x", RequestedAt: today.Add(time.Hour), Action: entity.ConnActionNew},
		{DeviceId: "x", RequestedAt: today.Add(2 * time.Hour), Action: entity.ConnActionEstablished,
			EstablishedAt: ptrTimeTest(today.Add(time.Hour)), ClosedAt: ptrTimeTest(today.Add(2 * time.Hour))},
		{DeviceId: "x", RequestedAt: today.Add(3 * time.Hour), Action: entity.ConnActionNew,
			ClosedAt: ptrTimeTest(today.Add(2 * time.Hour))},
		{DeviceId: "x", RequestedAt: today.Add(-25 * time.Hour), Action: entity.ConnActionNew}, // 窗口外
	}
	for _, r := range seed {
		if err := repo.Create(ctx, r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	todayN, err := repo.CountToday(ctx, today)
	if err != nil || todayN != 3 {
		t.Fatalf("CountToday = %d err=%v", todayN, err)
	}
	success, failure, err := repo.CountSuccessFailure(ctx)
	if err != nil {
		t.Fatalf("CountSuccessFailure: %v", err)
	}
	if success != 1 || failure != 1 {
		t.Fatalf("success=%d failure=%d, want 1/1", success, failure)
	}
}

// TestAlarmAuditListPagedFilters alarm 过滤契约（typ/uuid 精确）。
func TestAlarmAuditListPagedFilters(t *testing.T) {
	ctx, db := openM3Empty(t)
	repo := NewAlarmAuditRepo(db)
	now := time.Now()
	typ2 := 2
	rows := []*entity.AlarmAudit{
		{DeviceId: "a1", DeviceUuid: "u1", Typ: 1, CreatedAt: now.Add(-2 * time.Hour)},
		{DeviceId: "a2", DeviceUuid: "u1", Typ: 2, CreatedAt: now.Add(-time.Hour)},
		{DeviceId: "a3", DeviceUuid: "u2", Typ: 2, CreatedAt: now},
	}
	for _, r := range rows {
		if err := repo.Create(ctx, r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	got, total, err := repo.ListPaged(ctx, AlarmAuditFilter{Typ: &typ2, Uuid: "u1"})
	if err != nil || total != 1 || got[0].DeviceId != "a2" {
		t.Fatalf("typ+uuid: %+v err=%v", got, err)
	}
}

// strRepoPtr 字符串指针（仓储测试便捷函数）。
func strRepoPtr(s string) *string { return &s }

// ptrTimeTest 时间指针（仓储测试便捷函数）。
func ptrTimeTest(t time.Time) *time.Time { return &t }

// assertCount 断言表行数（级联/唯一约束验证辅助），返回实际计数。
func assertCount(t *testing.T, db *gorm.DB, table, where string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := db.Raw("SELECT COUNT(*) FROM "+table+" WHERE "+where, args...).Scan(&n).Error; err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}
