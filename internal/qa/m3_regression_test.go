// Package qa 本文件：M3 T05 回归（M2 批复 #3 / #4 在 T05 落地验证）。
//
// 覆盖两条高风险业务链，与契约/单元互补，防止"接口绿但业务语义漂移"：
//   - preset-address-book-* 联动：设备 sysinfo 上报携带预置键，在超管
//     名下 findOrCreate custom 地址簿并 upsert ab peer + 标签关联；
//   - deleted_rule_count 真实计数：删用户组时级联删除指向该组的
//     address_book_rules，计数真实回传（非硬编码）。
package qa

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// TestM3RegressionPresetAddressBook sysinfo preset-address-book-* 联动
// （M2 批复 #3，T05 落地）：设备上报携带 preset-address-book-* 时，在
// 超管名下 findOrCreate custom 地址簿并 upsert ab peer + 标签关联。
func TestM3RegressionPresetAddressBook(t *testing.T) {
	ts := newQAServer(t)

	// 1) 先注册设备（heartbeat 自动建 peers 行；sysinfo 不自动注册）。
	devUUID := "preset-dev-" + uuid.NewString()
	_, _, hraw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/heartbeat", map[string]any{
		"id":   "PRESETID001",
		"uuid": devUUID,
		"ver":  1,
	}, nil)
	_ = hraw

	// 2) 上报 sysinfo，携带 preset-address-book-* 五键。
	status, _, sraw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/sysinfo", map[string]any{
		"uuid":                         devUUID,
		"hostname":                     "preset-host",
		"preset-address-book-name":     "deploy-book",
		"preset-address-book-tag":      "prod,edge",
		"preset-address-book-alias":    "edge-node-1",
		"preset-address-book-password": "secret123",
		"preset-address-book-note":     "auto-provisioned",
	}, nil)
	if status != http.StatusOK {
		t.Fatalf("POST /api/sysinfo status = %d (body %s)", status, sraw)
	}

	// 3) 校验：超管（databk）名下存在名为 deploy-book 的 custom 地址簿。
	adminGuid := userGuid(t, ts, "databk")
	var book entity.AddressBook
	if err := ts.DB.Where("owner = ? AND name = ?", adminGuid, "deploy-book").First(&book).Error; err != nil {
		t.Fatalf("find preset custom book: %v", err)
	}
	if book.IsPersonal || book.IsShared {
		t.Fatalf("preset book 三态错误: isPersonal=%v isShared=%v", book.IsPersonal, book.IsShared)
	}

	// 4) 校验：ab peer 已按 deviceId upsert，且 alias/password/note 语义落位。
	var peer entity.AddressBookPeer
	if err := ts.DB.Where("addressBookGuid = ? AND deviceId = ?", book.Guid, devUUID).First(&peer).Error; err != nil {
		t.Fatalf("find preset ab peer: %v", err)
	}
	if peer.Alias == nil || *peer.Alias != "edge-node-1" {
		t.Fatalf("preset ab peer alias = %v, want edge-node-1", peer.Alias)
	}
	if peer.Password == nil || *peer.Password != "secret123" {
		t.Fatalf("preset ab peer password = %v, want secret123", peer.Password)
	}
	if peer.Note != "auto-provisioned" {
		t.Fatalf("preset ab peer note = %q, want auto-provisioned", peer.Note)
	}

	// 5) 校验：prod / edge 双标签已建，且均与设备关联（幂等并集 2 条）。
	var tags []entity.AddressBookTag
	if err := ts.DB.Where("addressBookGuid = ?", book.Guid).Find(&tags).Error; err != nil {
		t.Fatalf("find preset tags: %v", err)
	}
	have := make(map[string]string, len(tags))
	for _, tg := range tags {
		have[tg.Name] = tg.Guid
	}
	if _, ok := have["prod"]; !ok {
		t.Fatalf("preset tag prod 未创建: %v", have)
	}
	if _, ok := have["edge"]; !ok {
		t.Fatalf("preset tag edge 未创建: %v", have)
	}
	var ptCount int64
	if err := ts.DB.Model(&entity.AddressBookPeerTag{}).Where("peerGuid = ?", peer.Guid).Count(&ptCount).Error; err != nil {
		t.Fatalf("count peer tags: %v", err)
	}
	if ptCount != 2 {
		t.Fatalf("preset peer tag 关联数 = %d, want 2", ptCount)
	}
}

// TestM3RegressionDeletedRuleCount 删用户组时 deleted_rule_count 真实
// 计数（M2 批复 #4，T05 落地）：address_book_rules.targetGroupId 显式
// 级联删除，计数真实回传，与成员回落同事务提交。
func TestM3RegressionDeletedRuleCount(t *testing.T) {
	ts := newQAServer(t)
	token := mustLogin(t, ts, "databk", "databk")

	// 1) 创建用户组。
	cstatus, cparsed, craw := doJSON(t, ts.TS.Client(), http.MethodPost, ts.TS.URL+"/api/user-groups", map[string]any{
		"name": "rule-target-group",
		"note": "for deleted_rule_count regression",
	}, authHeader(token))
	if cstatus != http.StatusOK {
		t.Fatalf("create user-group status = %d (body %s)", cstatus, craw)
	}
	groupGuid, _ := cparsed["guid"].(string)
	if groupGuid == "" {
		t.Fatalf("create user-group 缺少 guid: %v", cparsed)
	}

	// 2) 直接注入 3 条指向该组的 address_book_rules（同事务级联删除前
	// 的真实存量，验证计数而非单测服务内部逻辑）。
	for i := 0; i < 3; i++ {
		rule := entity.AddressBookRule{
			Guid:            uuid.NewString(),
			AddressBookGuid: uuid.NewString(),
			TargetGroupId:   &groupGuid,
			Rule:            entity.ShareRuleRead,
		}
		if err := ts.DB.Create(&rule).Error; err != nil {
			t.Fatalf("seed rule %d: %v", i, err)
		}
	}
	var before int64
	if err := ts.DB.Model(&entity.AddressBookRule{}).Where("targetGroupId = ?", groupGuid).Count(&before).Error; err != nil {
		t.Fatalf("count before: %v", err)
	}
	if before != 3 {
		t.Fatalf("seed rule count = %d, want 3", before)
	}

	// 3) 删除用户组（同事务级联删规则 + 成员回落）。
	dstatus, dparsed, draw := doJSON(t, ts.TS.Client(), http.MethodDelete, ts.TS.URL+"/api/user-groups/"+groupGuid, nil, authHeader(token))
	if dstatus != http.StatusOK {
		t.Fatalf("delete user-group status = %d (body %s)", dstatus, draw)
	}
	// 字节级结构：deleted_rule_count 真实等于 3。
	if dc, _ := dparsed["deleted_rule_count"].(float64); int(dc) != 3 {
		t.Fatalf("deleted_rule_count = %v, want 3", dparsed["deleted_rule_count"])
	}

	// 4) 复核：DB 中该组相关规则已被真实删除。
	var after int64
	if err := ts.DB.Model(&entity.AddressBookRule{}).Where("targetGroupId = ?", groupGuid).Count(&after).Error; err != nil {
		t.Fatalf("count after: %v", err)
	}
	if after != 0 {
		t.Fatalf("after delete rule count = %d, want 0", after)
	}
	// 组本身已删。
	var gCount int64
	if err := ts.DB.Model(&entity.UserGroup{}).Where("guid = ?", groupGuid).Count(&gCount).Error; err != nil {
		t.Fatalf("count group: %v", err)
	}
	if gCount != 0 {
		t.Fatalf("user-group 未删除: count = %d", gCount)
	}
}
