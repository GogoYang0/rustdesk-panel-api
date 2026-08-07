// strategy_test.go 策略域服务单测：config_options 脏数据防御解析、
// target_guids 去重、部分成功拆分 reason 固定文案、DeleteWithDetach
// 幂等与三处置空（T04 验收单测项）。
package strategy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// TestParseConfigOptions 脏数据防御：空串/坏 JSON/非 object/含非 string
// 值均安全降级；恒返回非 nil（StrategyView.config_options 契约）。
func TestParseConfigOptions(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"empty", "", map[string]string{}},
		{"bad json", "not-json{", map[string]string{}},
		{"array", `["a","b"]`, map[string]string{}},
		{"null", `null`, map[string]string{}},
		{"string values", `{"a":"1","b":""}`, map[string]string{"a": "1", "b": ""}},
		{"mixed drop non-string", `{"a":"x","b":true,"c":1,"d":null}`, map[string]string{"a": "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseConfigOptions(tc.raw)
			if got == nil {
				t.Fatal("ParseConfigOptions returned nil, want non-nil map")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d (%v), want %d", len(got), got, len(tc.want))
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("config[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// TestDedupTargets 去重保持首次出现顺序（assign/unassign 契约）。
func TestDedupTargets(t *testing.T) {
	got := dedup([]string{"b", "a", "b", "c", "a", ""})
	want := []string{"b", "a", "c", ""}
	if len(got) != len(want) {
		t.Fatalf("dedup = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedup[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestSplitReasons 部分成功拆分：success 保持请求顺序、缺失者记入
// errors 且 reason 为固定文案。
func TestSplitReasons(t *testing.T) {
	res := split([]string{"g1", "g2", "g3"}, guidSetOf([]string{"g3", "g1"}, func(i int) string {
		return []string{"g3", "g1"}[i]
	}), reasonGroupNotFound)
	if len(res.Success) != 2 || res.Success[0] != "g1" || res.Success[1] != "g3" {
		t.Errorf("success = %v, want [g1 g3]（请求顺序）", res.Success)
	}
	if len(res.Errors) != 1 || res.Errors[0].TargetGuid != "g2" || res.Errors[0].Reason != reasonGroupNotFound {
		t.Errorf("errors = %v, want [{g2 %s}]", res.Errors, reasonGroupNotFound)
	}
}

// TestDeleteWithDetachIdempotent 删除置空幂等：仓储级二次删除不报错、
// 三处引用置空；服务级对已删策略二次删除返回 404 固定文案。
func TestDeleteWithDetachIdempotent(t *testing.T) {
	ctx := context.Background()
	db := testutil.NewMemoryDB(t)
	testutil.MigrateUpForTest(t, db)

	strategies := repository.NewStrategyRepo(db)
	peers := repository.NewPeerRepo(db)
	users := repository.NewUserRepo(db)
	groups := repository.NewDeviceGroupRepo(db)
	svc := NewService(nil, strategies, peers, users, groups) // Delete 路径不触 authz

	now := time.Now()
	st := &entity.Strategy{Guid: "st-del", Name: "del-me", ConfigOptions: `{"k":"v"}`, CreatedAt: now, UpdatedAt: now}
	peer := &entity.Peer{UUID: "p-del", ID: "1001", StrategyGuid: &st.Guid, CreatedAt: now, UpdatedAt: now}
	user := &entity.User{Guid: "u-del", Username: "udel", Email: "udel@example.com", Status: 1, StrategyGuid: &st.Guid, CreatedAt: now, UpdatedAt: now}
	group := &entity.DeviceGroup{Guid: "g-del", Name: "gdel", StrategyGuid: &st.Guid, CreatedAt: now, UpdatedAt: now}
	for _, row := range []any{st, peer, user, group} {
		if err := db.Create(row).Error; err != nil {
			t.Fatalf("seed %T: %v", row, err)
		}
	}

	if err := strategies.DeleteWithDetach(ctx, st.Guid); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	// 幂等：二次仓储删除不报错（幂等语义）。
	if err := strategies.DeleteWithDetach(ctx, st.Guid); err != nil {
		t.Fatalf("second delete must be idempotent: %v", err)
	}
	// 三处引用全部置空（共享知识 9）。
	p, err := peers.FindByUUID(ctx, peer.UUID)
	if err != nil || p.StrategyGuid != nil {
		t.Errorf("peer.strategyGuid not detached: %v/%v", p, err)
	}
	u, err := users.FindByGuid(ctx, user.Guid)
	if err != nil || u.StrategyGuid != nil {
		t.Errorf("user.strategyGuid not detached: %v/%v", u, err)
	}
	g, err := groups.FindByID(ctx, group.Guid)
	if err != nil || g.StrategyGuid != nil {
		t.Errorf("group.strategyGuid not detached: %v/%v", g, err)
	}

	// 服务级删除已不存在的策略：404 "Strategy not found"。
	err = svc.Delete(ctx, st.Guid)
	var se *rbac.StatusError
	if !errors.As(err, &se) || se.Status != 404 || se.Message != msgStrategyNotFound {
		t.Errorf("svc.Delete on missing = %v, want 404 %q", err, msgStrategyNotFound)
	}
}
