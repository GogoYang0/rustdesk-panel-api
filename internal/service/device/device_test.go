// device_test.go 设备域服务单元测试：ver 格式化公式、断连队列语义、
// configOptions 解析防御（设计 §1.1③④ 契约函数的逐点锁定）。
package device

import (
	"reflect"
	"testing"
)

// TestFormatPeerVersion ver 格式化（共享知识 8 公式）：
// major=ver/1e6, minor=(ver%1e6)/1e3, patch=(ver%1e3)/10, suffix=ver%10。
func TestFormatPeerVersion(t *testing.T) {
	cases := []struct {
		ver  int64
		want string
	}{
		{0, ""},              // ver=0 → 空串
		{1001000, "1.1.0"},   // 1.1.0 正式版
		{1001023, "1.1.2-3"}, // minor=1 patch=2 suffix=3
		{1000001, "1.0.0-1"},
		{1000000006, "1000.0.0-6"},
		{109090, "0.109.9"}, // major=0 合法
		{999, "0.0.99-9"},
	}
	for _, c := range cases {
		if got := FormatPeerVersion(c.ver); got != c.want {
			t.Errorf("FormatPeerVersion(%d) = %q, want %q", c.ver, got, c.want)
		}
	}
}

// TestDisconnectStore 断连队列：入队幂等、pending 升序、确认出队、
// 设备间隔离。
func TestDisconnectStore(t *testing.T) {
	s := NewDisconnectStore()

	if got := s.Pending("dev-1"); len(got) != 0 {
		t.Fatalf("initial pending = %v, want empty", got)
	}

	s.AddPending("dev-1", []int64{12, 11})
	s.AddPending("dev-1", []int64{11}) // 重复入队幂等
	s.AddPending("dev-2", []int64{99}) // 设备隔离

	if got := s.Pending("dev-1"); !reflect.DeepEqual(got, []int64{11, 12}) {
		t.Errorf("pending dev-1 = %v, want [11 12]（升序）", got)
	}
	if got := s.Pending("dev-2"); !reflect.DeepEqual(got, []int64{99}) {
		t.Errorf("pending dev-2 = %v, want [99]", got)
	}

	// 客户端不再上报 11 → 已断开确认出队；未入队的 55 静默忽略。
	s.RemoveDisconnected("dev-1", []int64{11, 55})
	if got := s.Pending("dev-1"); !reflect.DeepEqual(got, []int64{12}) {
		t.Errorf("pending dev-1 after confirm = %v, want [12]", got)
	}

	// 全部确认后清空设备条目。
	s.RemoveDisconnected("dev-1", []int64{12})
	if got := s.Pending("dev-1"); len(got) != 0 {
		t.Errorf("pending dev-1 after all confirmed = %v, want empty", got)
	}
}

// TestParseConfigOptions configOptions 解析契约：空串 → {}；
// 正常 map 解析；非 string 值/坏 JSON（脏数据防御）→ {}。
func TestParseConfigOptions(t *testing.T) {
	if got := ParseConfigOptions(""); len(got) != 0 {
		t.Errorf("empty raw = %v, want empty map", got)
	}
	got := ParseConfigOptions(`{"access_ip":"10.0.0.9","custom-rustdesk-port":"21116"}`)
	want := map[string]string{"access_ip": "10.0.0.9", "custom-rustdesk-port": "21116"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parsed = %v, want %v", got, want)
	}
	if got := ParseConfigOptions(`{"allow_log_anonymous":true}`); len(got) != 0 {
		t.Errorf("non-string value = %v, want empty map（防御脏数据）", got)
	}
	if got := ParseConfigOptions("not-json"); len(got) != 0 {
		t.Errorf("bad json = %v, want empty map", got)
	}
}
