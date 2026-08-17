// configoptions_test.go 单源 ParseConfigOptions 回归：两域历史形态
// （M2 heartbeat 原语义样本 + M2 strategy 脏数据样本）同一函数同一
// 结果；宽松统一后的行为变化（剔除非 string 保留 string）逐条锁定
// （M3 批复 #1，QA Info）。
package jsonutil

import (
	"reflect"
	"testing"
)

func TestParseConfigOptions(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		// ---- 第三层兜底：非 object 形态 ----
		{"empty raw", "", map[string]string{}},
		{"bad json", "not-json{", map[string]string{}},
		{"array", `["a","b"]`, map[string]string{}},
		{"null literal", `null`, map[string]string{}},
		{"number literal", `42`, map[string]string{}},
		{"string literal", `"x"`, map[string]string{}},

		// ---- 第一层：精确 string→string（heartbeat 正常形态）----
		{
			"strict object",
			`{"access_ip":"10.0.0.9","custom-rustdesk-port":"21116"}`,
			map[string]string{"access_ip": "10.0.0.9", "custom-rustdesk-port": "21116"},
		},
		{"empty object", `{}`, map[string]string{}},
		{"empty string value", `{"a":"1","b":""}`, map[string]string{"a": "1", "b": ""}},

		// ---- 第二层：逐键剔除非 string（strategy 脏数据样本）----
		{
			"mixed drop non-string",
			`{"a":"x","b":true,"c":1,"d":null}`,
			map[string]string{"a": "x"},
		},
		// heartbeat 旧语义样本：全非 string → {}（结果值与旧语义一致，
		// 语义差异在混合形态——上一用例新语义保留 string 键）。
		{"all non-string", `{"allow_log_anonymous":true}`, map[string]string{}},
		{"nested object value", `{"a":{"b":"c"},"d":"keep"}`, map[string]string{"d": "keep"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseConfigOptions(tc.raw)
			if got == nil {
				t.Fatal("ParseConfigOptions returned nil, want non-nil map")
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseConfigOptions(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestParseConfigOptionsSingleSourceHeartbeatStrategy 语义单源回归：
// 同一 DB 值经单源解析后，heartbeat 下发与 strategy 视图必然一致
// （两域调用点均引用本包，此处以字面样本锁定一致性契约）。
func TestParseConfigOptionsSingleSourceHeartbeatStrategy(t *testing.T) {
	samples := []string{
		``,
		`{}`,
		`{"access_ip":"10.0.0.9","custom-rustdesk-port":"21116"}`,
		`{"a":"x","b":true,"c":1}`,
		`{"allow_log_anonymous":true}`,
		`not-json{`,
		`["a"]`,
	}
	for _, raw := range samples {
		// 两域解析同一函数对象：结果恒等且非 nil。
		first := ParseConfigOptions(raw)
		second := ParseConfigOptions(raw)
		if first == nil || second == nil {
			t.Fatalf("ParseConfigOptions(%q) returned nil", raw)
		}
		if !reflect.DeepEqual(first, second) {
			t.Errorf("ParseConfigOptions(%q) not deterministic: %v vs %v", raw, first, second)
		}
	}
}
