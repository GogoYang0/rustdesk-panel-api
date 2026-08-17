// Package jsonutil 汇集跨域共享的 JSON 脏数据防御工具。
//
// M3 批复 #1（QA Info 落实）：configOptions 解析此前在
// service/device（整体失败→{}）与 service/strategy（逐键剔除非 string）
// 两处语义不一致，本包统一为单源宽松实现，两域同一函数同一快照。
// 任何新域解析 configOptions 一律引用本包，禁止本地再实现
// （共享知识 21）。
package jsonutil

import "encoding/json"

// ParseConfigOptions 解析 DB TEXT 中的 configOptions JSON 串为
// API 契约的 Record<string,string>（三层降级，恒返回非 nil）：
//
//  1. 精确解析：JSON object 且全部值为 string → 原样返回；
//  2. 逐键剔除：object 形态但含非 string 值 → 保留 string 值的键，
//     剔除 boolean/number/object 等键（策略域历史脏数据兼容，M3 批复 #1）；
//  3. 兜底：空串、坏 JSON、数组、null 等非 object 形态 → {}。
//
// heartbeat 下发与 strategy 视图组装共用本函数，保证两端对同一
// DB 值产出一致结果。
func ParseConfigOptions(raw string) map[string]string {
	out := map[string]string{}
	if raw == "" {
		return out
	}
	// 第一层：精确 map[string]string（绝大多数正常数据单次完成）。
	var strict map[string]string
	if err := json.Unmarshal([]byte(raw), &strict); err == nil {
		if strict != nil {
			return strict
		}
		// raw == "null" 落入此分支：无键可取，等价 {}。
		return out
	}
	// 第二层：object 形态但值类型混杂 → 逐键保留 string，剔除其余。
	var loose map[string]any
	if err := json.Unmarshal([]byte(raw), &loose); err != nil {
		// 第三层：非 object（数组/字面量/坏 JSON）→ {}。
		return out
	}
	for k, v := range loose {
		if sv, ok := v.(string); ok {
			out[k] = sv
		}
	}
	return out
}
