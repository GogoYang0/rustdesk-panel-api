package rbac

// 生效码过滤与依赖校验（镜像参考 filterEffectivePermissionCodes）。
//
// 语义（设计 §1.1②）：授权码集中缺任一依赖的码视为无效。
// requires 链允许递归（依赖本身可能又依赖其他码），以不动点迭代实现。

// FilterEffective 过滤生效码：返回 codes 中全部依赖均在集合内（含自身
// 传递闭包）的码。顺序保持输入顺序，重复码去重。
func FilterEffective(codes []string) []string {
	have := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		have[c] = struct{}{}
	}
	// 不动点迭代：反复剔除不满足依赖的码，直至稳定。
	for {
		removed := false
		for _, c := range codes {
			if _, ok := have[c]; !ok {
				continue
			}
			for _, req := range Requirements(c) {
				if _, ok := have[req]; !ok {
					delete(have, c)
					removed = true
					break
				}
			}
		}
		if !removed {
			break
		}
	}
	seen := make(map[string]struct{}, len(have))
	out := make([]string, 0, len(have))
	for _, c := range codes {
		if _, ok := have[c]; !ok {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// Requirements 返回码的依赖列表（未知码返回 nil）。
func Requirements(code string) []string {
	d, ok := catalogIndex[code]
	if !ok {
		return nil
	}
	return d.Requires
}

// MissingDependencies 返回授予 code 前缺失的依赖码
// （相对已有集合 have，按目录定义顺序）。code 本身不在目录时返回空。
func MissingDependencies(code string, have map[string]struct{}) []string {
	missing := make([]string, 0)
	for _, req := range Requirements(code) {
		if _, ok := have[req]; !ok {
			missing = append(missing, req)
		}
	}
	return missing
}

// ValidateAssignmentCodes 校验角色写入的权限码集合（requires 链在角色
// 写入时校验，共享知识 2）。
//
//   - 未知码或 system_only 码 → 400 "Permission code cannot be assigned: {code}"
//   - 任一码缺失依赖 → 400 "Missing permission dependencies: {依赖码}"
//
// 返回 (nil, nil) 表示合法；否则返回携带 HTTP 语义的 *StatusError。
func ValidateAssignmentCodes(codes []string) error {
	have := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		have[c] = struct{}{}
	}
	for _, c := range codes {
		if !IsAssignable(c) {
			return ErrBadRequest("Permission code cannot be assigned: " + c)
		}
		if missing := MissingDependencies(c, have); len(missing) > 0 {
			return ErrBadRequest("Missing permission dependencies: " + missing[0])
		}
	}
	return nil
}
