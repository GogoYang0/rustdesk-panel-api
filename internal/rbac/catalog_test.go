package rbac

import "testing"

// TestCatalogCount 断言目录总数与可分配/system_only 拆分：
// 设计 §1.1② 清单逐行枚举为 33 可分配 + 3 system_only（正文"32+3"计数
// 以清单枚举为准，见交付报告偏差说明）。
func TestCatalogCount(t *testing.T) {
	c := Catalog()
	if len(c) != 37 {
		t.Fatalf("catalog size = %d, want 37 (34 assignable + 3 system_only)", len(c))
	}
	assignable, systemOnly := 0, 0
	for _, d := range c {
		if d.SystemOnly {
			systemOnly++
		}
		if d.Assignable {
			assignable++
		}
	}
	if assignable != 34 || systemOnly != 3 {
		t.Fatalf("assignable = %d, systemOnly = %d, want 34/3", assignable, systemOnly)
	}
}

// TestCatalogCodes 断言全部 37 个码按清单原样存在（命名 resource.action）。
func TestCatalogCodes(t *testing.T) {
	want := []string{
		"users.view", "users.create", "users.edit", "users.status", "users.delete",
		"users.security", "users.force_logout",
		"user_groups.view", "user_groups.create", "user_groups.edit",
		"user_groups.delete", "user_groups.membership",
		"devices.view", "devices.edit", "devices.status", "devices.delete", "devices.disconnect",
		"devices.assign",
		"address_books.view", "address_books.edit", "address_books.share",
		"strategies.view", "strategies.create", "strategies.edit",
		"strategies.delete", "strategies.assign",
		"audit.view",
		"roles.view", "roles.assign", "roles.create", "roles.edit", "roles.delete",
		"servers.view", "servers.control", "servers.config", "servers.disconnect", "servers.ban",
	}
	codes := make(map[string]PermissionDefinition, len(catalog))
	for _, d := range catalog {
		codes[d.Code] = d
	}
	for _, code := range want {
		d, ok := codes[code]
		if !ok {
			t.Errorf("catalog missing code %q", code)
			continue
		}
		// resource/action 必须与码本身一致。
		resource, action := code[:len(code)-len(d.Action)-1], d.Action
		if resource != d.Resource || action != d.Action {
			t.Errorf("code %q: resource=%q action=%q mismatch", code, d.Resource, d.Action)
		}
	}
	if len(codes) != len(want) {
		t.Errorf("catalog has %d codes, want %d", len(codes), len(want))
	}
}

// TestCatalogScopes 断言 device_group 档仅 6 码（devices.* + strategies.assign）。
func TestCatalogScopes(t *testing.T) {
	deviceGroupScoped := []string{
		"devices.view", "devices.edit", "devices.status",
		"devices.delete", "devices.disconnect", "strategies.assign",
	}
	for _, code := range deviceGroupScoped {
		d, ok := FindDefinition(code)
		if !ok || d.Scope != ScopeDeviceGroup {
			t.Errorf("code %q must be device_group scope", code)
		}
	}
	for _, d := range catalog {
		switch d.Scope {
		case ScopeDeviceGroup, ScopeGlobal:
		default:
			t.Errorf("code %q has invalid scope %q", d.Code, d.Scope)
		}
	}
	// 除 6 码外不得有其他 device_group 档。
	for _, d := range catalog {
		if d.Scope == ScopeDeviceGroup {
			found := false
			for _, code := range deviceGroupScoped {
				if d.Code == code {
					found = true
				}
			}
			if !found {
				t.Errorf("unexpected device_group scoped code %q", d.Code)
			}
		}
	}
}

// TestCatalogRequires 断言 requires 依赖链（设计 §1.1②）。
func TestCatalogRequires(t *testing.T) {
	cases := []struct {
		code string
		want []string
	}{
		{"devices.view", nil},
		{"devices.edit", []string{"devices.view"}},
		{"devices.status", []string{"devices.view"}},
		{"devices.delete", []string{"devices.view"}},
		{"devices.disconnect", []string{"devices.view"}},
		{"users.create", []string{"users.view"}},
		{"users.force_logout", []string{"users.view"}},
		{"user_groups.membership", []string{"user_groups.view"}},
		{"strategies.create", []string{"strategies.view"}},
		{"strategies.assign", []string{"strategies.view", "users.view"}},
		{"address_books.share", []string{"address_books.view"}},
		{"servers.ban", []string{"servers.view"}},
		{"roles.assign", []string{"roles.view", "users.view"}},
	}
	for _, tc := range cases {
		got := Requirements(tc.code)
		if len(got) != len(tc.want) {
			t.Errorf("requires(%q) = %v, want %v", tc.code, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("requires(%q) = %v, want %v", tc.code, got, tc.want)
				break
			}
		}
	}
}

// TestSystemOnlyNotAssignable 断言 system_only 码不可分配（写入即 400 语义）。
func TestSystemOnlyNotAssignable(t *testing.T) {
	for _, code := range []string{"roles.create", "roles.edit", "roles.delete"} {
		d, ok := FindDefinition(code)
		if !ok {
			t.Fatalf("missing %s", code)
		}
		if d.Assignable || !d.SystemOnly {
			t.Errorf("%s must be assignable=false, system_only=true", code)
		}
		if IsAssignable(code) {
			t.Errorf("IsAssignable(%q) = true, want false", code)
		}
	}
	if !IsAssignable("devices.view") {
		t.Error("devices.view must be assignable")
	}
	if IsAssignable("no.such") {
		t.Error("unknown code must not be assignable")
	}
}
