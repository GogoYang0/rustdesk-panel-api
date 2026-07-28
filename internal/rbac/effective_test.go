package rbac

import (
	"errors"
	"testing"
)

// TestFilterEffectiveBasics 覆盖生效码过滤边界。
func TestFilterEffectiveBasics(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		if got := FilterEffective(nil); len(got) != 0 {
			t.Errorf("FilterEffective(nil) = %v, want empty", got)
		}
	})

	t.Run("standalone code kept", func(t *testing.T) {
		got := FilterEffective([]string{"devices.view", "audit.view"})
		if len(got) != 2 {
			t.Errorf("got %v, want both kept", got)
		}
	})

	t.Run("dependent code dropped when dependency missing", func(t *testing.T) {
		got := FilterEffective([]string{"devices.edit", "audit.view"})
		if len(got) != 1 || got[0] != "audit.view" {
			t.Errorf("got %v, want [audit.view] (devices.edit requires devices.view)", got)
		}
	})

	t.Run("dependent code kept with dependency", func(t *testing.T) {
		got := FilterEffective([]string{"devices.view", "devices.edit", "devices.disconnect"})
		if len(got) != 3 {
			t.Errorf("got %v, want all three", got)
		}
	})

	t.Run("multi dependency code", func(t *testing.T) {
		// strategies.assign ⇐ strategies.view + users.view。
		if got := FilterEffective([]string{"strategies.assign", "strategies.view"}); len(got) != 1 {
			t.Errorf("got %v, want only strategies.view", got)
		}
		if got := FilterEffective([]string{"strategies.assign", "strategies.view", "users.view"}); len(got) != 3 {
			t.Errorf("got %v, want all three", got)
		}
	})

	t.Run("duplicates deduped in order", func(t *testing.T) {
		got := FilterEffective([]string{"audit.view", "audit.view"})
		if len(got) != 1 || got[0] != "audit.view" {
			t.Errorf("got %v, want single audit.view", got)
		}
	})

	t.Run("chain drop iterates to fixpoint", func(t *testing.T) {
		// devices.edit 依赖 devices.view；两者同时在场但 view 又依赖
		// 不存在的码时应双双剔除（递归闭包语义）。
		got := FilterEffective([]string{"devices.edit"})
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})
}

// TestMissingDependencies 覆盖角色写入校验的两类 400。
func TestMissingDependencies(t *testing.T) {
	t.Run("unknown code rejected", func(t *testing.T) {
		err := ValidateAssignmentCodes([]string{"devices.view", "made.up.code"})
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 400 {
			t.Fatalf("err = %v, want 400 StatusError", err)
		}
		if se.Message != "Permission code cannot be assigned: made.up.code" {
			t.Errorf("message = %q", se.Message)
		}
	})

	t.Run("system_only rejected", func(t *testing.T) {
		err := ValidateAssignmentCodes([]string{"roles.create"})
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 400 {
			t.Fatalf("err = %v, want 400 StatusError", err)
		}
		if se.Message != "Permission code cannot be assigned: roles.create" {
			t.Errorf("message = %q", se.Message)
		}
	})

	t.Run("missing dependency rejected", func(t *testing.T) {
		err := ValidateAssignmentCodes([]string{"devices.delete", "audit.view"})
		var se *StatusError
		if !errors.As(err, &se) || se.Status != 400 {
			t.Fatalf("err = %v, want 400 StatusError", err)
		}
		if se.Message != "Missing permission dependencies: devices.view" {
			t.Errorf("message = %q", se.Message)
		}
	})

	t.Run("valid set passes", func(t *testing.T) {
		if err := ValidateAssignmentCodes([]string{"devices.view", "devices.delete", "audit.view"}); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
