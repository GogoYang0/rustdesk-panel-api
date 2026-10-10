package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

// widget 是泛型基座测试用最小实体（camelCase 列名，与生产实体同风格）。
type widget struct {
	Guid      string    `gorm:"column:guid;primaryKey;size:255"`
	Name      string    `gorm:"column:name;size:255"`
	IsRevoked bool      `gorm:"column:isRevoked;not null;default:false"`
	Counter   int       `gorm:"column:counter;not null;default:0"`
	ExpiresAt time.Time `gorm:"column:expiresAt"`
}

// TableName 指定表名。
func (widget) TableName() string { return "widgets" }

func newWidgetRepo(t *testing.T) (*GenericRepository[widget], context.Context) {
	t.Helper()
	db := testutil.NewMemoryDB(t)
	if err := db.AutoMigrate(&widget{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	return New[widget](db), context.Background()
}

func TestGenericRepositoryCRUD(t *testing.T) {
	repo, ctx := newWidgetRepo(t)

	e := &widget{Guid: "g-1", Name: "alpha", Counter: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := repo.Create(ctx, e); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.FindByID(ctx, "g-1")
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name != "alpha" {
		t.Errorf("Name = %q", got.Name)
	}

	got.Name = "beta"
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	again, _ := repo.FindByID(ctx, "g-1")
	if again.Name != "beta" {
		t.Errorf("after update Name = %q", again.Name)
	}

	if _, err := repo.FindByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("FindByID missing err = %v, want ErrNotFound", err)
	}

	if err := repo.Delete(ctx, Clause{Field: "guid", Op: OpEq, Value: "g-1"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.FindByID(ctx, "g-1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete err = %v, want ErrNotFound", err)
	}
}

func TestGenericRepositoryListAndClauses(t *testing.T) {
	repo, ctx := newWidgetRepo(t)
	now := time.Now()
	seed := []*widget{
		{Guid: "a", Name: "alpha", IsRevoked: false, Counter: 1, ExpiresAt: now.Add(1 * time.Hour)},
		{Guid: "b", Name: "bravo", IsRevoked: true, Counter: 2, ExpiresAt: now.Add(-1 * time.Hour)},
		{Guid: "c", Name: "charlie", IsRevoked: false, Counter: 3, ExpiresAt: now.Add(2 * time.Hour)},
	}
	for _, w := range seed {
		if err := repo.Create(ctx, w); err != nil {
			t.Fatalf("Create %s: %v", w.Guid, err)
		}
	}

	t.Run("eq + gt", func(t *testing.T) {
		items, total, err := repo.List(ctx, Query{
			Where: []Clause{
				{Field: "isRevoked", Op: OpEq, Value: false},
				{Field: "counter", Op: OpGt, Value: 1},
			},
		})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 1 || len(items) != 1 || items[0].Guid != "c" {
			t.Errorf("items = %+v total = %d", items, total)
		}
	})

	t.Run("in + order + limit", func(t *testing.T) {
		items, total, err := repo.List(ctx, Query{
			Where:   []Clause{{Field: "guid", Op: OpIn, Value: []string{"a", "b", "c"}}},
			OrderBy: "counter DESC",
			Limit:   2,
		})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 3 {
			t.Errorf("total = %d, want 3", total)
		}
		if len(items) != 2 || items[0].Guid != "c" || items[1].Guid != "b" {
			t.Errorf("items order = %+v", items)
		}
	})

	t.Run("lt for expiry sweep", func(t *testing.T) {
		items, total, err := repo.List(ctx, Query{
			Where: []Clause{{Field: "expiresAt", Op: OpLt, Value: now}},
		})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if total != 1 || items[0].Guid != "b" {
			t.Errorf("expired sweep = %+v (%d)", items, total)
		}
	})

	t.Run("neq + like + offset", func(t *testing.T) {
		items, _, err := repo.List(ctx, Query{
			Where:  []Clause{{Field: "guid", Op: OpNeq, Value: "a"}, {Field: "name", Op: OpLike, Value: "%ravo%"}},
			Offset: 0,
		})
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(items) != 1 || items[0].Guid != "b" {
			t.Errorf("items = %+v", items)
		}
	})
}

// TestPluck 验证 Go 1.27 方法级类型参数（泛型方法）：
// Pluck[E any] 在调用点实例化元素类型。
func TestPluck(t *testing.T) {
	repo, ctx := newWidgetRepo(t)
	seed := []*widget{
		{Guid: "g1", Name: "n1", IsRevoked: false},
		{Guid: "g2", Name: "n2", IsRevoked: false},
		{Guid: "g3", Name: "n3", IsRevoked: true},
	}
	for _, w := range seed {
		if err := repo.Create(ctx, w); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	jtis, err := repo.Pluck[string](ctx, "guid", Clause{Field: "isRevoked", Op: OpEq, Value: false})
	if err != nil {
		t.Fatalf("Pluck: %v", err)
	}
	if len(jtis) != 2 {
		t.Fatalf("jtis = %v, want 2", jtis)
	}

	counters, err := repo.Pluck[int](ctx, "counter")
	if err != nil {
		t.Fatalf("Pluck[int]: %v", err)
	}
	if len(counters) != 3 {
		t.Fatalf("counters = %v, want 3", counters)
	}
}
