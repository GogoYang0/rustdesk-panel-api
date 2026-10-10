// Package repository 是唯一允许直接写 GORM 的层。
//
// GenericRepository[T] 为泛型仓储基座（Go 1.27：方法级类型参数，
// 见 Pluck）；具体表仓储以组合嵌入扩展。
// 约定：所有实体主键列名为 guid（uuid v4 字符串，共享知识 3）；
// 条件 Field 使用数据库列名（camelCase，与迁移 SQL 逐列一致）。
package repository

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// Op 条件运算符。
type Op string

const (
	OpEq      Op = "eq"
	OpNeq     Op = "neq"
	OpGt      Op = "gt"
	OpGte     Op = "gte"
	OpLt      Op = "lt"
	OpLte     Op = "lte"
	OpIn      Op = "in"
	OpLike    Op = "like"
	OpIsNull  Op = "isnull"
	OpNotNull Op = "notnull"
)

// Clause 单个查询条件；Field 必须是代码内常量列名（禁止外部输入拼接）。
type Clause struct {
	Field string
	Op    Op
	Value any
}

// Query 列表查询参数。
type Query struct {
	Where   []Clause
	OrderBy string // 列名 + 方向，如 "createdAt DESC"
	Limit   int
	Offset  int
}

// ErrNotFound 统一未找到错误（仓储层不泄漏 gorm 错误类型）。
var ErrNotFound = errors.New("repository: record not found")

// GenericRepository 泛型仓储基座。
type GenericRepository[T any] struct {
	db *gorm.DB
}

// New 构建针对实体 T 的仓储。
func New[T any](db *gorm.DB) *GenericRepository[T] {
	return &GenericRepository[T]{db: db}
}

// applyClause 将单个条件落到查询链。
func applyClause(q *gorm.DB, c Clause) *gorm.DB {
	switch c.Op {
	case OpNeq:
		return q.Where(fmt.Sprintf("%s <> ?", c.Field), c.Value)
	case OpGt:
		return q.Where(fmt.Sprintf("%s > ?", c.Field), c.Value)
	case OpGte:
		return q.Where(fmt.Sprintf("%s >= ?", c.Field), c.Value)
	case OpLt:
		return q.Where(fmt.Sprintf("%s < ?", c.Field), c.Value)
	case OpLte:
		return q.Where(fmt.Sprintf("%s <= ?", c.Field), c.Value)
	case OpIn:
		return q.Where(fmt.Sprintf("%s IN ?", c.Field), c.Value)
	case OpLike:
		return q.Where(fmt.Sprintf("%s LIKE ?", c.Field), c.Value)
	case OpIsNull:
		return q.Where(fmt.Sprintf("%s IS NULL", c.Field))
	case OpNotNull:
		return q.Where(fmt.Sprintf("%s IS NOT NULL", c.Field))
	default:
		return q.Where(fmt.Sprintf("%s = ?", c.Field), c.Value)
	}
}

// scoped 返回应用了全部条件的查询链。
func (r *GenericRepository[T]) scoped(ctx context.Context, conds []Clause) *gorm.DB {
	q := r.db.WithContext(ctx).Model(new(T))
	for _, c := range conds {
		q = applyClause(q, c)
	}
	return q
}

// Scoped 返回裸查询句柄（供具体仓储构建复杂查询）。
func (r *GenericRepository[T]) Scoped(ctx context.Context, conds ...Clause) *gorm.DB {
	return r.scoped(ctx, conds)
}

// Create 插入实体。
func (r *GenericRepository[T]) Create(ctx context.Context, e *T) error {
	return r.db.WithContext(ctx).Create(e).Error
}

// FindByID 按主键 guid 查询；未找到返回 ErrNotFound。
func (r *GenericRepository[T]) FindByID(ctx context.Context, id string) (*T, error) {
	var e T
	err := r.db.WithContext(ctx).Where("guid = ?", id).First(&e).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// List 分页查询，返回记录与总数（Count 与 Find 使用独立语句，互不污染）。
func (r *GenericRepository[T]) List(ctx context.Context, q Query) ([]T, int64, error) {
	var total int64
	if err := r.scoped(ctx, q.Where).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := r.scoped(ctx, q.Where)
	if q.OrderBy != "" {
		fetch = fetch.Order(q.OrderBy)
	}
	if q.Limit > 0 {
		fetch = fetch.Limit(q.Limit)
	}
	if q.Offset > 0 {
		fetch = fetch.Offset(q.Offset)
	}
	out := make([]T, 0)
	if err := fetch.Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// Update 全量保存实体（按主键 guid，含零值列）。
func (r *GenericRepository[T]) Update(ctx context.Context, e *T) error {
	return r.db.WithContext(ctx).Save(e).Error
}

// Delete 按单条件删除。
func (r *GenericRepository[T]) Delete(ctx context.Context, cond Clause) error {
	return r.scoped(ctx, []Clause{cond}).Delete(new(T)).Error
}

// Pluck 方法级类型参数（Go 1.27 泛型方法）：抽取任意列的值列表。
// 典型用途：列出某用户全部活跃 jti。column 必须是代码内常量列名。
func (r *GenericRepository[T]) Pluck[E any](ctx context.Context, column string, conds ...Clause) ([]E, error) {
	q := r.scoped(ctx, conds)
	out := make([]E, 0)
	if err := q.Pluck(column, &out).Error; err != nil {
		return nil, err
	}
	return out, nil
}
