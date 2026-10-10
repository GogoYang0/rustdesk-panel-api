// Package repository 本文件：RoleRepo——roles 表仓储
// （RBAC 角色；重名判定大小写不敏感）。
package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// RoleRepo roles 表仓储。
type RoleRepo struct {
	*GenericRepository[entity.Role]
}

// NewRoleRepo 构建仓储。
func NewRoleRepo(db *gorm.DB) *RoleRepo {
	return &RoleRepo{GenericRepository: New[entity.Role](db)}
}

// FindByNameCI 大小写不敏感名称查询（角色重名 409 判定与按名取角色）。
func (r *RoleRepo) FindByNameCI(ctx context.Context, name string) (*entity.Role, error) {
	var role entity.Role
	err := r.db.WithContext(ctx).Where("LOWER(name) = LOWER(?)", name).First(&role).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &role, nil
}

// ListPaged 分页查询（name/note LIKE 过滤，可空；q 承载分页与排序，
// 附加 Where 条件原样保留）。
func (r *RoleRepo) ListPaged(ctx context.Context, name, note string, q Query) ([]entity.Role, int64, error) {
	conds := make([]Clause, 0, len(q.Where)+2)
	conds = append(conds, q.Where...)
	if name != "" {
		conds = append(conds, Clause{Field: "name", Op: OpLike, Value: like(name)})
	}
	if note != "" {
		conds = append(conds, Clause{Field: "note", Op: OpLike, Value: like(note)})
	}
	return r.List(ctx, Query{Where: conds, OrderBy: q.OrderBy, Limit: q.Limit, Offset: q.Offset})
}

// CountAssignments 统计持有该角色的指派数（角色删除影响面）。
func (r *RoleRepo) CountAssignments(ctx context.Context, guid string) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.UserRoleAssignment{}).
		Where("roleGuid = ?", guid).
		Count(&n).Error
	return n, err
}

// CreateTx 事务内插入角色行（创建与权限码写、审计同事务，共享知识 13）。
func (r *RoleRepo) CreateTx(tx *gorm.DB, e *entity.Role) error {
	return tx.Create(e).Error
}

// UpdateTx 事务内全量保存角色行。
func (r *RoleRepo) UpdateTx(tx *gorm.DB, e *entity.Role) error {
	return tx.Save(e).Error
}

// DeleteCascadeTx 事务内级联删除角色：role_permissions、
// user_role_assignment_device_groups、user_role_assignments、roles 行
// 全部显式清理（方言无关，共享知识 9；关联行先删、角色行最后删）。
func (r *RoleRepo) DeleteCascadeTx(tx *gorm.DB, guid string) error {
	if err := tx.Where("roleGuid = ?", guid).
		Delete(&entity.RolePermission{}).Error; err != nil {
		return err
	}
	var asgGuids []string
	if err := tx.Model(&entity.UserRoleAssignment{}).
		Where("roleGuid = ?", guid).
		Pluck("guid", &asgGuids).Error; err != nil {
		return err
	}
	if len(asgGuids) > 0 {
		if err := tx.Where("assignmentGuid IN ?", asgGuids).
			Delete(&entity.UserRoleAssignmentDeviceGroup{}).Error; err != nil {
			return err
		}
	}
	if err := tx.Where("roleGuid = ?", guid).
		Delete(&entity.UserRoleAssignment{}).Error; err != nil {
		return err
	}
	return tx.Where("guid = ?", guid).Delete(&entity.Role{}).Error
}
