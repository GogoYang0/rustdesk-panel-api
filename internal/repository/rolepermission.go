// Package repository 本文件：RolePermissionRepo——role_permissions
// 表仓储（角色权限码关联）。
package repository

import (
	"context"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// rolePermissionRow CodesByRoles 的扫描行（显式列 tag 保证 camelCase
// 列名映射，SQLite/MySQL 双方言一致）。
type rolePermissionRow struct {
	RoleGuid       string `gorm:"column:roleGuid"`
	PermissionCode string `gorm:"column:permissionCode"`
}

// RolePermissionRepo role_permissions 表仓储。
type RolePermissionRepo struct {
	*GenericRepository[entity.RolePermission]
}

// NewRolePermissionRepo 构建仓储。
func NewRolePermissionRepo(db *gorm.DB) *RolePermissionRepo {
	return &RolePermissionRepo{GenericRepository: New[entity.RolePermission](db)}
}

// CodesByRoles roleGuid → 权限码列表（rbac 授权决策端口；未出现的
// roleGuid 映射为空/缺失）。
func (r *RolePermissionRepo) CodesByRoles(ctx context.Context, roleGuids []string) (map[string][]string, error) {
	out := make(map[string][]string, len(roleGuids))
	if len(roleGuids) == 0 {
		return out, nil
	}
	rows := make([]rolePermissionRow, 0)
	err := r.db.WithContext(ctx).Model(&entity.RolePermission{}).
		Where("roleGuid IN ?", roleGuids).
		Select("roleGuid", "permissionCode").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.RoleGuid] = append(out[row.RoleGuid], row.PermissionCode)
	}
	return out, nil
}

// ReplaceForRole 事务整删整插角色权限码（角色更新全量重建语义）。
func (r *RolePermissionRepo) ReplaceForRole(ctx context.Context, roleGuid string, codes []string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return r.ReplaceForRoleTx(tx, roleGuid, codes)
	})
}

// ReplaceForRoleTx ReplaceForRole 的事务变体：服务层把权限码重建与
// 事务内 allowed 审计编排在同一事务（共享知识 13）。
func (r *RolePermissionRepo) ReplaceForRoleTx(tx *gorm.DB, roleGuid string, codes []string) error {
	if err := tx.Where("roleGuid = ?", roleGuid).
		Delete(&entity.RolePermission{}).Error; err != nil {
		return err
	}
	for _, code := range codes {
		row := &entity.RolePermission{RoleGuid: roleGuid, PermissionCode: code}
		if err := tx.Create(row).Error; err != nil {
			return err
		}
	}
	return nil
}

// DeleteByRole 删除角色全部权限码（角色删除级联，T05）。
func (r *RolePermissionRepo) DeleteByRole(ctx context.Context, roleGuid string) error {
	return r.db.WithContext(ctx).
		Where("roleGuid = ?", roleGuid).
		Delete(&entity.RolePermission{}).Error
}
