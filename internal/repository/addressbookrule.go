// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：AddressBookRuleRepo——address_book_rules 表仓储
// （规则并集判定的底座：RulesForUser / MaxRuleForUser / ExistsForUser，
// 设计事实⑦ + M2 批复 #4 落点）。
package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// AddressBookRuleRepo address_book_rules 表仓储。
type AddressBookRuleRepo struct {
	*GenericRepository[entity.AddressBookRule]
}

// NewAddressBookRuleRepo 构建仓储。
func NewAddressBookRuleRepo(db *gorm.DB) *AddressBookRuleRepo {
	return &AddressBookRuleRepo{GenericRepository: New[entity.AddressBookRule](db)}
}

// Upsert 规则落库（复合 PK (guid, addressBookGuid) 冲突即更新
// rule/target 双列；target 列 nil 置 NULL——撤指定语义）。
func (r *AddressBookRuleRepo) Upsert(ctx context.Context, rule *entity.AddressBookRule) error {
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "guid"}, {Name: "addressBookGuid"}},
		DoUpdates: clause.Assignments(map[string]any{
			"rule":          rule.Rule,
			"targetUserId":  rule.TargetUserId,
			"targetGroupId": rule.TargetGroupId,
		}),
	}).Create(rule).Error
}

// DeleteByGuids 按 guid 批删（DELETE rules 复数契约）。
func (r *AddressBookRuleRepo) DeleteByGuids(ctx context.Context, guids []string) error {
	if len(guids) == 0 {
		return nil
	}
	return r.db.WithContext(ctx).
		Where("guid IN ?", guids).
		Delete(&entity.AddressBookRule{}).Error
}

// DeleteByBook 删书全部规则（书级联半边）。
func (r *AddressBookRuleRepo) DeleteByBook(ctx context.Context, bookGuid string) error {
	return r.db.WithContext(ctx).
		Where("addressBookGuid = ?", bookGuid).
		Delete(&entity.AddressBookRule{}).Error
}

// DeleteByTargetGroup 删某用户组的全部规则（user-group 删除事务内
// 显式执行，M2 批复 #4：deleted_rule_count 真实计数配套）。
func (r *AddressBookRuleRepo) DeleteByTargetGroup(ctx context.Context, groupGuid string) error {
	return r.db.WithContext(ctx).
		Where("targetGroupId = ?", groupGuid).
		Delete(&entity.AddressBookRule{}).Error
}

// DeleteByTargetGroupTx 事务版删组规则（M2 批复 #4）：返回实际删除
// 行数（deleted_rule_count），与成员回落/删组同一事务提交。
func (r *AddressBookRuleRepo) DeleteByTargetGroupTx(tx *gorm.DB, groupGuid string) (int64, error) {
	res := tx.Where("targetGroupId = ?", groupGuid).
		Delete(&entity.AddressBookRule{})
	return res.RowsAffected, res.Error
}

// CountByTargetGroup 计某用户组的规则数（删除前计数/确认弹窗）。
func (r *AddressBookRuleRepo) CountByTargetGroup(ctx context.Context, groupGuid string) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.AddressBookRule{}).
		Where("targetGroupId = ?", groupGuid).
		Count(&n).Error
	return n, err
}

// RulesForUser 书内命中目标用户的全部规则（targetUserId=我 /
// targetGroupId∈我所在组 / 双空=everyone）。
func (r *AddressBookRuleRepo) RulesForUser(ctx context.Context, bookGuid, userGuid string, groupGuids []string) ([]entity.AddressBookRule, error) {
	out := make([]entity.AddressBookRule, 0)
	err := r.db.WithContext(ctx).
		Where("addressBookGuid = ? AND (targetUserId = ? OR targetGroupId IN ?"+
			" OR (targetUserId IS NULL AND targetGroupId IS NULL))",
			bookGuid, userGuid, groupGuids).
		Find(&out).Error
	return out, err
}

// ListByBooks 多书规则枚举（GET /api/ab/rules 的 ab 缺省分支底座；
// 排序 createdAt ASC + guid ASC 确定性输出）。
func (r *AddressBookRuleRepo) ListByBooks(ctx context.Context, bookGuids []string) ([]entity.AddressBookRule, error) {
	out := make([]entity.AddressBookRule, 0)
	if len(bookGuids) == 0 {
		return out, nil
	}
	err := r.db.WithContext(ctx).
		Where("addressBookGuid IN ?", bookGuids).
		Order("createdAt ASC, guid ASC").
		Find(&out).Error
	return out, err
}

// FindByBookAndTarget 精确定位规则（createRule 重复判定 409
// 'This rule already exists'；target 空=IS NULL everyone 语义）。
func (r *AddressBookRuleRepo) FindByBookAndTarget(ctx context.Context, bookGuid string, targetUserId, targetGroupId *string) (*entity.AddressBookRule, error) {
	var rule entity.AddressBookRule
	q := r.db.WithContext(ctx).Where("addressBookGuid = ?", bookGuid)
	if targetUserId != nil {
		q = q.Where("targetUserId = ?", *targetUserId)
	} else {
		q = q.Where("targetUserId IS NULL")
	}
	if targetGroupId != nil {
		q = q.Where("targetGroupId = ?", *targetGroupId)
	} else {
		q = q.Where("targetGroupId IS NULL")
	}
	err := q.First(&rule).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

// MaxRuleForUser 规则并集最大值（无命中返回 0；owner 提升
// FULL_CONTROL 由服务层叠加）。
func (r *AddressBookRuleRepo) MaxRuleForUser(ctx context.Context, bookGuid, userGuid string, groupGuids []string) (int, error) {
	var max sql.NullInt64
	err := r.db.WithContext(ctx).Model(&entity.AddressBookRule{}).
		Select("MAX(rule)").
		Where("addressBookGuid = ? AND (targetUserId = ? OR targetGroupId IN ?"+
			" OR (targetUserId IS NULL AND targetGroupId IS NULL))",
			bookGuid, userGuid, groupGuids).
		Scan(&max).Error
	if err != nil {
		return 0, err
	}
	return int(max.Int64), nil
}

// ExistsForUser EXTERNAL_GRANT_EXISTS 判定：存在 targetUserId=我 的
// 规则即视为可访问（含 shared 书 owner 校验，设计事实⑦）。
func (r *AddressBookRuleRepo) ExistsForUser(ctx context.Context, bookGuid, userGuid string) (bool, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.AddressBookRule{}).
		Where("addressBookGuid = ? AND targetUserId = ?", bookGuid, userGuid).
		Count(&n).Error
	return n > 0, err
}
