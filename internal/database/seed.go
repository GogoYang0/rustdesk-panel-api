package database

import (
	"context"
	"errors"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"uuid"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// seedBcryptCost 对齐参考 bcryptjs 的 cost 10。
const seedBcryptCost = 10

// Seed 幂等种子：默认用户组（isDefault=1）+ 默认管理员（§5 T03）。
// 管理员账号由 env 覆盖（ADMIN_USERNAME/ADMIN_EMAIL/ADMIN_PASSWORD，
// 批复事项 #5）；仅当不存在任何管理员时创建（UQ_users_single_owner 语义）。
// 迁移 SQL 内含等效种子注释样例；本函数是 Go 侧兜底实现（设计 §3.2）。
func Seed(ctx context.Context, db *gorm.DB, adminUsername, adminEmail, adminPassword string) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. 默认用户组：normalizedName = default。
		var group entity.UserGroup
		err := tx.Where("normalizedName = ?", "default").First(&group).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			group = entity.UserGroup{
				Guid:           uuid.New().String(),
				Name:           "Default",
				NormalizedName: "default",
				IsDefault:      true,
			}
			if err := tx.Create(&group).Error; err != nil {
				return err
			}
		case err != nil:
			return err
		}

		// 2. 默认管理员：仅当无管理员时创建（幂等）。
		var adminCount int64
		if err := tx.Model(&entity.User{}).Where("isAdmin = ?", true).Count(&adminCount).Error; err != nil {
			return err
		}
		if adminCount == 0 {
			hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), seedBcryptCost)
			if err != nil {
				return err
			}
			groupGuid := group.Guid
			admin := entity.User{
				Guid:          uuid.New().String(),
				Username:      adminUsername,
				Email:         adminEmail,
				Password:      string(hash),
				Status:        1,
				IsAdmin:       true,
				UserGroupGuid: &groupGuid,
			}
			if err := tx.Create(&admin).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// SeedAdminExists 报告管理员是否已存在（种子幂等性测试用）。
func SeedAdminExists(ctx context.Context, db *gorm.DB) (bool, error) {
	var count int64
	if err := db.WithContext(ctx).Model(&entity.User{}).Where("isAdmin = ?", true).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
