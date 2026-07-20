package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// StringSet method 白名单集合（语义集合，值不区分顺序）。
type StringSet []string

// Contains 报告集合是否包含 s。
func (s StringSet) Contains(s2 string) bool {
	for _, v := range s {
		if v == s2 {
			return true
		}
	}
	return false
}

// LoginSessionRepo login_sessions 表仓储（两步验证临时会话）。
type LoginSessionRepo struct {
	*GenericRepository[entity.LoginSession]
}

// NewLoginSessionRepo 构建仓储。
func NewLoginSessionRepo(db *gorm.DB) *LoginSessionRepo {
	return &LoginSessionRepo{GenericRepository: New[entity.LoginSession](db)}
}

// FindUsable 查找可用会话：guid 匹配、method 在白名单、未使用、未过期。
func (r *LoginSessionRepo) FindUsable(ctx context.Context, guid string, methods StringSet) (*entity.LoginSession, error) {
	methodList := make([]string, len(methods))
	copy(methodList, methods)
	var s entity.LoginSession
	err := r.db.WithContext(ctx).
		Where("guid = ? AND method IN ? AND used = ? AND expiresAt > ?", guid, methodList, false, time.Now()).
		First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// DeleteExisting 清除同用户同方法的既有活跃会话
// （共享知识 7：TFA 建 tfa 会话前先 DeleteExisting，单活跃）。
func (r *LoginSessionRepo) DeleteExisting(ctx context.Context, userGuid, method string) error {
	return r.db.WithContext(ctx).
		Where("userGuid = ? AND method = ?", userGuid, method).
		Delete(&entity.LoginSession{}).Error
}

// MarkUsed 单次使用：标记 used=1（共享知识 3：用后即毁）。
func (r *LoginSessionRepo) MarkUsed(ctx context.Context, guid string) error {
	return r.db.WithContext(ctx).Model(&entity.LoginSession{}).
		Where("guid = ?", guid).
		Update("used", true).Error
}

// DeleteExpired 清理过期会话（cron 清理）；返回删除行数。
func (r *LoginSessionRepo) DeleteExpired(ctx context.Context) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("expiresAt < ?", time.Now()).
		Delete(&entity.LoginSession{})
	return res.RowsAffected, res.Error
}
