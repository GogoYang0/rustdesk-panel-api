package repository

import (
	"context"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// PublicUserColumns 公共列清单（顺序稳定，供 Select 与列断言测试）。
// 敏感列（password/verifier/tfaSecret/emailVerificationCode）经白名单
// 方式默认排除，凭 WithSecrets 系列方法显式加载。
var PublicUserColumns = []string{
	"guid", "username", "displayName", "email", "note", "status", "isAdmin",
	"info", "thirdAuthType", "oidcSubject", "avatar", "strategyGuid",
	"userGroupGuid", "createdAt", "updatedAt",
}

// UserRepo users 表仓储。
type UserRepo struct {
	*GenericRepository[entity.User]
}

// NewUserRepo 构建仓储。
func NewUserRepo(db *gorm.DB) *UserRepo {
	return &UserRepo{GenericRepository: New[entity.User](db)}
}

// publicSelect 公共列查询链（排除敏感列）。
func (r *UserRepo) publicSelect(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx).Model(&entity.User{}).Select(PublicUserColumns)
}

// WithSecrets 返回全列查询链（显式加载敏感列，对齐参考 select:false 语义）。
func (r *UserRepo) WithSecrets(ctx context.Context) *gorm.DB {
	return r.db.WithContext(ctx).Model(&entity.User{})
}

// FindByGuid 公共列查询（payload 场景）。
func (r *UserRepo) FindByGuid(ctx context.Context, guid string) (*entity.User, error) {
	var u entity.User
	err := r.publicSelect(ctx).Where("guid = ?", guid).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByUsernameOrEmail 登录路径：username 或 email 匹配，全列加载
// （含 password/tfaSecret，设计场景 A）。
func (r *UserRepo) FindByUsernameOrEmail(ctx context.Context, ident string) (*entity.User, error) {
	var u entity.User
	err := r.WithSecrets(ctx).Where("username = ? OR email = ?", ident, ident).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByGuidWithSecrets 全列加载（两步登录复核等场景）。
func (r *UserRepo) FindByGuidWithSecrets(ctx context.Context, guid string) (*entity.User, error) {
	var u entity.User
	err := r.WithSecrets(ctx).Where("guid = ?", guid).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByOidcSubject 按 OIDC subject 绑定查找（全列，findOrCreate 场景）。
func (r *UserRepo) FindByOidcSubject(ctx context.Context, subject string) (*entity.User, error) {
	var u entity.User
	err := r.WithSecrets(ctx).Where("oidcSubject = ?", subject).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ProfilePatch 局部更新补丁；nil 表示不更新该字段。
type ProfilePatch struct {
	DisplayName *string
	Email       *string
	Note        *string
}

// UpdateProfile 局部更新资料（updatedAt 由 GORM 维护）。
func (r *UserRepo) UpdateProfile(ctx context.Context, guid string, p ProfilePatch) error {
	updates := map[string]any{}
	if p.DisplayName != nil {
		updates["displayName"] = *p.DisplayName
	}
	if p.Email != nil {
		updates["email"] = *p.Email
	}
	if p.Note != nil {
		updates["note"] = *p.Note
	}
	if len(updates) == 0 {
		return nil
	}
	err := r.db.WithContext(ctx).Model(&entity.User{}).Where("guid = ?", guid).Updates(updates).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// UpdateColumns 通用列更新（avatar / info / tfaSecret / oidcSubject 等场景）。
func (r *UserRepo) UpdateColumns(ctx context.Context, guid string, updates map[string]any) error {
	if len(updates) == 0 {
		return nil
	}
	err := r.db.WithContext(ctx).Model(&entity.User{}).Where("guid = ?", guid).Updates(updates).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	return err
}

// FindByEmail email 精确查询（创建/邀请冲突检查与 me 改密唯一性）。
func (r *UserRepo) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	var u entity.User
	err := r.WithSecrets(ctx).Where("email = ?", email).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ListAccessibleUsers 非 admin 三源并集（设计事实①）：自己 ∪
// user_user_permissions 授权用户 ∪ 授权设备组内设备的归属用户；
// 排序 username ASC（契约）。status 参数仅 admin 分支应用，此处不过滤。
func (r *UserRepo) ListAccessibleUsers(ctx context.Context, userGuid string) ([]entity.User, error) {
	rows := make([]entity.User, 0)
	err := r.publicSelect(ctx).
		Where("guid = ?"+
			" OR guid IN (SELECT targetUserGuid FROM user_user_permissions WHERE userGuid = ?)"+
			" OR guid IN (SELECT p.userGuid FROM peers p"+
			" JOIN device_group_user_permissions dgup ON dgup.deviceGroupGuid = p.deviceGroupGuid"+
			" AND dgup.userGuid = ? WHERE p.userGuid IS NOT NULL)",
			userGuid, userGuid, userGuid).
		Order("username ASC").
		Find(&rows).Error
	return rows, err
}

// ListUsersByStatus admin 分支：status 精确过滤（缺省 '1' 由服务层
// 归一），username ASC（契约）。
func (r *UserRepo) ListUsersByStatus(ctx context.Context, status int) ([]entity.User, error) {
	rows := make([]entity.User, 0)
	err := r.publicSelect(ctx).
		Where("status = ?", status).
		Order("username ASC").
		Find(&rows).Error
	return rows, err
}

// AdminUserRow GET /api/admin/users 行：用户列 + JOIN 名称列
// （strategy_name / user_group_name；role_names 与 is_protected 由
// 服务层批量组装）。
type AdminUserRow struct {
	entity.User
	StrategyName  *string `gorm:"column:strategyName"`
	UserGroupName *string `gorm:"column:userGroupName"`
}

// ListForAdmin admin/users 十过滤分页（契约 ListAdminUsersParams）：
// status 精确、name/email/strategy_name/user_group_name LIKE、
// is_admin/third_auth_type/user_group_guid 精确。排序 username ASC。
// 无任何过滤时可空值不拼接（动态链）。
func (r *UserRepo) ListForAdmin(ctx context.Context, f AdminUserFilter) ([]AdminUserRow, int64, error) {
	apply := func(q *gorm.DB) *gorm.DB {
		if f.Status != nil && *f.Status != "" {
			if st, err := strconv.Atoi(*f.Status); err == nil {
				q = q.Where("u.status = ?", st)
			}
		}
		if f.Name != "" {
			q = q.Where("u.username LIKE ? OR u.displayName LIKE ?", like(f.Name), like(f.Name))
		}
		if f.Email != "" {
			q = q.Where("u.email LIKE ?", like(f.Email))
		}
		if f.IsAdmin != nil {
			q = q.Where("u.isAdmin = ?", *f.IsAdmin == "1")
		}
		if f.ThirdAuthType != "" {
			q = q.Where("u.thirdAuthType = ?", f.ThirdAuthType)
		}
		if f.StrategyName != "" {
			q = q.Where("s.name LIKE ?", like(f.StrategyName))
		}
		if f.UserGroupGuid != "" {
			q = q.Where("u.userGroupGuid = ?", f.UserGroupGuid)
		}
		if f.UserGroupName != "" {
			q = q.Where("g.name LIKE ?", like(f.UserGroupName))
		}
		return q
	}
	base := func() *gorm.DB {
		return r.db.WithContext(ctx).Table("users u").
			Joins("LEFT JOIN strategies s ON s.guid = u.strategyGuid").
			Joins("LEFT JOIN user_groups g ON g.guid = u.userGroupGuid")
	}

	var total int64
	if err := apply(base().Session(&gorm.Session{})).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := apply(base().Session(&gorm.Session{})).
		Select("u.*, s.name AS strategyName, g.name AS userGroupName").
		Order("u.username ASC")
	if f.PageSize > 0 {
		fetch = fetch.Limit(f.PageSize)
		if f.Current > 1 {
			fetch = fetch.Offset((f.Current - 1) * f.PageSize)
		}
	}
	rows := make([]AdminUserRow, 0)
	if err := fetch.Scan(&rows).Error; err != nil {
		return nil, 0, err
	}
	return rows, total, nil
}

// AdminUserFilter admin/users 过滤（api.ListAdminUsersParams 的仓储侧
// 等价物，避免 repository 反向依赖 api 包）。
type AdminUserFilter struct {
	Status        *string
	Name          string
	Email         string
	IsAdmin       *string // "0" | "1"（空 = 不过滤）
	ThirdAuthType string
	StrategyName  string
	UserGroupGuid string
	UserGroupName string
	Current       int
	PageSize      int
}

// RoleNamesByGuids 批量取用户角色名（admin 行 role_names 组装；
// map[guid][]name，无角色用户不出现在映射中）。
func (r *UserRepo) RoleNamesByGuids(ctx context.Context, guids []string) (map[string][]string, error) {
	out := make(map[string][]string, len(guids))
	if len(guids) == 0 {
		return out, nil
	}
	type row struct {
		UserGuid string
		Name     string
	}
	rows := make([]row, 0)
	err := r.db.WithContext(ctx).Table("user_role_assignments ra").
		Select("ra.userGuid AS userGuid, ro.name AS name").
		Joins("JOIN roles ro ON ro.guid = ra.roleGuid").
		Where("ra.userGuid IN ?", guids).
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	for _, rw := range rows {
		out[rw.UserGuid] = append(out[rw.UserGuid], rw.Name)
	}
	return out, nil
}

// DeleteWithRelated 事务删除用户及其私有从属（应用层显式级联，共享
// 知识 9）：tokens/sessions/passkeys/assignments(+组范围)/uup 双侧/
// dgup/邀请引用置空；peers 归属保留（设备不随用户删除）。console_audits
// 保留（审计历史独立生命周期）。
func (r *UserRepo) DeleteWithRelated(ctx context.Context, guid string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("userGuid = ?", guid).Delete(&entity.UserToken{}).Error; err != nil {
			return err
		}
		if err := tx.Where("userGuid = ?", guid).Delete(&entity.LoginSession{}).Error; err != nil {
			return err
		}
		if err := tx.Where("userGuid = ?", guid).Delete(&entity.PasskeyCredential{}).Error; err != nil {
			return err
		}
		if err := tx.Exec("DELETE FROM user_role_assignment_device_groups WHERE assignmentGuid IN"+
			" (SELECT guid FROM user_role_assignments WHERE userGuid = ?)", guid).Error; err != nil {
			return err
		}
		if err := tx.Where("userGuid = ?", guid).Delete(&entity.UserRoleAssignment{}).Error; err != nil {
			return err
		}
		if err := tx.Where("userGuid = ?", guid).Delete(&entity.UserUserPermission{}).Error; err != nil {
			return err
		}
		if err := tx.Where("targetUserGuid = ?", guid).Delete(&entity.UserUserPermission{}).Error; err != nil {
			return err
		}
		if err := tx.Where("userGuid = ?", guid).Delete(&entity.DeviceGroupUserPermission{}).Error; err != nil {
			return err
		}
		if err := tx.Model(&entity.Invitation{}).Where("userGuid = ?", guid).
			Update("userGuid", nil).Error; err != nil {
			return err
		}
		return tx.Where("guid = ?", guid).Delete(&entity.User{}).Error
	})
}

// CountByDay 用户注册按日聚合（dashboard newUserTrend；createdAt
// 锚点，[from, to) 左闭右开；DayCount.Date 为 DATE() 产出的
// YYYY-MM-DD 字符串，双方言通用）。
func (r *UserRepo) CountByDay(ctx context.Context, from, to time.Time) ([]DayCount, error) {
	out := make([]DayCount, 0)
	err := r.db.WithContext(ctx).Model(&entity.User{}).
		Select("DATE(createdAt) AS date, COUNT(*) AS count").
		Where("createdAt >= ? AND createdAt < ?", from, to).
		Group("DATE(createdAt)").
		Order("date ASC").
		Scan(&out).Error
	return out, err
}
