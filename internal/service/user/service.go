// Package user 实现 user 域服务：管理端用户 CRUD/批量/邀请/安全，
// 以及 M1 交付的 me/avatar（profile.go、avatar.go，本包不动）。
//
// 权限面：顶层权限码由路由中间件（rbac.PermPolicy）执行；本层负责
// 按字段分权复核（PATCH users/{guid}）、条件授权（user_group_guid）
// 与目标保护账号复核（AssertUserMutation/AssertUsersMutation）。
// 固定文案红线：38 条逐字节见设计 §1.1 事实①。
package user

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/google/uuid"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/email"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// defaultFrontendURL 邀请链接回退基址（设计事实④：无 siteFrontendUrl
// 时 effectiveFrontendUrl 回退 http://localhost:3000；T07 settings
// store 落地后由装配层注入 store 值替换空串）。
const defaultFrontendURL = "http://localhost:3000"

// inviteTTL 邀请 token 有效期（设计事实①：7 天）。
const inviteTTL = 7 * 24 * time.Hour

// Service 管理端用户域服务（14 端点主体；me/avatar 在 Profile/Avatar）。
type Service struct {
	db       *gorm.DB
	users    *repository.UserRepo
	groups   *repository.UserGroupRepo
	invites  *repository.InvitationRepo
	tokens   *repository.UserTokenRepo
	sessions *repository.LoginSessionRepo
	authz    *rbac.AuthorizationService

	// mailer 邀请邮件发送器（nil 容忍：测试可注入禁用态）。
	mailer *email.Mailer

	// frontendURL 邀请链接 base；ownerUsername 系统所有者用户名
	//（装配期取 config.AdminUsername），所有者账号不可禁用/删除。
	frontendURL   string
	ownerUsername string
}

// NewService 构建管理端用户服务。frontendURL 传空串时回退
// defaultFrontendURL（T07 接线 settings store 前的缺省行为）。
func NewService(
	db *gorm.DB,
	users *repository.UserRepo,
	groups *repository.UserGroupRepo,
	invites *repository.InvitationRepo,
	tokens *repository.UserTokenRepo,
	sessions *repository.LoginSessionRepo,
	authz *rbac.AuthorizationService,
	mailer *email.Mailer,
	frontendURL, ownerUsername string,
) *Service {
	return &Service{
		db: db, users: users, groups: groups, invites: invites,
		tokens: tokens, sessions: sessions, authz: authz, mailer: mailer,
		frontendURL: frontendURL, ownerUsername: ownerUsername,
	}
}

// effectiveFrontendURL 邀请链接基址（空配置回退缺省）。
func (s *Service) effectiveFrontendURL() string {
	if s.frontendURL == "" {
		return defaultFrontendURL
	}
	return s.frontendURL
}

// isSystemOwner 目标是否系统所有者账号（不可禁用/删除）。
func (s *Service) isSystemOwner(u *entity.User) bool {
	return s.ownerUsername != "" && u.IsAdmin && u.Username == s.ownerUsername
}

// revokeActiveTokensTx 撤 token 兜底事务体（共享知识 23）：user_tokens
// 全量置 isRevoked + 删除未使用 login_sessions。必须在调用方事务内对
// tx 执行，任一半边失败由外层 Transaction 统一回滚（MIN-04：改密链路
// 与 status 变更/security/batch/force_logout/accept 五链路复用）。
func revokeActiveTokensTx(tx *gorm.DB, userGuid string) error {
	now := time.Now()
	if err := tx.Model(&entity.UserToken{}).
		Where("userGuid = ? AND isRevoked = ? AND expiresAt > ?", userGuid, false, now).
		Update("isRevoked", true).Error; err != nil {
		return err
	}
	return tx.Where("userGuid = ? AND used = ?", userGuid, false).
		Delete(&entity.LoginSession{}).Error
}

// revokeActiveTokens 在传入事务内撤 token 兜底（共享知识 23）：
// status 变更/security/batch/force_logout/accept 五链路复用。
func (s *Service) revokeActiveTokens(ctx context.Context, tx *gorm.DB, userGuid string) error {
	return revokeActiveTokensTx(tx, userGuid)
}

// userViewOf 实体 → UserView（Name = displayName 非空 ? displayName :
// username，UserTargetView 同款语义；email/note 空串归一为省略）。
func userViewOf(u *entity.User, isProtected bool) api.UserView {
	name := u.Username
	if u.DisplayName != "" {
		name = u.DisplayName
	}
	view := api.UserView{
		Guid:        u.Guid,
		Username:    u.Username,
		Name:        name,
		Status:      u.Status,
		IsProtected: isProtected,
	}
	if u.DisplayName != "" {
		dn := u.DisplayName
		view.DisplayName = &dn
	}
	if u.Email != "" {
		email := u.Email
		view.Email = &email
	}
	if u.Note != "" {
		note := u.Note
		view.Note = &note
	}
	if u.UserGroupGuid != nil && *u.UserGroupGuid != "" {
		view.UserGroupGuid = u.UserGroupGuid
	}
	return view
}

// parseStatusParam 解析 admin 分支 status 过滤（缺省 '1'；'0'/'-1'/'1'；
// 非法 → 400）。
func parseStatusParam(raw *string) (int, error) {
	val := "1"
	if raw != nil {
		val = *raw
	}
	switch val {
	case "1":
		return 1, nil
	case "0":
		return 0, nil
	case "-1":
		return -1, nil
	default:
		return 0, authsvc.BadRequest("Invalid status filter")
	}
}

// findUserOr404 按 guid 查用户；不存在 → 404 固定文案。
func (s *Service) findUserOr404(ctx context.Context, guid string) (*entity.User, error) {
	u, err := s.users.FindByGuid(ctx, guid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, authsvc.NotFound("User does not exist")
		}
		return nil, err
	}
	return u, nil
}

// assertGroupExists user_group_guid 指向的组必须存在（404，与
// usergroup 服务 msgGroupNotFound 同文案）。
func (s *Service) assertGroupExists(ctx context.Context, guid string) error {
	if _, err := s.groups.FindByID(ctx, guid); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return authsvc.NotFound("User group does not exist")
		}
		return err
	}
	return nil
}

// ListUsers GET /api/users（契约：username ASC；admin 分支 status 缺省
// '1' 过滤，显式 '0'/'-1' 可查停用/未验证；非 admin 三源并集不过滤）。
func (s *Service) ListUsers(ctx context.Context, actorGuid string, isAdmin bool, statusParam *string) (api.UserPage, error) {
	var rows []entity.User
	if isAdmin {
		status, err := parseStatusParam(statusParam)
		if err != nil {
			return api.UserPage{}, err
		}
		list, err := s.users.ListUsersByStatus(ctx, status)
		if err != nil {
			return api.UserPage{}, err
		}
		rows = list
	} else {
		list, err := s.users.ListAccessibleUsers(ctx, actorGuid)
		if err != nil {
			return api.UserPage{}, err
		}
		rows = list
	}

	guids := make([]string, 0, len(rows))
	for _, u := range rows {
		guids = append(guids, u.Guid)
	}
	protected, err := s.authz.GetEffectiveProtectionMap(ctx, guids)
	if err != nil {
		return api.UserPage{}, err
	}
	data := make([]api.UserView, 0, len(rows))
	for i := range rows {
		data = append(data, userViewOf(&rows[i], protected[rows[i].Guid]))
	}
	return api.UserPage{Data: data, Total: len(data)}, nil
}

// GetUser GET /api/users/{guid}（users.view 中间件已过）。
func (s *Service) GetUser(ctx context.Context, guid string) (api.UserView, error) {
	u, err := s.findUserOr404(ctx, guid)
	if err != nil {
		return api.UserView{}, err
	}
	protected, err := s.authz.IsProtectedUser(ctx, guid)
	if err != nil {
		if errors.Is(err, rbac.ErrUserNotFound) {
			return api.UserView{}, authsvc.NotFound("User does not exist")
		}
		return api.UserView{}, err
	}
	return userViewOf(u, protected), nil
}

// CreateUser POST /api/users（users.create 中间件已过；body 携带
// user_group_guid 时追加 user_groups.membership 条件授权）。重名
// 400 "Username already exists"；bcrypt(10)；响应 User created successfully。
func (s *Service) CreateUser(ctx context.Context, actorGuid string, req api.CreateUserRequest) (api.MessageResponse, error) {
	// 必填防御（spec required；生成类型无 validate 标签，服务层兜底）。
	if req.Username == "" || req.Name == "" || req.Password == "" || string(req.Email) == "" {
		return api.MessageResponse{}, authsvc.BadRequest("Username, name, email and password are required")
	}
	if req.UserGroupGuid != nil && *req.UserGroupGuid != "" {
		if _, err := s.authz.RequirePermission(ctx, actorGuid, rbac.CodeUserGroupsMembership); err != nil {
			return api.MessageResponse{}, err
		}
		if err := s.assertGroupExists(ctx, *req.UserGroupGuid); err != nil {
			return api.MessageResponse{}, err
		}
	}
	if dup, err := s.users.FindByUsername(ctx, req.Username); err != nil {
		if !errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, err
		}
	} else if dup != nil {
		return api.MessageResponse{}, authsvc.BadRequest("Username already exists")
	}
	if req.Email != "" {
		dup, err := s.users.FindByEmail(ctx, string(req.Email))
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, err
		}
		if dup != nil {
			return api.MessageResponse{}, authsvc.BadRequest("Email is already in use")
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		return api.MessageResponse{}, err
	}
	now := time.Now()
	u := &entity.User{
		Guid:          uuid.New().String(),
		Username:      req.Username,
		DisplayName:   req.Name, // 契约 name = 显示名（users 表无 name 列，映射 displayName）
		Email:         string(req.Email),
		Password:      string(hash),
		Note:          derefOrEmpty(req.Note),
		Status:        1, // ACTIVE
		UserGroupGuid: req.UserGroupGuid,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.db.WithContext(ctx).Create(u).Error; err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "User created successfully"}, nil
}

// derefOrEmpty 指针字符串取值（nil → ""）。
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// UpdateUser PATCH /api/users/{guid}（按字段分权，设计事实①）：
// name/display_name/email/note → users.edit；status → users.status；
// user_group_guid → user_groups.membership；is_admin 由 JSON 绑定层
// DisallowUnknownFields 一律 400；全空 body → 400 "No fields to
// update"；status 变更同事务撤 token；owner 不可禁用。
func (s *Service) UpdateUser(ctx context.Context, actorGuid, guid string, req api.UpdateUserRequest) (api.MessageResponse, error) {
	needEdit := req.Name != nil || req.DisplayName != nil || req.Email != nil || req.Note != nil
	needStatus := req.Status != nil
	needGroup := req.UserGroupGuid != nil
	if !needEdit && !needStatus && !needGroup {
		return api.MessageResponse{}, authsvc.BadRequest("No fields to update")
	}
	// 按字段分权复核（顶层无权限码，Auth 中间件已过）。
	if needEdit {
		if _, err := s.authz.RequirePermission(ctx, actorGuid, rbac.CodeUsersEdit); err != nil {
			return api.MessageResponse{}, err
		}
	}
	if needStatus {
		if _, err := s.authz.RequirePermission(ctx, actorGuid, rbac.CodeUsersStatus); err != nil {
			return api.MessageResponse{}, err
		}
	}
	if needGroup {
		if _, err := s.authz.RequirePermission(ctx, actorGuid, rbac.CodeUserGroupsMembership); err != nil {
			return api.MessageResponse{}, err
		}
	}

	target, err := s.findUserOr404(ctx, guid)
	if err != nil {
		return api.MessageResponse{}, err
	}
	if needStatus && *req.Status != 1 && s.isSystemOwner(target) {
		return api.MessageResponse{}, rbac.ErrForbidden(rbac.MsgOwnerAccountImmutable)
	}
	// email 冲突（更新为他人 email → 409）。
	if req.Email != nil && string(*req.Email) != "" && string(*req.Email) != target.Email {
		dup, err := s.users.FindByEmail(ctx, string(*req.Email))
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return api.MessageResponse{}, err
		}
		if dup != nil && dup.Guid != guid {
			return api.MessageResponse{}, rbac.ErrConflictMsg("Email is already in use")
		}
	}
	// user_group_guid 指向的组必须存在（404）。
	if needGroup && *req.UserGroupGuid != "" {
		if err := s.assertGroupExists(ctx, *req.UserGroupGuid); err != nil {
			return api.MessageResponse{}, err
		}
	}

	updates := map[string]any{"updatedAt": time.Now()}
	if req.Name != nil {
		updates["displayName"] = *req.Name
	}
	if req.DisplayName != nil {
		updates["displayName"] = *req.DisplayName
	}
	if req.Email != nil {
		updates["email"] = string(*req.Email)
	}
	if req.Note != nil {
		updates["note"] = *req.Note
	}
	if needGroup {
		updates["userGroupGuid"] = *req.UserGroupGuid
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&entity.User{}).Where("guid = ?", guid).Updates(updates).Error; err != nil {
			return err
		}
		if needStatus {
			if err := tx.Model(&entity.User{}).Where("guid = ?", guid).
				Update("status", int(*req.Status)).Error; err != nil {
				return err
			}
			// status 变更同事务撤 token（事实①/共享知识 23）。
			if err := s.revokeActiveTokens(ctx, tx, guid); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "User updated"}, nil
}

// DeleteUser DELETE /api/users/{guid}（users.delete 中间件已过 +
// AssertUserMutation 保护复核；owner 拒绝）。
func (s *Service) DeleteUser(ctx context.Context, actorGuid, guid string) (api.MessageResponse, error) {
	target, err := s.findUserOr404(ctx, guid)
	if err != nil {
		return api.MessageResponse{}, err
	}
	if s.isSystemOwner(target) {
		return api.MessageResponse{}, rbac.ErrForbidden(rbac.MsgOwnerAccountImmutable)
	}
	if err := s.authz.AssertUserMutation(ctx, actorGuid, guid, rbac.CodeUsersDelete); err != nil {
		return api.MessageResponse{}, err
	}
	if err := s.users.DeleteWithRelated(ctx, guid); err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "User deleted"}, nil
}

// UpdateUserSecurity PATCH /api/users/{guid}/security（users.security
// 中间件已过 + AssertUserMutation）：tfa_enforce/email_verification 写
// users.info JSON；new_password（≥6）管理员重置口令；不重置已登记
// 2FA/通行密钥；任何字段变更后统一撤 token。
func (s *Service) UpdateUserSecurity(ctx context.Context, actorGuid, guid string, req api.UpdateUserSecurityRequest) (api.MessageResponse, error) {
	if err := s.authz.AssertUserMutation(ctx, actorGuid, guid, rbac.CodeUsersSecurity); err != nil {
		return api.MessageResponse{}, err
	}
	hash := ""
	if req.NewPassword != nil {
		if len(*req.NewPassword) < 6 {
			return api.MessageResponse{}, authsvc.BadRequest("New password must be at least 6 characters")
		}
		raw, err := bcrypt.GenerateFromPassword([]byte(*req.NewPassword), 10)
		if err != nil {
			return api.MessageResponse{}, err
		}
		hash = string(raw)
	}
	if _, err := s.findUserOr404(ctx, guid); err != nil {
		return api.MessageResponse{}, err
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// info JSON 读-改-写（顶层键 tfa_enforce/email_verification；
		// 不触碰 other/隐蔽态键）。
		var u entity.User
		if err := tx.Where("guid = ?", guid).First(&u).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return authsvc.NotFound("User does not exist")
			}
			return err
		}
		info := map[string]any{}
		if u.Info != "" {
			if err := json.Unmarshal([]byte(u.Info), &info); err != nil || info == nil {
				info = map[string]any{}
			}
		}
		if req.TfaEnforce != nil {
			info["tfa_enforce"] = *req.TfaEnforce
		}
		if req.EmailVerification != nil {
			info["email_verification"] = *req.EmailVerification
		}
		updates := map[string]any{"updatedAt": time.Now()}
		rawInfo, err := json.Marshal(info)
		if err != nil {
			return err
		}
		updates["info"] = string(rawInfo)
		if hash != "" {
			updates["password"] = hash
		}
		if err := tx.Model(&entity.User{}).Where("guid = ?", guid).Updates(updates).Error; err != nil {
			return err
		}
		// 任何字段变更后统一撤 token。
		return s.revokeActiveTokens(ctx, tx, guid)
	})
	if err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Security settings updated"}, nil
}

// ForceLogout DELETE /api/users/{guid}/sessions（users.force_logout
// 中间件已过 + AssertUserMutation）：revokeActiveTokens。
func (s *Service) ForceLogout(ctx context.Context, actorGuid, guid string) (api.MessageResponse, error) {
	if err := s.authz.AssertUserMutation(ctx, actorGuid, guid, rbac.CodeUsersForceLogout); err != nil {
		return api.MessageResponse{}, err
	}
	if _, err := s.findUserOr404(ctx, guid); err != nil {
		return api.MessageResponse{}, err
	}
	if err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return s.revokeActiveTokens(ctx, tx, guid)
	}); err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Sessions deleted"}, nil
}

// ListAdminUsers GET /api/admin/users（users.view 中间件已过）：
// 十过滤分页 + role_names（admin 追加 'Super Admin'）+ is_protected +
// strategy_name/user_group_name；current/pageSize 契约缺省 1/20。
func (s *Service) ListAdminUsers(ctx context.Context, p api.ListAdminUsersParams) (api.AdminUserPage, error) {
	current, pageSize := 1, 20
	if p.Current != nil {
		current = *p.Current
	}
	if p.PageSize != nil {
		pageSize = *p.PageSize
	}
	filter := repository.AdminUserFilter{
		Status:        p.Status,
		Name:          derefOrEmpty(p.Name),
		Email:         derefOrEmpty(p.Email),
		IsAdmin:       (*string)(p.IsAdmin),
		ThirdAuthType: derefOrEmpty(p.ThirdAuthType),
		StrategyName:  derefOrEmpty(p.StrategyName),
		UserGroupGuid: derefOrEmpty(p.UserGroupGuid),
		UserGroupName: derefOrEmpty(p.UserGroupName),
		Current:       current,
		PageSize:      pageSize,
	}
	rows, total, err := s.users.ListForAdmin(ctx, filter)
	if err != nil {
		return api.AdminUserPage{}, err
	}
	guids := make([]string, 0, len(rows))
	for _, row := range rows {
		guids = append(guids, row.Guid)
	}
	protected, err := s.authz.GetEffectiveProtectionMap(ctx, guids)
	if err != nil {
		return api.AdminUserPage{}, err
	}
	roleNames, err := s.users.RoleNamesByGuids(ctx, guids)
	if err != nil {
		return api.AdminUserPage{}, err
	}

	// AdminUserPage.Data 为生成代码的内联匿名结构：以索引填充方式
	// 单点声明类型，规避两处字面量的类型恒等维护成本。
	page := api.AdminUserPage{
		Data: make([]struct {
			CreatedAt     *time.Time `json:"created_at,omitempty"`
			DisplayName   *string    `json:"display_name,omitempty"`
			Email         *string    `json:"email,omitempty"`
			Guid          string     `json:"guid"`
			IsAdmin       bool       `json:"is_admin"`
			IsProtected   bool       `json:"is_protected"`
			Name          string     `json:"name"`
			Note          *string    `json:"note,omitempty"`
			RoleNames     []string   `json:"role_names"`
			Status        int        `json:"status"`
			StrategyName  *string    `json:"strategy_name,omitempty"`
			UserGroupGuid *string    `json:"user_group_guid,omitempty"`
			UserGroupName *string    `json:"user_group_name,omitempty"`
			Username      string     `json:"username"`
		}, len(rows)),
		Total: int(total),
	}
	for i := range rows {
		row := &rows[i]
		item := &page.Data[i]

		names := roleNames[row.Guid]
		if names == nil {
			names = []string{}
		}
		if row.IsAdmin {
			names = append(names, "Super Admin")
		}
		name := row.Username
		if row.DisplayName != "" {
			name = row.DisplayName
		}

		item.Guid = row.Guid
		item.Username = row.Username
		item.Name = name
		item.IsAdmin = row.IsAdmin
		item.IsProtected = protected[row.Guid]
		item.RoleNames = names
		item.Status = row.Status
		item.StrategyName = row.StrategyName
		item.UserGroupName = row.UserGroupName
		if row.DisplayName != "" {
			dn := row.DisplayName
			item.DisplayName = &dn
		}
		if row.Email != "" {
			email := row.Email
			item.Email = &email
		}
		if row.Note != "" {
			note := row.Note
			item.Note = &note
		}
		if !row.CreatedAt.IsZero() {
			ca := row.CreatedAt
			item.CreatedAt = &ca
		}
		if row.UserGroupGuid != nil && *row.UserGroupGuid != "" {
			item.UserGroupGuid = row.UserGroupGuid
		}
	}
	return page, nil
}
