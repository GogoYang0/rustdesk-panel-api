package server

import (
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/email"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/handler"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	devicesvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/device"
	devicegroupsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/devicegroup"
	rbacsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/rbac"
	strategysvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/strategy"
	usersvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/user"
	usergroupsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/usergroup"
)

// Domain 装配完成的认证/用户/设备域服务容器（仓储 → 服务 → handler 全链）。
type Domain struct {
	Tokens  *authsvc.TokenService
	Login   *authsvc.AuthService
	Tfa     *authsvc.TfaService
	Passkey *authsvc.PasskeyService
	OIDC    *authsvc.OidcFlowService
	Cleanup *authsvc.CleanupService
	Profile *usersvc.ProfileService
	Avatar  *usersvc.AvatarService

	// Rbac 授权决策服务（T01 桩端口装配，T02 接真实仓储适配）；
	// RbacMW 为路由策略中间件族（HandlePolicy 使用）。
	Rbac   *rbac.AuthorizationService
	RbacMW *rbac.Middleware

	// 设备域（T03）：心跳/系统信息端协议 + /peers 查询 + /devices 管理。
	Heartbeat *handler.HeartbeatHandler
	Devices   *handler.DeviceHandler

	// 设备组与策略域（T04）：设备组 CRUD/accessible/strategy-targets/
	// 加减设备 + 策略 CRUD/候选/指派。
	DeviceGroups *handler.DeviceGroupHandler
	Strategy     *handler.StrategyHandler

	// RBAC 域与用户组域（T05）：权限目录/生效权限/角色 CRUD/保护影响/
	// 用户角色指派 + 用户组 CRUD/成员/移动。（RbacAPI 与上方 Rbac
	// 区分：前者为域端点集合，后者为授权决策服务。）
	RbacAPI    *handler.RbacHandler
	UserGroups *handler.UserGroupHandler

	Auth *handler.AuthHandler
	Oidc *handler.OidcHandler
	User *handler.UserHandler
}

// assembleDomain 依 deps.DB 构建域容器（router 装配期一次性调用）。
func assembleDomain(deps RouterDeps) (*Domain, error) {
	users := repository.NewUserRepo(deps.DB)
	tokenRepo := repository.NewUserTokenRepo(deps.DB)
	sessions := repository.NewLoginSessionRepo(deps.DB)
	creds := repository.NewPasskeyRepo(deps.DB)
	groups := repository.NewUserGroupRepo(deps.DB)
	providers := repository.NewOidcRepo(deps.DB)

	tokenSvc := authsvc.NewTokenService(tokenRepo, deps.Config.JWTSecret, deps.Config.JWTExpiryDays)
	tfaSvc := authsvc.NewTfaService(users, sessions, tokenSvc)
	passkeySvc, err := authsvc.NewPasskeyService(
		deps.Config.WebAuthnRPID, deps.Config.WebAuthnOrigins, users, sessions, creds, tokenSvc)
	if err != nil {
		return nil, err
	}
	loginSvc := authsvc.NewAuthService(users, tokenSvc, tfaSvc, passkeySvc)
	oidcSvc := authsvc.NewOidcFlowService(providers, users, groups, tokenSvc)
	cleanupSvc := authsvc.NewCleanupService(tokenRepo, sessions, providers, deps.Logger)

	profileSvc := usersvc.NewProfileService(users)
	avatarSvc := usersvc.NewAvatarService(users, deps.Config.DataDir)

	// RBAC 横切件：真实仓储适配（T02 起接通）。授权决策实时查库
	//（共享知识 3）；审计落 console_audits（denied 失败仅告警）。
	auditSvc := rbac.NewAuditService(repository.NewConsoleAuditRepo(deps.DB), deps.Logger)
	authzSvc := rbac.NewAuthorizationService(NewRBACStores(deps.DB), auditSvc)
	rbacMW := rbac.NewMiddleware(authzSvc)

	// 用户域（M3 T03）：管理端 CRUD/批量/邀请/安全。SMTP 配置经
	// 禁用态 provider 动态读取（T07 settings store 落地后接线
	// smtp.* 键，届时 SendInvitation 才能真实出站；当前恒降级
	// token 明文）；frontendURL 传空 → 服务层回退缺省值（事实④）。
	invites := repository.NewInvitationRepo(deps.DB)
	mailer := email.NewMailer(func() email.SmtpConfig { return email.SmtpConfig{} }, deps.Logger)
	userSvc := usersvc.NewService(
		deps.DB, users, groups, invites, tokenRepo, sessions, authzSvc,
		mailer, "", deps.Config.AdminUsername)

	authH := handler.NewAuthHandler(loginSvc, tfaSvc, passkeySvc, tokenSvc)
	oidcH, err := handler.NewOidcHandler(oidcSvc)
	if err != nil {
		return nil, err
	}
	userH := handler.NewUserHandler(profileSvc, avatarSvc, userSvc)

	// 设备域（T03）：协议（heartbeat/sysinfo）+ /peers 查询 + /devices
	// 管理。断连队列为进程内单例（DisconnectStore），心跳与管理动作
	// 共享同一实例才能形成"入队 → 心跳下发 → 确认出队"回路。
	peerRepo := repository.NewPeerRepo(deps.DB)
	connsRepo := repository.NewActiveConnectionRepo(deps.DB)
	sysinfoRepo := repository.NewSysinfoRepo(deps.DB)
	strategyRepo := repository.NewStrategyRepo(deps.DB)
	deviceGroupRepo := repository.NewDeviceGroupRepo(deps.DB)
	disconnects := devicesvc.NewDisconnectStore()

	heartbeatSvc := devicesvc.NewHeartbeatService(
		peerRepo, connsRepo, strategyRepo, users, deviceGroupRepo, disconnects, deps.Logger)
	sysinfoSvc := devicesvc.NewSysinfoService(peerRepo, sysinfoRepo, deviceGroupRepo, deps.Logger)
	querySvc := devicesvc.NewQueryService(peerRepo, sysinfoRepo, users, deviceGroupRepo, strategyRepo)
	adminSvc := devicesvc.NewAdminService(
		authzSvc, peerRepo, sysinfoRepo, users, deviceGroupRepo, strategyRepo, disconnects)

	heartbeatH := handler.NewHeartbeatHandler(heartbeatSvc, sysinfoSvc)
	deviceH := handler.NewDeviceHandler(authzSvc, querySvc, adminSvc)

	// 设备组与策略域（T04）：设备组（accessible/ListAccessible 双源、
	// device_count 批量计数、加减设备按 peer.id 命中）与策略（CRUD/
	// 候选/指派清单/assign 族宿主表回写）。
	groupSvc := devicegroupsvc.NewGroupService(authzSvc, deviceGroupRepo, peerRepo)
	strategySvc := strategysvc.NewService(authzSvc, strategyRepo, peerRepo, users, deviceGroupRepo)
	groupH := handler.NewDeviceGroupHandler(groupSvc)
	strategyH := handler.NewStrategyHandler(strategySvc)

	// RBAC 域与用户组域（T05）：角色写路径事务内显式审计（allowed
	// before/after 快照）；用户角色指派走 AssertUserMutation 防护链；
	// 用户组成员移动复用 AssertUsersMutation。
	roleRepo := repository.NewRoleRepo(deps.DB)
	rolePermRepo := repository.NewRolePermissionRepo(deps.DB)
	assignmentRepo := repository.NewAssignmentRepo(deps.DB)
	asgGroupRepo := repository.NewAssignmentGroupRepo(deps.DB)
	auditRepo := repository.NewConsoleAuditRepo(deps.DB)

	roleSvc := rbacsvc.NewRoleService(authzSvc, deps.DB, roleRepo, rolePermRepo, assignmentRepo, asgGroupRepo, auditRepo)
	userRoleSvc := rbacsvc.NewUserRoleService(authzSvc, deps.DB, roleRepo, rolePermRepo, assignmentRepo, asgGroupRepo, users, deviceGroupRepo, auditRepo)
	userGroupSvc := usergroupsvc.NewService(authzSvc, deps.DB, groups, users)
	rbacH := handler.NewRbacHandler(authzSvc, roleSvc, userRoleSvc)
	userGroupH := handler.NewUserGroupHandler(userGroupSvc)

	return &Domain{
		Tokens:       tokenSvc,
		Login:        loginSvc,
		Tfa:          tfaSvc,
		Passkey:      passkeySvc,
		OIDC:         oidcSvc,
		Cleanup:      cleanupSvc,
		Profile:      profileSvc,
		Avatar:       avatarSvc,
		Rbac:         authzSvc,
		RbacMW:       rbacMW,
		Heartbeat:    heartbeatH,
		Devices:      deviceH,
		DeviceGroups: groupH,
		Strategy:     strategyH,
		RbacAPI:      rbacH,
		UserGroups:   userGroupH,
		Auth:         authH,
		Oidc:         oidcH,
		User:         userH,
	}, nil
}
