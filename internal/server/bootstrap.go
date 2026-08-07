package server

import (
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/handler"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	devicesvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/device"
	devicegroupsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/devicegroup"
	strategysvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/strategy"
	usersvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/user"
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

	authH := handler.NewAuthHandler(loginSvc, tfaSvc, passkeySvc, tokenSvc)
	oidcH, err := handler.NewOidcHandler(oidcSvc)
	if err != nil {
		return nil, err
	}
	userH := handler.NewUserHandler(profileSvc, avatarSvc)

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
		Auth:         authH,
		Oidc:         oidcH,
		User:         userH,
	}, nil
}
