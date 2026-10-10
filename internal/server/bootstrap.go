package server

import (
	"fmt"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/email"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/handler"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	auditsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/audit"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	absvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/addressbook"
	dashboardsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/dashboard"
	devicesvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/device"
	devicegroupsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/devicegroup"
	nexussvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/nexus"
	oidcadmin "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/oidcadmin"
	rbacsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/rbac"
	servermgmt "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/servermgmt"
	settingssvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/settings"
	strategysvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/strategy"
	updatechecksvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/updatecheck"
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

	// 审计域与仪表盘域（T04）：上报三端（Public 档在路由）+ 查询
	// 六端（audit.view / devices.disconnect / SuperAdmin）+ 仪表盘
	// 聚合与趋势（双端点 SuperAdmin）。
	Audit     *handler.AuditHandler
	Dashboard *handler.DashboardHandler

	// 通讯录域（M3 T05）：legacy 双端点（兼容怪癖三件套）+ settings/
	// personal/custom/shared profiles + peers/tags/peer/tag + rules。
	AddressBook *handler.AddressBookHandler

	// 服务器管理域（M3 T06，事实③）：经 agent 转发 hbbs/hbbr /v1，
	// 启动校验 RUSTDESK_NODES（失败 fail-fast）。
	ServerMGMT *handler.ServerMGMTHandler

	// nexus 域（M3 T06，事实⑤）：GitHub 设备码绑定 + 定制构建生命周期
	// + 产物 safeJoin 下载；后台 10s poller 由 main 启动（Nexus.Start）。
	Nexus *handler.NexusHandler

	// 设置域（M3 T07，事实④）：frontend 公开 + general/smtp/ldap 读写
	// 与连通性测试（test 恒 200）。
	Settings *handler.SettingsHandler

	// OIDC 提供者管理域（M3 T07，事实⑧）：CRUD/sort/toggle/test。
	OidcAdmin *handler.OidcAdminHandler

	// 更新检查域（M3 T07，事实④）：GET /api/update-check（AdminGuard）。
	UpdateCheck *handler.UpdateCheckHandler

	// UpdateCheckScheduler 后台每小时调度器（main 显式启动）。
	UpdateCheckScheduler *updatechecksvc.Scheduler

	// NexusPoller nexus 构建轮询服务（main 显式 Start 启动后台 10s 轮询）。
	NexusPoller *nexussvc.NexusService

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

	// 设置域 KV 存储（GAP2 前移：mfa.* 策略与保留期清理读取口在认证域
	// 装配期即需引用；其余 settings 子服务仍在设置域段构建）。
	settingRepo := repository.NewSystemSettingRepo(deps.DB)
	settingStore := settingssvc.NewStore(settingRepo)
	settingGeneral := settingssvc.NewGeneralService(settingStore)

	tokenSvc := authsvc.NewTokenService(tokenRepo, deps.Config.JWTSecret, deps.Config.JWTExpiryDays)
	tfaSvc := authsvc.NewTfaService(users, sessions, tokenSvc)
	passkeySvc, err := authsvc.NewPasskeyService(
		deps.Config.WebAuthnRPID, deps.Config.WebAuthnOrigins, users, sessions, creds, tokenSvc)
	if err != nil {
		return nil, err
	}
	loginSvc := authsvc.NewAuthService(users, tokenSvc, tfaSvc, passkeySvc)
	oidcSvc := authsvc.NewOidcFlowService(providers, users, groups, tokenSvc)

	// GAP2 强制 MFA + 登录审计：策略键目录（mfa.*，category=mfa）+ 绑定
	// 服务 + best-effort 审计记录器；三登录收敛点统一判定（OQ-3）。
	settingMfa := settingssvc.NewMfaService(settingStore)
	loginAudits := repository.NewLoginAuditRepo(deps.DB)
	loginAuditRecorder := authsvc.NewLoginAuditRecorder(loginAudits, deps.Logger)
	mfaSvc := authsvc.NewMfaService(users, sessions, tokenSvc, settingMfa).WithLogin(loginSvc).WithAuditRecorder(loginAuditRecorder)
	loginSvc.WithMfa(mfaSvc, loginAuditRecorder)
	tfaSvc.WithAuditRecorder(loginAuditRecorder)
	passkeySvc.WithMfa(mfaSvc, loginAuditRecorder)
	oidcSvc.WithMfa(mfaSvc, loginAuditRecorder)

	cleanupSvc := authsvc.NewCleanupService(tokenRepo, sessions, providers, deps.Logger)
	// GAP2 OQ-7：login_audits 纳入 general.auditRetentionDays 清理任务。
	cleanupSvc.WithLoginAuditRetention(loginAudits, settingGeneral)

	profileSvc := usersvc.NewProfileService(deps.DB, users, tokenRepo, sessions)
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

	authH := handler.NewAuthHandler(loginSvc, tfaSvc, passkeySvc, tokenSvc, mfaSvc)
	oidcH, err := handler.NewOidcHandler(oidcSvc)
	if err != nil {
		return nil, err
	}

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
	// sysinfo 联动仓储（preset-address-book-*，M2 批复 #3 / M3 T05）：
	// owner 锚定超管（AdminUsername）名下 findOrCreate custom 书。
	sysinfoSvc := devicesvc.NewSysinfoService(
		peerRepo, sysinfoRepo, deviceGroupRepo, users,
		repository.NewAddressBookRepo(deps.DB),
		repository.NewAddressBookPeerRepo(deps.DB),
		repository.NewAddressBookTagRepo(deps.DB),
		repository.NewAddressBookPeerTagRepo(deps.DB),
		deps.Config.AdminUsername, deps.Logger)
	querySvc := devicesvc.NewQueryService(peerRepo, sysinfoRepo, users, deviceGroupRepo, strategyRepo)
	adminSvc := devicesvc.NewAdminService(
		authzSvc, peerRepo, sysinfoRepo, users, deviceGroupRepo, strategyRepo, disconnects)
	// GAP2 设备个人归属域：assign/解绑（devices.assign）+ me/user 设备查询。
	assignSvc := devicesvc.NewAssignService(
		authzSvc, auditSvc, peerRepo, sysinfoRepo, users, deviceGroupRepo, strategyRepo)

	heartbeatH := handler.NewHeartbeatHandler(heartbeatSvc, sysinfoSvc)
	deviceH := handler.NewDeviceHandler(authzSvc, querySvc, adminSvc, assignSvc)
	// userH 依赖 assignSvc（GAP2 设备归属查询端点），在 assignSvc 装配后构建。
	userH := handler.NewUserHandler(profileSvc, avatarSvc, userSvc, assignSvc)

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
	userGroupSvc := usergroupsvc.NewService(authzSvc, deps.DB, groups, users, repository.NewAddressBookRuleRepo(deps.DB))
	rbacH := handler.NewRbacHandler(authzSvc, roleSvc, userRoleSvc)
	userGroupH := handler.NewUserGroupHandler(userGroupSvc)

	// 审计域与仪表盘域（T04）：上报三端（conn upsert 状态机 / file、
	// alarm nonce 幂等）+ 查询六端（active 的 scope 过滤复用 RBAC
	// 授权服务与 peers 仓储；console 查询复用 M2 auditRepo）。仪表盘
	// systemStatus 磁盘统计以 DATA_DIR 所在卷为锚点（§10-6 批复）。
	connAuditRepo := repository.NewConnectionAuditRepo(deps.DB)
	fileAuditRepo := repository.NewFileAuditRepo(deps.DB)
	alarmAuditRepo := repository.NewAlarmAuditRepo(deps.DB)
	dashboardRepo := repository.NewDashboardRepo(deps.DB)
	addressBookRepo := repository.NewAddressBookRepo(deps.DB)

	auditReportSvc := auditsvc.NewReportService(connAuditRepo, fileAuditRepo, alarmAuditRepo)
	auditQuerySvc := auditsvc.NewQueryService(
		authzSvc, connAuditRepo, fileAuditRepo, alarmAuditRepo, auditRepo, peerRepo, loginAudits)
	dashboardSvc := dashboardsvc.NewService(
		dashboardRepo, addressBookRepo, connAuditRepo, fileAuditRepo, alarmAuditRepo,
		users, deps.Config.DataDir)

	auditH := handler.NewAuditHandler(auditReportSvc, auditQuerySvc)
	dashboardH := handler.NewDashboardHandler(dashboardSvc)

	// 通讯录域（M3 T05，事实⑦）：权限判定收敛 PermissionService；
	// 书级写路径（custom/shared 建改删）与规则 CRUD 在 RuleService；
	// legacy 双端点独立服务（兼容怪癖三件套）；设备/标签子服务
	// 分立（peer/tag）。sysinfo 联动（preset-address-book-*）复用
	// 同一批仓储（M2 批复 #3）。
	abRuleRepo := repository.NewAddressBookRuleRepo(deps.DB)
	abPeerRepo := repository.NewAddressBookPeerRepo(deps.DB)
	abTagRepo := repository.NewAddressBookTagRepo(deps.DB)
	abPeerTagRepo := repository.NewAddressBookPeerTagRepo(deps.DB)

	abPerms := absvc.NewPermissionService(addressBookRepo, abRuleRepo, users)
	abLegacySvc := absvc.NewLegacyService(
		deps.DB, addressBookRepo, abPeerRepo, abTagRepo, abPeerTagRepo,
		peerRepo, sysinfoRepo, abPerms)
	abBookSvc := absvc.NewBookService(addressBookRepo, abRuleRepo, users, abPerms, abLegacySvc)
	abRuleSvc := absvc.NewRuleService(deps.DB, addressBookRepo, abRuleRepo, users, groups, abPerms)
	abPeerSvc := absvc.NewPeerService(
		addressBookRepo, abPeerRepo, abPeerTagRepo, abTagRepo, peerRepo, sysinfoRepo, abPerms)
	abTagSvc := absvc.NewTagService(deps.DB, abTagRepo, abPeerTagRepo, abPerms)
	abH := handler.NewAddressBookHandler(abBookSvc, abRuleSvc, abPeerSvc, abTagSvc, abLegacySvc)

	// 服务器管理域（M3 T06，事实③）：RUSTDESK_NODES 解析校验（失败
	// fail-fast）；转发客户端 + handler（mutate 审计复用全局 auditSvc）。
	mgmtNodes, err := servermgmt.ParseNodes(deps.Config.RustdeskNodes)
	if err != nil {
		return nil, fmt.Errorf("servermgmt: %w", err)
	}
	mgmtClient := servermgmt.NewClient(mgmtNodes, deps.Logger)
	mgmtH := handler.NewServerMGMTHandler(mgmtClient, auditSvc)

	// nexus 域（M3 T06，事实⑤）：上游代理 + 产物落盘 DATA_DIR/nexus；
	// 后台 poller 不在此处启动（主流程显式 Nexus.Start，便于 ctx 生命周期）。
	nexusSvc := nexussvc.NewNexusService(deps.DB, deps.Config.NexusUpstream, deps.Config.DataDir)
	nexusH := handler.NewNexusHandler(nexusSvc)

	// 设置域（M3 T07，事实④）：system_settings KV 存储（store/general
	// 已前移至认证域段，GAP2）+ smtp/ldap/frontend/mfa 子服务；掩码约定
	// 与 404 固定文案由服务层承担。
	settingSmtp := settingssvc.NewSmtpService(settingStore)
	settingLdap := settingssvc.NewLdapService(settingStore)
	settingFrontend := settingssvc.NewFrontendService(settingGeneral)
	settingsH := handler.NewSettingsHandler(settingGeneral, settingSmtp, settingLdap, settingFrontend, settingMfa)

	// OIDC 提供者管理域（M3 T07，事实⑧）：CRUD/sort/toggle/test；
	// discovery 缓存进程内单例（issuer 变更时失效）。
	oidcAdminRepo := repository.NewOidcProviderAdminRepo(deps.DB)
	oidcAdminSvc := oidcadmin.NewProviderService(oidcAdminRepo)
	oidcAdminH := handler.NewOidcAdminHandler(oidcAdminSvc)

	// update-check 域（M3 T07，事实④）：每小时 cron 拉取
	// {NEXUS_UPSTREAM}/v1/update/check；install_id 落 system_settings。
	updateCheckSvc := updatechecksvc.NewService(updatechecksvc.Options{
		Upstream: deps.Config.NexusUpstream,
		Version:  deps.Config.Version,
		Channel:  deps.Config.UpdateChannel,
		Settings: settingRepo,
		Counters: repository.NewUpdateCheckCounters(deps.DB),
	})
	updateCheckH := handler.NewUpdateCheckHandler(updateCheckSvc)
	// 调度器仅构造，不启动（main 显式 Start/Stop，便于优雅退出）。
	updateCheckScheduler := updatechecksvc.NewScheduler(updateCheckSvc, deps.Logger)

	// M1 批复 #7 settings 驱动切换：JWT 过期天数与 OIDC 提供者
	// 改为"查库 → env fallback"两级读取（env 缺省保留为降级形态）。
	tokenSvc.WithRuntimeSettings(settingGeneral, deps.Config.JWTExpiryDays)
	oidcSvc.WithEnvFallback(&authsvc.EnvOidcFallback{
		Enabled:      deps.Config.OidcIssuer != "",
		Name:         "oidc",
		Issuer:       deps.Config.OidcIssuer,
		ClientID:     deps.Config.OidcClientID,
		ClientSecret: deps.Config.OidcClientSecret,
		Scope:        deps.Config.OidcScope,
	})

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
		Audit:        auditH,
		Dashboard:    dashboardH,
		AddressBook:  abH,
		ServerMGMT:   mgmtH,
		Nexus:        nexusH,
		Settings:     settingsH,
		OidcAdmin:    oidcAdminH,
		UpdateCheck:  updateCheckH,

		UpdateCheckScheduler: updateCheckScheduler,
		NexusPoller:          nexusSvc,
		Auth:                 authH,
		Oidc:                 oidcH,
		User:                 userH,
	}, nil
}
