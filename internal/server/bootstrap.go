package server

import (
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/handler"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
	usersvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/user"
)

// Domain 装配完成的认证/用户域服务容器（仓储 → 服务 → handler 全链）。
type Domain struct {
	Tokens  *authsvc.TokenService
	Login   *authsvc.AuthService
	Tfa     *authsvc.TfaService
	Passkey *authsvc.PasskeyService
	OIDC    *authsvc.OidcFlowService
	Cleanup *authsvc.CleanupService
	Profile *usersvc.ProfileService
	Avatar  *usersvc.AvatarService
	Auth    *handler.AuthHandler
	Oidc    *handler.OidcHandler
	User    *handler.UserHandler
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

	authH := handler.NewAuthHandler(loginSvc, tfaSvc, passkeySvc, tokenSvc)
	oidcH, err := handler.NewOidcHandler(oidcSvc)
	if err != nil {
		return nil, err
	}
	userH := handler.NewUserHandler(profileSvc, avatarSvc)
	return &Domain{
		Tokens:  tokenSvc,
		Login:   loginSvc,
		Tfa:     tfaSvc,
		Passkey: passkeySvc,
		OIDC:    oidcSvc,
		Cleanup: cleanupSvc,
		Profile: profileSvc,
		Avatar:  avatarSvc,
		Auth:    authH,
		Oidc:    oidcH,
		User:    userH,
	}, nil
}
