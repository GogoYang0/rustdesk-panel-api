package server

import (
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/handler"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// Domain 装配完成的认证域服务容器（仓储 → 服务 → handler 全链）。
// T05 将在此容器上扩展 user 域（ProfileService/AvatarService）。
type Domain struct {
	Tokens  *authsvc.TokenService
	Login   *authsvc.AuthService
	Tfa     *authsvc.TfaService
	Passkey *authsvc.PasskeyService
	OIDC    *authsvc.OidcFlowService
	Cleanup *authsvc.CleanupService
	Auth    *handler.AuthHandler
	Oidc    *handler.OidcHandler
}

// assembleDomain 依 deps.DB 构建认证域容器（router 装配期一次性调用）。
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

	authH := handler.NewAuthHandler(loginSvc, tfaSvc, passkeySvc, tokenSvc)
	oidcH, err := handler.NewOidcHandler(oidcSvc)
	if err != nil {
		return nil, err
	}
	return &Domain{
		Tokens:  tokenSvc,
		Login:   loginSvc,
		Tfa:     tfaSvc,
		Passkey: passkeySvc,
		OIDC:    oidcSvc,
		Cleanup: cleanupSvc,
		Auth:    authH,
		Oidc:    oidcH,
	}, nil
}
