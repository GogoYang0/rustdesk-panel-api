package entity

import "time"

// OidcAuthState oidc_auth_states 表实体。
// OIDC 授权中间态（PKCE codeVerifier + nonce + state，短 TTL）。
type OidcAuthState struct {
	Guid                string    `gorm:"column:guid;primaryKey;size:36"`
	Code                string    `gorm:"column:code;size:255;not null"`
	Op                  string    `gorm:"column:op;size:255"`
	ProviderType        string    `gorm:"column:providerType;size:64"`
	DeviceId            string    `gorm:"column:deviceId;size:255"`
	DeviceUuid          string    `gorm:"column:deviceUuid;size:255"`
	DeviceInfo          string    `gorm:"column:deviceInfo"`
	RedirectUri         string    `gorm:"column:redirectUri;size:255"`
	State               string    `gorm:"column:state;size:255"`
	Status              string    `gorm:"column:status;size:32"`
	UserGuid            string    `gorm:"column:userGuid;size:36"`
	AccessToken         string    `gorm:"column:accessToken"`
	CodeVerifier        string    `gorm:"column:codeVerifier;size:255"`
	Nonce               string    `gorm:"column:nonce;size:255"`
	FrontendRedirectUrl string    `gorm:"column:frontendRedirectUrl;size:255"`
	ExpiresAt           time.Time `gorm:"column:expiresAt;not null"`
}

// TableName 指定表名。
func (OidcAuthState) TableName() string { return "oidc_auth_states" }
