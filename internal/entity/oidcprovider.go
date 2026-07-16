package entity

// OidcProvider oidc_providers 表实体。
type OidcProvider struct {
	Guid                  string `gorm:"column:guid;primaryKey;size:36"`
	Name                  string `gorm:"column:name;size:255;not null"`
	Type                  string `gorm:"column:type;size:64"`
	Issuer                string `gorm:"column:issuer;size:255"`
	ClientId              string `gorm:"column:clientId;size:255"`
	ClientSecret          string `gorm:"column:clientSecret;size:255"`
	Scope                 string `gorm:"column:scope;size:255"`
	AuthorizationEndpoint string `gorm:"column:authorizationEndpoint;size:255"`
	TokenEndpoint         string `gorm:"column:tokenEndpoint;size:255"`
	UserinfoEndpoint      string `gorm:"column:userinfoEndpoint;size:255"`
	JwksUri               string `gorm:"column:jwksUri;size:255"`
	Icon                  string `gorm:"column:icon;size:255"`
	Enabled               bool   `gorm:"column:enabled;not null;default:false"`
	Priority              int    `gorm:"column:priority;not null;default:0"`
}

// TableName 指定表名。
func (OidcProvider) TableName() string { return "oidc_providers" }
