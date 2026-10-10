package entity

// PasskeyCredential passkey_credentials 表实体。
type PasskeyCredential struct {
	Guid                string `gorm:"column:guid;primaryKey;size:36"`
	UserGuid            string `gorm:"column:userGuid;size:36;not null"`
	CredentialId        string `gorm:"column:credentialId;size:512;not null"`
	CredentialPublicKey string `gorm:"column:credentialPublicKey"`
	Counter             uint32 `gorm:"column:counter;not null;default:0"`
	Transports          string `gorm:"column:transports;size:255"`
	DeviceType          string `gorm:"column:deviceType;size:64"`
	BackedUp            bool   `gorm:"column:backedUp;not null;default:false"`
	Name                string `gorm:"column:name;size:255"`
}

// TableName 指定表名。
func (PasskeyCredential) TableName() string { return "passkey_credentials" }
