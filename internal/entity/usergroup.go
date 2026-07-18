package entity

// UserGroup user_groups 表实体。
type UserGroup struct {
	Guid          string `gorm:"column:guid;primaryKey;size:36"`
	Name          string `gorm:"column:name;size:255;not null"`
	NormalizedName string `gorm:"column:normalizedName;size:255;not null"`
	Note          string `gorm:"column:note"`
	IsDefault     bool   `gorm:"column:isDefault;not null;default:false"`
}

// TableName 指定表名。
func (UserGroup) TableName() string { return "user_groups" }
