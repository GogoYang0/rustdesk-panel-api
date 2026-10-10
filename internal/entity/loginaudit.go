package entity

import "time"

// LoginAudit login_audits 表实体（GAP2 设计 §3.4，迁移 000004_m4_gap2）。
//
// 登录事件审计（成败/被强制/绑定完成），列名 = DB 契约（camelCase 原样）：
//   - userGuid 可空：登录尝试可能不对应任何既有用户（防枚举锚点）；
//   - username 为登录尝试输入原文（审计锚点，非展示名）；
//   - result 六枚举（共享知识 G3）：success | failed | tfa_required |
//     tfa_failed | mfa_enroll_required | mfa_enroll_completed；
//   - method 五枚举：password | tfa_code | email_code | passkey | oidc；
//   - reason 为固定文案（如 bad_credentials / tfa_code_invalid）。
//
// 写入为 best-effort（G3：失败仅告警，不阻断登录主流程）。
type LoginAudit struct {
	Guid       string    `gorm:"column:guid;primaryKey;size:36"`
	UserGuid   *string   `gorm:"column:userGuid;size:36"`
	Username   string    `gorm:"column:username;size:255;not null"`
	Result     string    `gorm:"column:result;size:32;not null"`
	Method     string    `gorm:"column:method;size:32;not null"`
	IP         string    `gorm:"column:ip;size:64"`
	UserAgent  string    `gorm:"column:userAgent;size:255"`
	DeviceId   string    `gorm:"column:deviceId;size:255"`
	DeviceUuid string    `gorm:"column:deviceUuid;size:36"`
	Reason     string    `gorm:"column:reason;size:255"`
	CreatedAt  time.Time `gorm:"column:createdAt;not null"`
}

// TableName 指定表名。
func (LoginAudit) TableName() string { return "login_audits" }

// 登录审计 result 枚举（共享知识 G3）。
const (
	LoginAuditResultSuccess           = "success"
	LoginAuditResultFailed            = "failed"
	LoginAuditResultTfaRequired       = "tfa_required"
	LoginAuditResultTfaFailed         = "tfa_failed"
	LoginAuditResultMfaEnrollRequired = "mfa_enroll_required"
	LoginAuditResultMfaEnrollComplete = "mfa_enroll_completed"
)

// 登录审计 method 枚举（GAP2 设计 §3.4）。
const (
	LoginAuditMethodPassword = "password"
	LoginAuditMethodTfaCode  = "tfa_code"
	LoginAuditMethodEmailCod = "email_code"
	LoginAuditMethodPasskey  = "passkey"
	LoginAuditMethodOidc     = "oidc"
)
