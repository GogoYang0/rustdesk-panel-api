// Package email 提供邮件服务（M3 扩展点③，设计 §1.2）：
//
//	net/smtp + crypto/tls 客户端替代参考 nodemailer；SMTP 配置经
//	ConfigProvider 动态读取（T07 起由 settings store 注入，读取时机
//
// 为每次发送而非进程启动——配置热更生效）；
//
//	SendInvitation 失败返回 false（不阻断流程）——邀请域据此降级：
//	邮件失败时邀请 token 明文回退给管理员（设计事实①/§4.1）。
package email

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SmtpConfig SMTP 配置（与 system_settings 的 smtp.* 键目录一一对应，
// 共享知识 18；T07 settings store 的 GetSmtp 直接返回本结构）。
type SmtpConfig struct {
	Host    string // SMTP 主机
	Port    int    // 端口（465/587/25）
	Secure  bool   // true=隐式 SSL(465)；false=STARTTLS/明文
	User    string // 认证用户（空=匿名）
	Pass    string // 认证口令
	From    string // 发件人地址
	Enabled bool   // 总开关（false 时发送恒失败——布尔降级语义）
}

// ConfigProvider 每次发送时动态读取 SMTP 配置（T07 由 settings store
// 提供；测试注入固定配置）。
type ConfigProvider func() SmtpConfig

// Mailer 邮件服务。sendTimeout 限制单次 SMTP 会话时长，防止上游
// 挂死拖垮请求链（对齐参考 nodemailer 默认 connectionTimeout 语义）。
type Mailer struct {
	provider ConfigProvider
	logger   *slog.Logger
	// sendTimeout 单次会话超时（缺省 10s；测试可注入）。
	sendTimeout time.Duration
}

// NewMailer 构建邮件服务。
func NewMailer(provider ConfigProvider, logger *slog.Logger) *Mailer {
	return &Mailer{provider: provider, logger: logger, sendTimeout: 10 * time.Second}
}

// SendInvitation 发送邀请邮件（正文含接受邀请链接）。
// 返回 false 表示未发送（配置关闭/缺失或发送失败）——调用方据此
// 走 token 明文降级（设计 §4.1，不阻断邀请主链）。
func (m *Mailer) SendInvitation(to, name, link string) bool {
	body, err := renderInvitation(name, link)
	if err != nil {
		m.log("invitation", to, err)
		return false
	}
	return m.send(to, "You're invited to RustDesk Panel", body)
}

// SendVerification 发送验证码邮件（2FA 邮箱验证等）。失败返回 false。
func (m *Mailer) SendVerification(to, code string) bool {
	body, err := renderVerification(code)
	if err != nil {
		m.log("verification", to, err)
		return false
	}
	return m.send(to, "Your verification code", body)
}

// SendWelcome 发送欢迎邮件（邀请接受成功后）。失败返回 false
// （欢迎邮件属尽力而为，不触发任何降级链）。
func (m *Mailer) SendWelcome(to, name string) bool {
	body, err := renderWelcome(name)
	if err != nil {
		m.log("welcome", to, err)
		return false
	}
	return m.send(to, "Welcome to RustDesk Panel", body)
}

// send 单次发送全链：取配置 → 建连（secure=隐式 TLS / 其余 STARTTLS
// 协商）→ 可选 AUTH → MAIL/RCPT/DATA → QUIT。任何失败返回 false
// 并记日志，绝不 panic——邮件是旁路能力。
func (m *Mailer) send(to, subject, body string) bool {
	cfg := m.provider()
	if !cfg.Enabled || cfg.Host == "" || cfg.Port == 0 || cfg.From == "" {
		return false
	}
	done := make(chan error, 1)
	go func() {
		done <- smtpSession(cfg, to, subject, body)
	}()
	select {
	case err := <-done:
		if err != nil {
			m.log(subject, to, err)
			return false
		}
		return true
	case <-time.After(m.sendTimeout):
		m.log(subject, to, fmt.Errorf("smtp session timeout after %s", m.sendTimeout))
		return false
	}
}

// smtpSession 执行一次完整 SMTP 会话（同步；超时由 send 守护）。
func smtpSession(cfg SmtpConfig, to, subject, body string) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	var conn net.Conn
	var err error
	if cfg.Secure {
		conn, err = tls.Dial("tcp", addr, &tls.Config{ServerName: cfg.Host})
	} else {
		conn, err = net.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer func() { _ = client.Close() }()

	// 明文连接上协商 STARTTLS（服务端支持时）；隐式 SSL 分支已加密。
	if !cfg.Secure {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: cfg.Host}); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}
	// 认证（配置了用户名时）；PlainAuth 要求加密连接，明文会话由
	// net/smtp 自行拒绝——生产配置应使用 secure/STARTTLS。
	if cfg.User != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.User, cfg.Pass, cfg.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("rcpt to: %w", err)
	}
	data, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := data.Write([]byte(buildMessage(cfg.From, to, subject, body))); err != nil {
		_ = data.Close()
		return fmt.Errorf("write data: %w", err)
	}
	if err := data.Close(); err != nil {
		return fmt.Errorf("close data: %w", err)
	}
	return client.Quit()
}

// buildMessage 组装最小 MIME 邮件（text/html UTF-8；subject 与地址
// 由调用方保证 ASCII 安全面——模板 subject 恒为英文文案）。
func buildMessage(from, to, subject, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

// log 统一失败日志（logger 缺省为 slog.Default，测试可注入 no-op）。
func (m *Mailer) log(kind, to string, err error) {
	if m.logger != nil {
		m.logger.Warn("email: send failed", "kind", kind, "to", to, "error", err)
	}
}
