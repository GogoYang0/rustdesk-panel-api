// mailer_test.go 邮件域单测：三模板渲染占位替换、disabled/缺配置
// 布尔降级（SendInvitation=false 触发 token 明文回退链）、最小 SMTP
// stub 会话（EHLO/MAIL/RCPT/DATA/QUIT 全链，M1 批复邮箱域 T01 验收）。
package email

import (
	"bufio"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRenderTemplates 三模板渲染：占位替换正确、无残留 {{。
func TestRenderTemplates(t *testing.T) {
	inv, err := renderInvitation("Alice", "https://panel.example.com/invite?t=abc")
	if err != nil {
		t.Fatalf("renderInvitation: %v", err)
	}
	if !strings.Contains(inv, "Alice") || !strings.Contains(inv, "https://panel.example.com/invite?t=abc") {
		t.Errorf("invitation body missing placeholders: %s", inv)
	}
	if strings.Contains(inv, "{{") {
		t.Errorf("invitation body has unparsed placeholder: %s", inv)
	}

	ver, err := renderVerification("123456")
	if err != nil {
		t.Fatalf("renderVerification: %v", err)
	}
	if !strings.Contains(ver, "123456") {
		t.Errorf("verification body missing code: %s", ver)
	}

	wel, err := renderWelcome("Bob")
	if err != nil {
		t.Fatalf("renderWelcome: %v", err)
	}
	if !strings.Contains(wel, "Bob") {
		t.Errorf("welcome body missing name: %s", wel)
	}
}

// TestSendDisabledOrMissingConfig 布尔降级矩阵：enabled=false、
// host/port/from 缺失一律 false 且不发起网络请求。
func TestSendDisabledOrMissingConfig(t *testing.T) {
	cases := []SmtpConfig{
		{Enabled: false, Host: "smtp.example.com", Port: 587, From: "p@e.com"},
		{Enabled: true, Host: "", Port: 587, From: "p@e.com"},
		{Enabled: true, Host: "smtp.example.com", Port: 0, From: "p@e.com"},
		{Enabled: true, Host: "smtp.example.com", Port: 587, From: ""},
	}
	for i, cfg := range cases {
		m := NewMailer(func() SmtpConfig { return cfg }, slog.New(slog.DiscardHandler))
		if m.SendInvitation("to@e.com", "A", "https://e.com") {
			t.Errorf("case %d: SendInvitation = true, want false", i)
		}
		if m.SendVerification("to@e.com", "1") {
			t.Errorf("case %d: SendVerification = true, want false", i)
		}
		if m.SendWelcome("to@e.com", "A") {
			t.Errorf("case %d: SendWelcome = true, want false", i)
		}
	}
}

// fakeSMTP 启动最小 SMTP stub：220 问候 → EHLO 多行 → MAIL/RCPT/DATA
// 全链 → QUIT。捕获 from/to/正文供断言。
func fakeSMTP(t *testing.T, capture *map[string]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		write := func(s string) { _, _ = conn.Write([]byte(s + "\r\n")) }
		write("220 fake ESMTP ready")
		inData := false
		var data strings.Builder
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					(*capture)["data"] = data.String()
					write("250 OK queued")
				} else {
					data.WriteString(line + "\n")
				}
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				// 多行能力响应；不通告 STARTTLS → 客户端跳过协商。
				write("250-fake greets you")
				write("250 SMTPUTF8")
			case strings.HasPrefix(line, "MAIL FROM:"):
				(*capture)["from"] = line
				write("250 OK")
			case strings.HasPrefix(line, "RCPT TO:"):
				(*capture)["to"] = line
				write("250 OK")
			case strings.HasPrefix(line, "DATA"):
				inData = true
				write("354 go ahead")
			case strings.HasPrefix(line, "QUIT"):
				write("221 bye")
				return
			default:
				write("250 OK")
			}
		}
	}()
	return ln.Addr().String()
}

// TestSendInvitationFakeSMTP 经 stub SMTP 全链发送邀请邮件：
// 返回 true，会话级 from/to 与 MIME 形状（From/To/Subject/Content-Type +
// 正文链接）逐项锁定。
func TestSendInvitationFakeSMTP(t *testing.T) {
	capture := map[string]string{}
	addr := fakeSMTP(t, &capture)
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	cfg := SmtpConfig{
		Host: host, Port: port, Secure: false,
		From: "panel@rustdesk.local", Enabled: true,
	}
	m := NewMailer(func() SmtpConfig { return cfg }, slog.New(slog.DiscardHandler))
	m.sendTimeout = 5 * time.Second

	if !m.SendInvitation("guest@rustdesk.local", "Alice", "https://panel/invite?t=abc") {
		t.Fatal("SendInvitation = false, want true (stub SMTP session)")
	}
	if !strings.HasPrefix(capture["from"], "MAIL FROM:<panel@rustdesk.local>") {
		// net/smtp 在 hello 通告 SMTPUTF8 后会在参数后追加该扩展标记，
		// 属合法形态——断言按前缀锁定地址本体。
		t.Errorf("MAIL FROM = %q", capture["from"])
	}
	if !strings.HasPrefix(capture["to"], "RCPT TO:<guest@rustdesk.local>") {
		t.Errorf("RCPT TO = %q", capture["to"])
	}
	data := capture["data"]
	for _, want := range []string{
		"From: panel@rustdesk.local",
		"To: guest@rustdesk.local",
		"Subject: You're invited to RustDesk Panel",
		"Content-Type: text/html; charset=UTF-8",
		"https://panel/invite?t=abc",
	} {
		if !strings.Contains(data, want) {
			t.Errorf("data missing %q, got:\n%s", want, data)
		}
	}
}

// TestMailerTimeoutDialRefused 不可达上游走超时/拒连路径：恒 false
// 不 panic（邮件旁路语义）。
func TestMailerTimeoutDialRefused(t *testing.T) {
	cfg := SmtpConfig{Host: "127.0.0.1", Port: 1, Secure: false, From: "p@e.com", Enabled: true}
	m := NewMailer(func() SmtpConfig { return cfg }, slog.New(slog.DiscardHandler))
	m.sendTimeout = 500 * time.Millisecond
	if m.SendWelcome("to@e.com", "A") {
		t.Error("SendWelcome on refused dial = true, want false")
	}
}

// fmtSscan 薄包装（避免直接依赖 fmt 在测试内散布）。
var _ = smtp.PlainAuth
