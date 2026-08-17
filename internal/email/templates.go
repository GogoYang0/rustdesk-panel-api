// templates.go 邮件模板（text/template ×3，embed 编译期打包）：
// 对齐参考 nodemailer+Handlebars 的占位语义（name/link/code）。
// 模板正文为 HTML 片段；subject 固定英文（见 mailer.go 各 Send*）。
package email

import (
	"embed"
	"strings"
	"text/template"
)

//go:embed templates
var templateFS embed.FS

// 三个模板编译期解析完成（模板语法错误属编程错误，直接 panic）。
var (
	invitationTmpl   = template.Must(template.ParseFS(templateFS, "templates/invitation.tmpl"))
	verificationTmpl = template.Must(template.ParseFS(templateFS, "templates/verification.tmpl"))
	welcomeTmpl      = template.Must(template.ParseFS(templateFS, "templates/welcome.tmpl"))
)

// invitationData / verificationData / welcomeData 模板数据。
type invitationData struct {
	Name string
	Link string
}

type verificationData struct {
	Code string
}

type welcomeData struct {
	Name string
}

// renderInvitation 渲染邀请邮件正文（含接受链接）。
func renderInvitation(name, link string) (string, error) {
	return render(invitationTmpl, invitationData{Name: name, Link: link})
}

// renderVerification 渲染验证码邮件正文。
func renderVerification(code string) (string, error) {
	return render(verificationTmpl, verificationData{Code: code})
}

// renderWelcome 渲染欢迎邮件正文。
func renderWelcome(name string) (string, error) {
	return render(welcomeTmpl, welcomeData{Name: name})
}

// render 执行模板并输出 HTML 字符串。
func render(t *template.Template, data any) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
