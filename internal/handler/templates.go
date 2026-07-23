package handler

import (
	"embed"
	"html/template"
)

// callbackTemplates 内嵌 OIDC 回调页（设计 T04 文件列表：
// templates/callback-success.html / templates/callback-error.html）。
//
//go:embed templates
var callbackTemplates embed.FS

// mustParseTemplate 解析单个内嵌模板；启动期失败即 panic（装配错误）。
func mustParseTemplate(name string) *template.Template {
	tmpl, err := template.ParseFS(callbackTemplates, "templates/"+name)
	if err != nil {
		panic("handler: parse template " + name + ": " + err.Error())
	}
	return tmpl
}
