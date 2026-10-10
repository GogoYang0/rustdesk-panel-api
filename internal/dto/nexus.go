// Package dto 本文件：nexus 域（设计事实⑤，M3 T06）请求/视图载体。
//
// 契约形状以 openapi.yaml 为准：NexusGenerateDto{os,arch,custom}、
// NexusBuildView{uuid,os,arch,status,custom,message,created_at}、
// NexusBindStatus{bound,...}、BuildFiles{files:[{filename,size}]}。
//
// 状态码特例（共享知识 17）：POST builds = 201、DELETE builds/{uuid} = 204。
package dto

import (
	"regexp"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
)

// NexusGenerateDto 构建参数（os 仅 windows；arch ∈ x86_64|aarch64|x86；
// custom 键校验归上游，事实⑤）。
type NexusGenerateDto = api.NexusGenerateDto

// NexusBuildView 构建任务视图。
type NexusBuildView = api.NexusBuildView

// NexusBindStatus 绑定态视图。
type NexusBindStatus = api.NexusBindStatus

// BuildFiles 产物清单视图。
type BuildFiles = api.BuildFiles

// osWindows 构建目标 OS 唯一取值（事实⑤：os 仅 'windows'）。
const osWindows = "windows"

// archWhitelist 构建目标架构白名单（事实⑤）。
var archWhitelist = map[string]struct{}{
	"x86_64":  {},
	"aarch64": {},
	"x86":     {},
}

// filenameWhitelistRe 产物文件名白名单（批复 #8）：仅允许安全字符集，
// 从源头消除 Content-Disposition 头注入与路径面歧义。
//
// 首字符限定为字母或数字：排除 "." / ".." / "..." 等纯点集——它们能
// 通过字符集检查却会被解析为当前/上级目录，形成目录读取面。
var filenameWhitelistRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)

// ValidateGenerate 校验构建参数形状（openapi enum 约束的显式复核，
// 使契约违例在进入上游前即被拒绝为 400）。
func ValidateGenerate(d *NexusGenerateDto) error {
	if d == nil {
		return errMsg("Invalid build request")
	}
	if string(d.Os) != osWindows {
		return errMsg("os must be 'windows'")
	}
	if _, ok := archWhitelist[string(d.Arch)]; !ok {
		return errMsg("arch must be one of x86_64|aarch64|x86")
	}
	if d.Custom == nil {
		return errMsg("custom is required")
	}
	return nil
}

// SanitizeFilename 白名单过滤产物文件名（批复 #8）：剥离 CR/LF/引号/
// 路径分隔符等一切头注入与穿越字符；返回空串表示文件名整体非法
// （调用方须以 400 Invalid path 拒绝）。
//
// 白名单优先于黑名单剥离：仅接受 ^[A-Za-z0-9._-]{1,255}$ 的字面量，
// 从构造上排除 ".."、绝对路径与前缀歧义。
func SanitizeFilename(name string) string {
	if !filenameWhitelistRe.MatchString(name) {
		return ""
	}
	return name
}
