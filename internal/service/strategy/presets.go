// Package strategy 本文件：策略配置项预设值目录（v0.2.1 问题 8）。
//
// 键全集取自官方客户端 libs/base/src/config/keys.rs（rustdesk master），
// 收录可通过策略 config_options 下发且属"受控端行为"的键，按
// security/connection/display/permission/other 五类组织。每项含
// key、type（bool 项取值 "Y"/"N"/""——空串=回退内置默认）、
// default_value（官方内置默认行为描述）与中文说明。服务端不做键级
// 校验（客户端 handle_config_options 接受任意键），目录仅供 web
// 编辑器渲染与运维参考。
package strategy

import (
	"sort"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
)

// 预设项类型（契约枚举；oapi-codegen 生成的常量为短名）。
const (
	presetTypeBool   = api.Bool
	presetTypeString = api.String
	presetTypeInt    = api.Int
)

// presetCatalog 预设目录（编译期常量表；新增键在此登记）。
var presetCatalog = []api.StrategyOptionPreset{
	// ---------- 权限（受控端会话能力开关） ----------
	{Key: "access-mode", Category: api.Permission, Type: presetTypeString, DefaultValue: "", Description: "访问模式：full（全控）/ view（仅查看）/ 空串=不限制"},
	{Key: "enable-keyboard", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许控制端使用键盘（N=禁用键盘输入）"},
	{Key: "enable-clipboard", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许剪贴板同步（N=禁用复制粘贴）"},
	{Key: "enable-file-transfer", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许文件传输"},
	{Key: "enable-camera", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许远程摄像头访问"},
	{Key: "enable-terminal", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许远程终端会话"},
	{Key: "enable-audio", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许音频传输（受控端声音）"},
	{Key: "enable-tunnel", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许 TCP 隧道（端口转发）"},
	{Key: "enable-remote-restart", Category: api.Permission, Type: presetTypeBool, DefaultValue: "N", Description: "允许控制端远程重启受控机"},
	{Key: "enable-record-session", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许会话录制"},
	{Key: "enable-block-input", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许控制端封锁受控端物理输入"},
	{Key: "enable-privacy-mode", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许隐私模式（受控端黑屏）"},
	{Key: "enable-perm-change-in-accept-window", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许在连接接受窗口内改动上述权限"},
	{Key: "allow-remote-config-modification", Category: api.Permission, Type: presetTypeBool, DefaultValue: "N", Description: "允许控制端经连接修改受控端配置"},
	{Key: "allow-remote-cm-modification", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许控制端修改连接管理器（cm）配置"},
	{Key: "allow-hide-cursor", Category: api.Permission, Type: presetTypeBool, DefaultValue: "Y", Description: "允许控制端隐藏受控端鼠标指针"},

	// ---------- 安全（接入控制与密码策略） ----------
	{Key: "approve-mode", Category: api.Security, Type: presetTypeString, DefaultValue: "click", Description: "连接确认方式：password（仅密码）/ click（点确认）/ full（密码+确认）；空串=内置默认"},
	{Key: "verification-method", Category: api.Security, Type: presetTypeString, DefaultValue: "use-temporary-password", Description: "临时密码/永久密码接入校验方式（逗号分隔多值）"},
	{Key: "temporary-password-length", Category: api.Security, Type: presetTypeString, DefaultValue: "6", Description: "临时密码长度：6/8/10 位"},
	{Key: "whitelist", Category: api.Security, Type: presetTypeString, DefaultValue: "", Description: "IP 白名单（逗号分隔；空=允许所有 IP）"},
	{Key: "id-whitelist", Category: api.Security, Type: presetTypeString, DefaultValue: "", Description: "RustDesk ID 白名单（逗号分隔；空=不限制）"},
	{Key: "allow-auto-disconnect", Category: api.Security, Type: presetTypeBool, DefaultValue: "N", Description: "受控端无输入时自动断开空闲连接"},
	{Key: "auto-disconnect-timeout", Category: api.Security, Type: presetTypeInt, DefaultValue: "180", Description: "自动断开空闲超时（秒；allow-auto-disconnect=Y 时生效）"},
	{Key: "allow-only-conn-window-open", Category: api.Security, Type: presetTypeBool, DefaultValue: "N", Description: "仅允许在连接窗口打开时接受连接"},
	{Key: "remove-preset-password-warning", Category: api.Security, Type: presetTypeBool, DefaultValue: "N", Description: "移除预置密码的安全提示横幅"},
	{Key: "default-connect-password", Category: api.Security, Type: presetTypeString, DefaultValue: "", Description: "预置连接密码（明文下发到受控端，谨慎使用）"},
	{Key: "allow-ask-for-note", Category: api.Security, Type: presetTypeBool, DefaultValue: "N", Description: "连接结束时提示控制端填写审计备注"},

	// ---------- 连接（网络与发现） ----------
	{Key: "direct-access-port", Category: api.Connection, Type: presetTypeInt, DefaultValue: "21118", Description: "IP 直连监听端口（空=禁用直连）"},
	{Key: "enable-lan-discovery", Category: api.Connection, Type: presetTypeBool, DefaultValue: "Y", Description: "允许局域网发现（N=拒绝 LAN 广播响应）"},
	{Key: "deny-lan-discovery", Category: api.Connection, Type: presetTypeBool, DefaultValue: "N", Description: "拒绝局域网发现响应（旧键，等价 enable-lan-discovery=N）"},
	{Key: "disable-udp", Category: api.Connection, Type: presetTypeBool, DefaultValue: "N", Description: "禁用 UDP（强制 TCP 直连/中继）"},
	{Key: "enable-tcp-punch", Category: api.Connection, Type: presetTypeBool, DefaultValue: "Y", Description: "允许 TCP 打洞"},
	{Key: "enable-udp-punch", Category: api.Connection, Type: presetTypeBool, DefaultValue: "Y", Description: "允许 UDP 打洞"},
	{Key: "enable-ipv6-punch", Category: api.Connection, Type: presetTypeBool, DefaultValue: "Y", Description: "允许 IPv6 打洞"},
	{Key: "enable-port-forward-mux", Category: api.Connection, Type: presetTypeBool, DefaultValue: "N", Description: "端口转发复用主连接"},
	{Key: "enable-webrtc", Category: api.Connection, Type: presetTypeBool, DefaultValue: "N", Description: "启用 WebRTC 通道"},
	{Key: "relay-fallback-delay", Category: api.Connection, Type: presetTypeInt, DefaultValue: "3000", Description: "直连失败转中继的等待（毫秒）"},
	{Key: "allow-https-21114", Category: api.Connection, Type: presetTypeBool, DefaultValue: "N", Description: "允许经 21114 端口 HTTPS 访问 API"},
	{Key: "use-raw-tcp-for-api", Category: api.Connection, Type: presetTypeBool, DefaultValue: "N", Description: "API 请求经 ID 服务器 raw TCP 转发"},

	// ---------- 显示（画质与渲染） ----------
	{Key: "enable-abr", Category: api.Display, Type: presetTypeBool, DefaultValue: "Y", Description: "自适应码率（ABR）"},
	{Key: "enable-hwcodec", Category: api.Display, Type: presetTypeBool, DefaultValue: "Y", Description: "硬件编解码"},
	{Key: "allow-remove-wallpaper", Category: api.Display, Type: presetTypeBool, DefaultValue: "Y", Description: "隐私模式下允许移除桌面壁纸"},
	{Key: "allow-always-software-render", Category: api.Display, Type: presetTypeBool, DefaultValue: "N", Description: "允许始终软件渲染（GPU 兼容性兜底）"},
	{Key: "enable-directx-capture", Category: api.Display, Type: presetTypeBool, DefaultValue: "Y", Description: "Windows DirectX 屏幕捕获"},

	// ---------- 其他（UI 限制 / 预置信息 / 录制） ----------
	{Key: "hide-tray", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏系统托盘图标"},
	{Key: "hide-general-settings", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏客户端常规设置页"},
	{Key: "hide-security-settings", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏客户端安全设置页"},
	{Key: "hide-network-settings", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏客户端网络设置页"},
	{Key: "hide-server-settings", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏客户端服务器设置页"},
	{Key: "hide-proxy-settings", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏客户端代理设置页"},
	{Key: "hide-websocket-settings", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏 WebSocket 设置项"},
	{Key: "hide-stop-service", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏停止服务按钮"},
	{Key: "allow-command-line-settings-when-settings-disabled", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "设置被隐藏时仍允许命令行改配置"},
	{Key: "enable-check-update", Category: api.Other, Type: presetTypeBool, DefaultValue: "Y", Description: "客户端检查自身更新"},
	{Key: "allow-auto-update", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "客户端自动更新"},
	{Key: "allow-auto-record-incoming", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "被控会话自动录制"},
	{Key: "allow-auto-record-outgoing", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "主控会话自动录制"},
	{Key: "hide-recording-button", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "隐藏会话录制按钮"},
	{Key: "video-save-directory", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "会话录制保存目录（空=默认）"},
	{Key: "preset-device-name", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置设备名（覆盖 sysinfo hostname 上报）"},
	{Key: "preset-device-username", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置设备用户名（覆盖 sysinfo username 上报）"},
	{Key: "preset-note", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置设备备注（面板设备列表 note 兜底）"},
	{Key: "preset-device-group-name", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置设备组名（sysinfo 上报后面板自动归组）"},
	{Key: "preset-user-name", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置用户名标记（sysinfo preset-username）"},
	{Key: "preset-strategy-name", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置策略名标记（sysinfo preset-strategy-name）"},
	{Key: "preset-address-book-name", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置通讯簿名（sysinfo 上报后面板自动建书挂载）"},
	{Key: "preset-address-book-tag", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置通讯簿标签（逗号分隔多值）"},
	{Key: "preset-address-book-alias", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置通讯簿别名"},
	{Key: "preset-address-book-password", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置通讯簿密码"},
	{Key: "preset-address-book-note", Category: api.Other, Type: presetTypeString, DefaultValue: "", Description: "预置通讯簿备注"},
	{Key: "enable-trusted-devices", Category: api.Other, Type: presetTypeBool, DefaultValue: "Y", Description: "启用受信任设备（免二次验证）"},
	{Key: "enable-remote-printer", Category: api.Other, Type: presetTypeBool, DefaultValue: "N", Description: "启用远程打印机"},
}

// Presets 策略预设目录（key ASC 排序，稳定输出）。
func Presets() []api.StrategyOptionPreset {
	out := make([]api.StrategyOptionPreset, len(presetCatalog))
	copy(out, presetCatalog)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
