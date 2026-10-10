// Package dto 本文件：服务器管理域（设计事实③，M3 T06）请求/视图载体。
//
// 契约形状以 openapi.yaml 为准：NodeStatus（列表握手元素）、
// ServerConfigDto{values}、ServerBansDto{device_ids,ips}。面板对 agent
// 载荷只做透传与 JSON object 校验，键级 schema 归 agent 版本演进
// （§10-4 批复）。
package dto

import (
	"regexp"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// NodeStatusView 节点状态视图（与 api.NodeStatus 同构；不可达节点
// services 恒为空数组而非 nil，避免前端 null 判定分叉）。
type NodeStatusView = api.NodeStatus

// ServerConfigDto 服务配置透传形态 {values:{k:v}}（事实③）。
type ServerConfigDto = api.ServerConfigDto

// ServerBansDto 封禁名单 {device_ids,ips}（事实③：device_ids ≤10000，
// ips 为标准 IP 格式）。
type ServerBansDto = api.ServerBansDto

// maxBanDeviceIDs 封禁设备 id 条数上限（事实③ / openapi maxItems）。
const maxBanDeviceIDs = 10000

// ipv4Re 标准 IPv4 字面量校验（openapi ServerBansDto.ips format: ipv4）。
var ipv4Re = regexp.MustCompile(
	`^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}` +
		`(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$`)

// ServiceName 服务枚举（事实③：hbbs|hbbr）。
type ServiceName string

// 服务枚举值。
const (
	ServiceHbbs ServiceName = "hbbs"
	ServiceHbbr ServiceName = "hbbr"
)

// IsValidService 服务名是否在枚举内（键级校验归 agent，枚举为面板侧
// 契约（openapi enum）约束，路径级校验合理保留）。
func IsValidService(s string) bool {
	return s == string(ServiceHbbs) || s == string(ServiceHbbr)
}

// ServiceAction 服务动作枚举（事实③：start|stop|restart|apply）。
type ServiceAction string

// 动作枚举值。
const (
	ActionStart   ServiceAction = "start"
	ActionStop    ServiceAction = "stop"
	ActionRestart ServiceAction = "restart"
	ActionApply   ServiceAction = "apply"
)

// serviceActions 动作白名单。
var serviceActions = map[string]struct{}{
	string(ActionStart):   {},
	string(ActionStop):    {},
	string(ActionRestart): {},
	string(ActionApply):   {},
}

// IsValidAction 动作是否在枚举内（openapi enum 路径参数约束）。
func IsValidAction(a string) bool {
	_, ok := serviceActions[a]
	return ok
}

// errMsg 构造 400 业务错误（dto 层形状校验统一出口；handler 以
// rbac.WriteStatusError 出包络）。包内单一定义，servermgmt/nexus 共用。
func errMsg(msg string) error {
	return rbac.ErrBadRequest(msg)
}

// ValidateBans 校验封禁载荷形状（事实③）：device_ids ≤10000、ips 逐条
// 匹配标准 IPv4 字面量。返回 nil 表示形状合法。
func ValidateBans(d *ServerBansDto) error {
	if d == nil {
		return errMsg("Invalid server management request")
	}
	if len(d.DeviceIds) > maxBanDeviceIDs {
		return errMsg("Too many device ids (max 10000)")
	}
	for _, ip := range d.Ips {
		if !ipv4Re.MatchString(ip) {
			return errMsg("Invalid IP address: " + ip)
		}
	}
	return nil
}
