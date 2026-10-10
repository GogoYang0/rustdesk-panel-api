// Package dto 本文件：update-check 域 DTO（设计事实④，M3 T07）。
//
// 视图别名至 oapi-codegen 产物；遥测 payload 结构在此声明，供
// service/updatecheck 组装（与参考实现的 payload 字段对齐）。
package dto

import "github.com/rustdesk-panel/rustdesk-panel-api/internal/api"

// UpdateCheckResultView GET /api/update-check 响应。
type UpdateCheckResultView = api.UpdateCheckResult

// UpdateCheckPayload 上报遥测 payload（POST {NEXUS_UPSTREAM}/v1/update/check）。
//
// 字段命名与参考一致（snake_case），version 为面板版本，
// deployment 携带渠道与 install_id。
type UpdateCheckPayload struct {
	Version    string                `json:"version"`
	Deployment UpdateDeploymentInfo  `json:"deployment"`
	System     UpdateSystemInfo      `json:"system"`
	Runtime    UpdateRuntimeInfo     `json:"runtime"`
	Database   UpdateDatabaseInfo    `json:"database"`
	Stats      UpdateStatisticsInfo  `json:"statistics"`
}

// UpdateDeploymentInfo 部署信息（渠道 + 安装实例 id）。
type UpdateDeploymentInfo struct {
	Channel   string `json:"channel"`
	InstallID string `json:"install_id"`
}

// UpdateSystemInfo 宿主系统信息（gopsutil 采集）。
type UpdateSystemInfo struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	CPUCount int    `json:"cpu_count"`
	MemTotal uint64 `json:"mem_total"`
}

// UpdateRuntimeInfo 运行时信息。
type UpdateRuntimeInfo struct {
	GoVersion string `json:"go_version"`
	UptimeSec int64  `json:"uptime_sec"`
}

// UpdateDatabaseInfo 数据库信息。
type UpdateDatabaseInfo struct {
	Driver string `json:"driver"`
}

// UpdateStatisticsInfo 业务统计（用户/设备/策略计数）。
type UpdateStatisticsInfo struct {
	Users    int64 `json:"users"`
	Devices  int64 `json:"devices"`
	Groups   int64 `json:"groups"`
	Strategy int64 `json:"strategy"`
}

// UpdateCheckUpstream 上游响应（{NEXUS_UPSTREAM}/v1/update/check 200 体）。
//
// backend/frontend 各自给出 latest 与 download_url；面板侧按渠道与
// install_id 组装最终响应。
type UpdateCheckUpstream struct {
	Backend *UpdateCheckBranch `json:"backend,omitempty"`
	Frontend *UpdateCheckBranch `json:"frontend,omitempty"`
}

// UpdateCheckBranch 单分支上游结果。
type UpdateCheckBranch struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
}
