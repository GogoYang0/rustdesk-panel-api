package dashboard

import (
	"math"
	"os"
	"path/filepath"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

// SystemStatus 系统状态采集（gopsutil/v3，§10-6 批复；参考用
// systeminformation + os.uptime）。返回 (cpu, memory, disk) 百分比
// （一位小数，clamp [0,100]）与主机 uptime 秒。
//
// 采集失败项回落 0：生成契约 systemStatus 四字段均非可空，无法表达
// 参考的 null 语义（偏离注记，QA 快照以字段存在为准）。cpu.Percent(0)
// 首调返回自开机均值、后续为距上次调用增量——与参考 currentLoad 的
// 采样语义等价（均无固定窗口阻塞）。
func SystemStatus(dataDir string) (cpuPct, memPct, diskPct float32, uptime int) {
	cpuPct = float32(round1(gopsutilCPUPercent()))
	memPct = float32(round1(gopsutilMemPercent()))
	diskPct = float32(round1(gopsutilDiskPercent(diskAnchor(dataDir))))
	uptime = gopsutilUptime()
	return cpuPct, memPct, diskPct, uptime
}

// diskAnchor 磁盘统计路径（参考 statfs(databasePath)——DB 所在卷；
// DATA_DIR 未配置时回退根卷）。
func diskAnchor(dataDir string) string {
	if dataDir == "" {
		return string(os.PathSeparator)
	}
	if abs, err := filepath.Abs(dataDir); err == nil {
		return abs
	}
	return dataDir
}

// gopsutilCPUPercent CPU 使用率（%）。
func gopsutilCPUPercent() float64 {
	percents, err := cpu.Percent(0, false)
	if err != nil || len(percents) == 0 {
		return 0
	}
	return percents[0]
}

// gopsutilMemPercent 内存使用率（(total-available)/total×100，与参考
// si.mem 同口径）。
func gopsutilMemPercent() float64 {
	vm, err := mem.VirtualMemory()
	if err != nil || vm.Total <= 0 {
		return 0
	}
	return float64(vm.Total-vm.Available) / float64(vm.Total) * 100
}

// gopsutilDiskPercent 磁盘使用率（(blocks-bfree)/blocks×100 等价口径）。
func gopsutilDiskPercent(path string) float64 {
	usage, err := disk.Usage(path)
	if err != nil || usage.Total <= 0 {
		return 0
	}
	return usage.UsedPercent
}

// gopsutilUptime 主机 uptime（秒，os.uptime 同源语义；uint64 恒非负，
// 仅错误时回落 0）。
func gopsutilUptime() int {
	info, err := host.Info()
	if err != nil {
		return 0
	}
	return int(info.Uptime)
}

// round1 一位小数舍入并 clamp [0,100]（参考 roundPercentage）。
func round1(v float64) float64 {
	if v < 0 {
		v = 0
	}
	if v > 100 {
		v = 100
	}
	return math.Round(v*10) / 10
}
