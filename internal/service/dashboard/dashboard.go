// Package dashboard 仪表盘域服务（M3 T04）：overview 聚合（设计
// 事实⑥口径）与 trends 逐日序列（§10-9 批复：GROUP BY 单查询等价
// 实现，空日补 0）。双端点 SuperAdmin 档在路由。
package dashboard

import (
	"context"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// 趋势范围档（spec enum 7d/30d/90d；缺省 7d 与参考 parseRange 一致）。
var trendDays = map[string]int{"7d": 7, "30d": 30, "90d": 90}

// Service 仪表盘服务。
type Service struct {
	counts  *repository.DashboardRepo
	books   *repository.AddressBookRepo
	conns   *repository.ConnectionAuditRepo
	files   *repository.FileAuditRepo
	alarms  *repository.AlarmAuditRepo
	users   *repository.UserRepo
	dataDir string // systemStatus 磁盘统计锚点（DB 所在卷）
}

// NewService 构建仪表盘服务。
func NewService(
	counts *repository.DashboardRepo,
	books *repository.AddressBookRepo,
	conns *repository.ConnectionAuditRepo,
	files *repository.FileAuditRepo,
	alarms *repository.AlarmAuditRepo,
	users *repository.UserRepo,
	dataDir string,
) *Service {
	return &Service{
		counts: counts, books: books, conns: conns,
		files: files, alarms: alarms, users: users, dataDir: dataDir,
	}
}

// overviewUsers 匿名契约视图别名（生成代码内联结构，单点声明）。
type overviewUsers = struct {
	Admin int `json:"admin"`
	Total int `json:"total"`
}

// overviewDevices 匿名契约视图别名。
type overviewDevices = struct {
	Online int `json:"online"`
	Total  int `json:"total"`
}

// overviewConnections 匿名契约视图别名。
type overviewConnections = struct {
	Failure int `json:"failure"`
	Success int `json:"success"`
	Today   int `json:"today"`
}

// overviewFiles 匿名契约视图别名。
type overviewFiles = struct {
	Today  int `json:"today"`
	Upload int `json:"upload"`
}

// overviewCounts 匿名契约视图别名。
type overviewCounts = struct {
	AddressBooks int `json:"addressBooks"`
	Groups       int `json:"groups"`
	Roles        int `json:"roles"`
	Strategies   int `json:"strategies"`
}

// overviewSystemStatus 匿名契约视图别名。
type overviewSystemStatus = struct {
	Cpu    float32 `json:"cpu"`
	Disk   float32 `json:"disk"`
	Memory float32 `json:"memory"`
	Uptime int     `json:"uptime"`
}

// Overview 总览聚合（GET /api/dashboard；设计事实⑥口径，参考
// dashboard.service.ts getDashboard。connections.success/failure 以
// 当日为界——参考 createdAt>=today，本表无 createdAt 列以 requestedAt
// 时间锚点承担；文件当日口径同锚）。
func (s *Service) Overview(ctx context.Context) (api.DashboardOverview, error) {
	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	userTotal, adminCount, err := s.counts.CountUsers(ctx)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	deviceTotal, deviceOnline, err := s.counts.CountDevices(ctx, now.Add(-60*time.Second))
	if err != nil {
		return api.DashboardOverview{}, err
	}
	connToday, err := s.conns.CountToday(ctx, dayStart)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	success, failure, err := s.conns.CountSuccessFailure(ctx, dayStart)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	fileToday, err := s.files.CountToday(ctx, dayStart)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	uploadToday, err := s.files.CountTodayUpload(ctx, dayStart)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	addressBooks, err := s.books.CountAll(ctx)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	userGroups, err := s.counts.CountUserGroups(ctx)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	deviceGroups, err := s.counts.CountDeviceGroups(ctx)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	roles, err := s.counts.CountRoles(ctx)
	if err != nil {
		return api.DashboardOverview{}, err
	}
	strategies, err := s.counts.CountStrategies(ctx)
	if err != nil {
		return api.DashboardOverview{}, err
	}

	cpuPct, memPct, diskPct, uptime := SystemStatus(s.dataDir)
	return api.DashboardOverview{
		Users: overviewUsers{Admin: int(adminCount), Total: int(userTotal)},
		Devices: overviewDevices{
			Online: int(deviceOnline), Total: int(deviceTotal),
		},
		Connections: overviewConnections{
			Failure: int(failure), Success: int(success), Today: int(connToday),
		},
		Files: overviewFiles{Today: int(fileToday), Upload: int(uploadToday)},
		Counts: overviewCounts{
			AddressBooks: int(addressBooks),
			Groups:       int(userGroups + deviceGroups),
			Roles:        int(roles),
			Strategies:   int(strategies),
		},
		SystemStatus: overviewSystemStatus{
			Cpu: cpuPct, Disk: diskPct, Memory: memPct, Uptime: uptime,
		},
	}, nil
}

// trendItemConnection 匿名契约视图别名（connectionTrend/alarmTrend 行）。
type trendItemConnection = struct {
	Count int                `json:"count"`
	Date  openapi_types.Date `json:"date"`
}

// trendItemNewUser 匿名契约视图别名（newUserTrend 行）。
type trendItemNewUser = struct {
	Date     openapi_types.Date `json:"date"`
	NewUsers int                `json:"newUsers"`
}

// Trends 趋势序列（GET /api/dashboard/trends；range 缺省 7d。参考为
// 内存逐日循环逐日 COUNT——本仓以三组 GROUP BY DATE 单查询 + 空日
// 补 0 等价实现，§10-9 批复）。日界与标签均为服务器本地时区。
func (s *Service) Trends(ctx context.Context, rangeParam *string) (api.DashboardTrends, error) {
	days := trendDays["7d"]
	if rangeParam != nil {
		if n, ok := trendDays[*rangeParam]; ok {
			days = n
		}
	}

	now := time.Now()
	from := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).
		AddDate(0, 0, -(days - 1))
	to := from.AddDate(0, 0, days)

	connCounts, err := s.conns.CountByDay(ctx, from, to)
	if err != nil {
		return api.DashboardTrends{}, err
	}
	userCounts, err := s.users.CountByDay(ctx, from, to)
	if err != nil {
		return api.DashboardTrends{}, err
	}
	alarmCounts, err := s.alarms.CountByDay(ctx, from, to)
	if err != nil {
		return api.DashboardTrends{}, err
	}

	connMap := countMap(connCounts)
	userMap := countMap(userCounts)
	alarmMap := countMap(alarmCounts)

	out := api.DashboardTrends{
		ConnectionTrend: make([]trendItemConnection, 0, days),
		NewUserTrend:    make([]trendItemNewUser, 0, days),
		AlarmTrend:      make([]trendItemConnection, 0, days),
	}
	for i := 0; i < days; i++ {
		day := from.AddDate(0, 0, i)
		label := day.Format("2006-01-02")
		out.ConnectionTrend = append(out.ConnectionTrend, trendItemConnection{
			Count: int(connMap[label]),
			Date:  openapi_types.Date{Time: day},
		})
		out.NewUserTrend = append(out.NewUserTrend, trendItemNewUser{
			NewUsers: int(userMap[label]),
			Date:     openapi_types.Date{Time: day},
		})
		out.AlarmTrend = append(out.AlarmTrend, trendItemConnection{
			Count: int(alarmMap[label]),
			Date:  openapi_types.Date{Time: day},
		})
	}
	return out, nil
}

// countMap DayCount 序列 → 日期标签映射（空日由调用方补 0）。
func countMap(rows []repository.DayCount) map[string]int64 {
	m := make(map[string]int64, len(rows))
	for _, r := range rows {
		m[r.Date] = r.Count
	}
	return m
}
