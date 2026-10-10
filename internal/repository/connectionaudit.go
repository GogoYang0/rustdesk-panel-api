// Package repository 是唯一允许直接写 GORM 的层。
// 本文件：ConnectionAuditRepo——connection_audits 表仓储。
// 核心语义：UpsertConn 状态机（设计事实②/§4.2：定位键
// deviceId+deviceUuid+connId；报文 action='new' → 行 'open'、
// 报文 action=” → 行 'established'+establishedAt=now）。
package repository

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
)

// DayCount 按日聚合行（trends 曲线；Date 为 DATE() 产出的
// YYYY-MM-DD 字符串，双方言通用——MySQL DATE(datetime(6)) /
// SQLite DATE(RFC3339 文本) 均可解析）。
// DayCount trends 逐日聚合行。Date 为本地时区的 YYYY-MM-DD 标签，
// 与 dashboard.Trends 生成的补零标签同一口径（见 LocalDayExpr 说明）。
type DayCount struct {
	Date  string `gorm:"column:date"`
	Count int64  `gorm:"column:count"`
}

// LocalDayExpr 构造"按本地时区日期归组"的 SQL 表达式（dialect 感知）。
//
// 背景：SQLite 的 DATE(col) 会先把无时区偏移的 DATETIME 字面量按 UTC
// 解读再取日期；而本仓写入的均为 Go time.Now() 的本地时刻（如
// "2026-10-10 01:32:46+08:00"）。直接 DATE() 会得到前一天的
// "2026-10-09"，与 dashboard.Trends 以本地时区生成的补零标签错位，
// 导致本地时间 00:00~08:00（东八区）区间内"今日"计数恒为 0。
//
// 统一修正为：strftime('%Y-%m-%d', col, 'localtime')。该函数把列值
// 视为 UTC 并加上本地偏移——由于 GORM 写入 SQLite 的是带偏移的字面量，
// 结果恰好还原为写入时刻的本地日历日，与 Trends 标签一致。
// MySQL 的 DATE() 已是会话时区语义，无需改写（双方言同构返回
// YYYY-MM-DD 字符串）。
func LocalDayExpr(dialector string, column string) string {
	if dialector == "mysql" {
		return "DATE(" + column + ")"
	}
	return "strftime('%Y-%m-%d', " + column + ", 'localtime')"
}

// ConnAuditFilter GET /api/audits/conn 过滤（契约
// ListConnectionAuditsParams：peer_id/uuid/type 精确，start/end 为
// requestedAt 闭区间边界）。
type ConnAuditFilter struct {
	PeerId   string     // 精确 peerId
	Uuid     string     // 精确 deviceUuid
	Type     *int       // 精确 type
	Start    *time.Time // requestedAt >= Start
	End      *time.Time // requestedAt <= End
	Current  int        // 页码（1 起）
	PageSize int        // 页大小（0 = 不分页）
}

// ConnectionAuditRepo connection_audits 表仓储。
type ConnectionAuditRepo struct {
	*GenericRepository[entity.ConnectionAudit]
}

// NewConnectionAuditRepo 构建仓储。
func NewConnectionAuditRepo(db *gorm.DB) *ConnectionAuditRepo {
	return &ConnectionAuditRepo{GenericRepository: New[entity.ConnectionAudit](db)}
}

// locatorQuery 构建定位键查询（deviceId 必填；deviceUuid/connId
// 逐列区分「等于」与「IS NULL」——列可空，NULL 不参与 = 匹配）。
func (r *ConnectionAuditRepo) locatorQuery(ctx context.Context, deviceId string, deviceUuid, connId *string) *gorm.DB {
	q := r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).Where("deviceId = ?", deviceId)
	if deviceUuid != nil {
		q = q.Where("deviceUuid = ?", *deviceUuid)
	} else {
		q = q.Where("deviceUuid IS NULL")
	}
	if connId != nil {
		q = q.Where("connId = ?", *connId)
	} else {
		q = q.Where("connId IS NULL")
	}
	return q
}

// FindByLocator 按定位键查询既有行；未找到返回 ErrNotFound。
func (r *ConnectionAuditRepo) FindByLocator(ctx context.Context, deviceId string, deviceUuid, connId *string) (*entity.ConnectionAudit, error) {
	var row entity.ConnectionAudit
	err := r.locatorQuery(ctx, deviceId, deviceUuid, connId).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// FindBySession 按 deviceId+sessionId 查询（note-only 上报定位，
// 设计事实②：找不到目标行由服务层转 404）。
func (r *ConnectionAuditRepo) FindBySession(ctx context.Context, deviceId, sessionId string) (*entity.ConnectionAudit, error) {
	var row entity.ConnectionAudit
	err := r.db.WithContext(ctx).
		Where("deviceId = ? AND sessionId = ?", deviceId, sessionId).
		Order("requestedAt DESC").
		First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// UpsertConn 连接审计状态机落库（设计 §4.2）：
//   - 无行 → INSERT（action 恒落 'new'，首报初始化，不采信报文 action）；
//   - 有行且报文 action='new' → UPDATE 'open'；
//   - 有行且报文 action=”（未带）→ UPDATE 'established' + establishedAt=now；
//   - 其余（open/established 重放等）幂等无操作。
//
// 返回落库后的行与是否新建。in 的其余上报列仅在新建时写入
// （迁移分支只动 action/establishedAt，避免重放覆盖显示信息）。
func (r *ConnectionAuditRepo) UpsertConn(ctx context.Context, in *entity.ConnectionAudit) (*entity.ConnectionAudit, bool, error) {
	existing, err := r.FindByLocator(ctx, in.DeviceId, in.DeviceUuid, in.ConnId)
	if errors.Is(err, ErrNotFound) {
		in.Action = entity.ConnActionNew
		if err := r.db.WithContext(ctx).Create(in).Error; err != nil {
			return nil, false, err
		}
		return in, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	switch in.Action {
	case entity.ConnActionNew:
		// 仅行仍为 'new' 时迁移 'open'（established/open 重放不降级）。
		if existing.Action == entity.ConnActionNew {
			if err := r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).
				Where("id = ?", existing.Id).
				Update("action", entity.ConnActionOpen).Error; err != nil {
				return nil, false, err
			}
			existing.Action = entity.ConnActionOpen
		}
		return existing, false, nil
	case "":
		// '' → established（established 重放幂等：不再改写 establishedAt）。
		if existing.Action != entity.ConnActionEstablished {
			now := time.Now()
			if err := r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).
				Where("id = ?", existing.Id).
				Updates(map[string]any{
					"action":        entity.ConnActionEstablished,
					"establishedAt": now,
				}).Error; err != nil {
				return nil, false, err
			}
			existing.Action = entity.ConnActionEstablished
			existing.EstablishedAt = &now
		}
		return existing, false, nil
	default:
		// 未知/重放 action：幂等返回既有行。
		return existing, false, nil
	}
}

// applyConnFilter 构建 conn 列表过滤链（别名列直引，无 JOIN）。
// start/end 统一转本地时区：SQLite 侧时间以本地文本落库/绑定（带
// +08:00 后缀），跨时区后缀的字典序比较不可靠——本地化后与存储文本
// 同构；MySQL 侧 DATETIME 值比较与时区无关，Local 化同样正确。
func applyConnFilter(f ConnAuditFilter) func(*gorm.DB) *gorm.DB {
	return func(q *gorm.DB) *gorm.DB {
		if f.PeerId != "" {
			q = q.Where("peerId = ?", f.PeerId)
		}
		if f.Uuid != "" {
			q = q.Where("deviceUuid = ?", f.Uuid)
		}
		if f.Type != nil {
			q = q.Where("type = ?", *f.Type)
		}
		if f.Start != nil {
			q = q.Where("requestedAt >= ?", f.Start.Local())
		}
		if f.End != nil {
			q = q.Where("requestedAt <= ?", f.End.Local())
		}
		return q
	}
}

// auditPage 通用审计分页执行器（count 与 fetch 独立语句；排序固定
// 时间锚点 DESC + id DESC，同锚并列时稳定）。
func auditPage[T any](r *GenericRepository[T], base *gorm.DB, apply func(*gorm.DB) *gorm.DB, orderCol string, current, pageSize int) ([]T, int64, error) {
	var total int64
	if err := apply(base.Session(&gorm.Session{})).Count(&total).Error; err != nil {
		return nil, 0, err
	}
	fetch := apply(base.Session(&gorm.Session{})).Order(orderCol + " DESC, id DESC")
	if pageSize > 0 {
		fetch = fetch.Limit(pageSize)
		if current > 1 {
			fetch = fetch.Offset((current - 1) * pageSize)
		}
	}
	out := make([]T, 0)
	if err := fetch.Find(&out).Error; err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// ListPaged 连接审计分页（GET /api/audits/conn；audit.view 中间件已过）。
func (r *ConnectionAuditRepo) ListPaged(ctx context.Context, f ConnAuditFilter) ([]entity.ConnectionAudit, int64, error) {
	base := r.db.WithContext(ctx).Model(&entity.ConnectionAudit{})
	return auditPage[entity.ConnectionAudit](r.GenericRepository, base, applyConnFilter(f), "requestedAt", f.Current, f.PageSize)
}

// ListActive 活跃连接列表（GET /api/audits/conn/active 底座）：
// 未关闭行（closedAt IS NULL）。allowedUUIDs 为 scope 内设备 uuid 集
// （服务层由 device_group scope 查出）；nil = 不过滤（全局视图），
// 非 nil 空集 = scope 无可见设备（返回空）。
func (r *ConnectionAuditRepo) ListActive(ctx context.Context, allowedUUIDs []string) ([]entity.ConnectionAudit, error) {
	q := r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).Where("closedAt IS NULL")
	if allowedUUIDs != nil {
		if len(allowedUUIDs) == 0 {
			return []entity.ConnectionAudit{}, nil
		}
		q = q.Where("deviceUuid IN ?", allowedUUIDs)
	}
	out := make([]entity.ConnectionAudit, 0)
	if err := q.Order("requestedAt DESC, id DESC").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// FindByID 按自增主键查询（PATCH /api/audits/conn/{id} 存在性检查）；
// 未找到返回 ErrNotFound。
func (r *ConnectionAuditRepo) FindByID(ctx context.Context, id uint) (*entity.ConnectionAudit, error) {
	var row entity.ConnectionAudit
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// UpdateNote 备注更新（report note-only 模式与 PATCH
// /api/audits/conn/{id} 共用；空串写 NULL——参考 note=dto.note||null
// 语义，查询行 omitempty 序列化保持一致）。
func (r *ConnectionAuditRepo) UpdateNote(ctx context.Context, id uint, note string) error {
	var val any
	if note != "" {
		val = note
	}
	return r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).
		Where("id = ?", id).
		Update("note", val).Error
}

// CountToday 今日连接数（dashboard overview.connections.today；
// dayStart 为当日零点，requestedAt >= dayStart）。
func (r *ConnectionAuditRepo) CountToday(ctx context.Context, dayStart time.Time) (int64, error) {
	var n int64
	err := r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).
		Where("requestedAt >= ?", dayStart).
		Count(&n).Error
	return n, err
}

// CountSuccessFailure 仪表盘成功/失败口径（设计 §1.1⑥，参考实现
// 以当日为界）：success = establishedAt/closedAt 双非空；failure =
// closedAt 非空且 establishedAt 空。since 为当日零点（requestedAt
// 锚点，本表无 createdAt 列，T02 时间锚点契约）。
func (r *ConnectionAuditRepo) CountSuccessFailure(ctx context.Context, since time.Time) (success, failure int64, err error) {
	if err = r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).
		Where("requestedAt >= ? AND establishedAt IS NOT NULL AND closedAt IS NOT NULL", since).
		Count(&success).Error; err != nil {
		return 0, 0, err
	}
	if err = r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).
		Where("requestedAt >= ? AND closedAt IS NOT NULL AND establishedAt IS NULL", since).
		Count(&failure).Error; err != nil {
		return 0, 0, err
	}
	return success, failure, nil
}

// CountByDay 连接数按日聚合（dashboard trends connectionTrend；
// requestedAt 锚点、按本地日历日归组，from 起始零点、to 终止零点
// （左闭右开））。
func (r *ConnectionAuditRepo) CountByDay(ctx context.Context, from, to time.Time) ([]DayCount, error) {
	out := make([]DayCount, 0)
	dayExpr := LocalDayExpr(r.db.Name(), "requestedAt")
	err := r.db.WithContext(ctx).Model(&entity.ConnectionAudit{}).
		Select(dayExpr+" AS date, COUNT(*) AS count").
		Where("requestedAt >= ? AND requestedAt < ?", from, to).
		Group(dayExpr).
		Order("date ASC").
		Scan(&out).Error
	return out, err
}
