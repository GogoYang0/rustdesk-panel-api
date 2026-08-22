package user

// batch.go 批量用户操作三端点（设计事实①）：部分成功响应 BatchResult，
// 保护账号由 AssertUsersMutation 整批 403 前置；所有者行不可禁用 →
// 记入 failed[]（部分成功允许）；操作者快照与库内状态并发漂移 →
// 409 "User info has changed, please try again"（整批拒绝，非部分成功）。
//
// 漂移判定采用「事务内重读比对」而非 RowsAffected 条件更新：MySQL 的
// UPDATE 默认返回"被改变"行数（值未变化时为 0），与 SQLite 的"被匹配"
// 行数语义相悖——no-op 启停（status 与快照相同）会在 MySQL 侧误报
// 409。先 SELECT 比对快照字段（跨驱动一致），再执行无条件 UPDATE。

import (
	"context"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
	authsvc "github.com/rustdesk-panel/rustdesk-panel-api/internal/service/auth"
)

// msgUserDrift 快照漂移整批拒绝文案（契约 batch/status 409 description）。
const msgUserDrift = "User info has changed, please try again"

// batchFailedItem 与生成代码 BatchResult.Failed 元素类型结构恒等
// （内联匿名结构无法具名引用，此处按字段序/标签逐字对齐）。
type batchFailedItem = struct {
	Guid   string `json:"guid"`
	Reason string `json:"reason"`
}

// batchOutcome 部分成功结果组装器（succeeded/failed 明细 + 计数）。
type batchOutcome struct {
	Succeeded []string
	Failed    []batchFailedItem
}

func newBatchOutcome(total int) batchOutcome {
	return batchOutcome{
		Succeeded: make([]string, 0, total),
		Failed:    make([]batchFailedItem, 0),
	}
}

func (b *batchOutcome) fail(guid, reason string) {
	b.Failed = append(b.Failed, batchFailedItem{Guid: guid, Reason: reason})
}

func (b *batchOutcome) result(total int) api.BatchResult {
	return api.BatchResult{
		Succeeded:      b.Succeeded,
		Failed:         b.Failed,
		Total:          total,
		SucceededCount: len(b.Succeeded),
		FailedCount:    len(b.Failed),
	}
}

// errUserDrift 事务内快照比对未命中 → 整批回滚 409。
var errUserDrift = errors.New("user snapshot drifted")

// assertSnapshotUnchanged 事务内重读目标行并与快照比对；行消失或
// status 漂移 → errUserDrift（整批回滚）。
func assertSnapshotUnchanged(tx *gorm.DB, guid string, wantStatus int) error {
	var cur entity.User
	err := tx.Where("guid = ?", guid).First(&cur).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errUserDrift
		}
		return err
	}
	if cur.Status != wantStatus {
		return errUserDrift
	}
	return nil
}

// BatchStatus PATCH /api/users/batch/status（users.status 中间件已过 +
// AssertUsersMutation）：owner 行不可禁用记入 failed[]；其余行事务内
// 快照比对（status 漂移 → 整批回滚 409）；status 变更行同事务撤 token。
func (s *Service) BatchStatus(ctx context.Context, actorGuid string, req api.BatchStatusRequest) (api.BatchResult, error) {
	if len(req.Guids) == 0 { // spec minItems:1 服务端兜底
		return api.BatchResult{}, authsvc.BadRequest("guids should not be empty")
	}
	if err := s.authz.AssertUsersMutation(ctx, actorGuid, req.Guids, rbac.CodeUsersStatus); err != nil {
		return api.BatchResult{}, err
	}
	rows, err := s.users.FindByGuids(ctx, req.Guids)
	if err != nil {
		return api.BatchResult{}, err
	}
	snapshot := make(map[string]entity.User, len(rows))
	for _, u := range rows {
		snapshot[u.Guid] = u
	}
	targetStatus := int(req.Status)
	out := newBatchOutcome(len(req.Guids))
	targets := make([]string, 0, len(req.Guids))
	for _, guid := range req.Guids {
		row, ok := snapshot[guid]
		if !ok {
			// AssertUsersMutation 已 404 兜底；防御性分支。
			return api.BatchResult{}, authsvc.NotFound("User does not exist")
		}
		// 所有者账号不可禁用（启用放行）→ 记入 failed[]。
		if targetStatus != 1 && s.isSystemOwner(&row) {
			out.fail(guid, rbac.MsgOwnerAccountImmutable)
			continue
		}
		targets = append(targets, guid)
	}

	if len(targets) > 0 {
		err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			for _, guid := range targets {
				if err := assertSnapshotUnchanged(tx, guid, snapshot[guid].Status); err != nil {
					return err
				}
				if err := tx.Model(&entity.User{}).
					Where("guid = ?", guid).
					Update("status", targetStatus).Error; err != nil {
					return err
				}
			}
			for _, guid := range targets {
				if err := s.revokeActiveTokens(ctx, tx, guid); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, errUserDrift) {
				// 纯文本 message（对齐参考 ConflictException("...")）。
				return api.BatchResult{}, rbac.ErrConflictMsg(msgUserDrift)
			}
			return api.BatchResult{}, err
		}
	}
	out.Succeeded = targets
	return out.result(len(req.Guids)), nil
}

// BatchSecurity PATCH /api/users/batch/security（users.security 中间件
// 已过 + AssertUsersMutation）：tfa_enforce/email_verification 写
// users.info JSON；new_password（≥6）统一重置；逐行事务读-改-写 +
// 统一撤 token。
func (s *Service) BatchSecurity(ctx context.Context, actorGuid string, req api.BatchSecurityRequest) (api.MessageResponse, error) {
	if len(req.Guids) == 0 { // spec minItems:1 服务端兜底
		return api.MessageResponse{}, authsvc.BadRequest("guids should not be empty")
	}
	if err := s.authz.AssertUsersMutation(ctx, actorGuid, req.Guids, rbac.CodeUsersSecurity); err != nil {
		return api.MessageResponse{}, err
	}
	hash := ""
	if req.NewPassword != nil {
		if len(*req.NewPassword) < 6 {
			return api.MessageResponse{}, authsvc.BadRequest("New password must be at least 6 characters")
		}
		raw, err := bcrypt.GenerateFromPassword([]byte(*req.NewPassword), 10)
		if err != nil {
			return api.MessageResponse{}, err
		}
		hash = string(raw)
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, guid := range req.Guids {
			var u entity.User
			if err := tx.Where("guid = ?", guid).First(&u).Error; err != nil {
				return err
			}
			// info JSON 读-改-写（顶层键；不触碰 other/隐蔽态键）。
			info := map[string]any{}
			if u.Info != "" {
				if err := json.Unmarshal([]byte(u.Info), &info); err != nil || info == nil {
					info = map[string]any{}
				}
			}
			if req.TfaEnforce != nil {
				info["tfa_enforce"] = *req.TfaEnforce
			}
			if req.EmailVerification != nil {
				info["email_verification"] = *req.EmailVerification
			}
			rawInfo, err := json.Marshal(info)
			if err != nil {
				return err
			}
			updates := map[string]any{"info": string(rawInfo)}
			if hash != "" {
				updates["password"] = hash
			}
			if err := tx.Model(&entity.User{}).Where("guid = ?", guid).Updates(updates).Error; err != nil {
				return err
			}
			if err := s.revokeActiveTokens(ctx, tx, guid); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Bulk security settings updated"}, nil
}

// BatchSessions DELETE /api/users/batch/sessions（users.force_logout
// 中间件已过 + AssertUsersMutation）：逐行事务 revokeActiveTokens。
func (s *Service) BatchSessions(ctx context.Context, actorGuid string, req api.BatchSessionsRequest) (api.MessageResponse, error) {
	if len(req.Guids) == 0 { // spec minItems:1 服务端兜底
		return api.MessageResponse{}, authsvc.BadRequest("guids should not be empty")
	}
	if err := s.authz.AssertUsersMutation(ctx, actorGuid, req.Guids, rbac.CodeUsersForceLogout); err != nil {
		return api.MessageResponse{}, err
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, guid := range req.Guids {
			if err := s.revokeActiveTokens(ctx, tx, guid); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return api.MessageResponse{}, err
	}
	return api.MessageResponse{Message: "Forced logout successful"}, nil
}
