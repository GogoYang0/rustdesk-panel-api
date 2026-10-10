package auth

import (
	"context"
	"errors"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/api"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/entity"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// ListSessions 当前用户活跃会话（createdAt 倒序，设计场景 D）。
func (s *TokenService) ListSessions(ctx context.Context, userGuid string) ([]api.SessionInfo, error) {
	records, err := s.tokens.ListActive(ctx, userGuid)
	if err != nil {
		return nil, err
	}
	out := make([]api.SessionInfo, 0, len(records))
	for _, t := range records {
		out = append(out, sessionInfoOf(t))
	}
	return out, nil
}

// RevokeSession 按 jti 撤销指定会话；目标不存在或已失效返回 404
// （设计场景 D：撤销后该 token 下次请求即 401）。
func (s *TokenService) RevokeSession(ctx context.Context, userGuid, jti string) error {
	if _, err := s.tokens.FindActive(ctx, userGuid, jti); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return NotFound("Session not found")
		}
		return err
	}
	return s.tokens.RevokeByJti(ctx, userGuid, jti)
}

// sessionInfoOf 实体 → SessionInfo 契约视图。
func sessionInfoOf(t entity.UserToken) api.SessionInfo {
	info := api.SessionInfo{
		Jti:       t.Jti,
		CreatedAt: wallUTC(t.CreatedAt),
		ExpiresAt: wallUTC(t.ExpiresAt),
	}
	if t.DeviceId != "" {
		deviceId := t.DeviceId
		info.DeviceId = &deviceId
	}
	if t.DeviceUuid != "" {
		deviceUuid := t.DeviceUuid
		info.DeviceUuid = &deviceUuid
	}
	if t.DeviceOs != "" {
		deviceOs := t.DeviceOs
		info.DeviceOs = &deviceOs
	}
	if t.DeviceType != "" {
		deviceType := t.DeviceType
		info.DeviceType = &deviceType
	}
	if t.DeviceName != "" {
		deviceName := t.DeviceName
		info.DeviceName = &deviceName
	}
	return info
}

// wallUTC 将 DB 存储的 naive local datetime 按挂钟值重解释为 UTC
// （共享知识 12：DB 存 naive local，JSON 输出 ISO 8601 UTC）。
func wallUTC(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}
