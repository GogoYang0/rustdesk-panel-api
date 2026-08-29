// Package settings 本文件：system_settings KV 服务（设计事实④，M3 T07）。
//
// 类型化 getter/setter 与掩码约定集中在此；各域（general/smtp/ldap/
// frontend）只声明键目录并调用本服务，避免散落的裸 SQL 与类型断言。
package settings

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
)

// Store system_settings KV 读写门面。
type Store struct {
	repo *repository.SystemSettingRepo
	// now 可注入虚拟时钟（测试用）；默认 time.Now。
	now func() time.Time
}

// NewStore 构建 KV 服务。
func NewStore(repo *repository.SystemSettingRepo) *Store {
	return &Store{repo: repo, now: time.Now}
}

// Get 读单键原始值；未找到返回 ("", false, nil)。
func (s *Store) Get(ctx context.Context, key string) (string, bool, error) {
	row, err := s.repo.Get(ctx, key)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	return row.Value, true, nil
}

// MustGet 读单键，未找到返回 def。
func (s *Store) MustGet(ctx context.Context, key, def string) (string, error) {
	v, ok, err := s.Get(ctx, key)
	if err != nil {
		return "", err
	}
	if !ok {
		return def, nil
	}
	return v, nil
}

// Set 写单键（category 归入该键所属段）。
func (s *Store) Set(ctx context.Context, key, value, category string) error {
	return s.repo.Set(ctx, key, value, category)
}

// GetString 读字符串键（未找到返回 def）。
func (s *Store) GetString(ctx context.Context, key, def string) (string, error) {
	return s.MustGet(ctx, key, def)
}

// GetBool 读布尔键（"true"/"1" 为真；未找到或解析失败返回 def）。
func (s *Store) GetBool(ctx context.Context, key string, def bool) (bool, error) {
	v, ok, err := s.Get(ctx, key)
	if err != nil {
		return def, err
	}
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	parsed, perr := strconv.ParseBool(strings.TrimSpace(v))
	if perr != nil {
		return def, nil
	}
	return parsed, nil
}

// GetInt 读整数键（未找到或解析失败返回 def）。
func (s *Store) GetInt(ctx context.Context, key string, def int) (int, error) {
	v, ok, err := s.Get(ctx, key)
	if err != nil {
		return def, err
	}
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	parsed, perr := strconv.Atoi(strings.TrimSpace(v))
	if perr != nil {
		return def, nil
	}
	return parsed, nil
}

// GetStringList 读字符串数组键（以换行分隔存储；未找到返回 def）。
func (s *Store) GetStringList(ctx context.Context, key string, def []string) ([]string, error) {
	v, ok, err := s.Get(ctx, key)
	if err != nil {
		return def, err
	}
	if !ok || strings.TrimSpace(v) == "" {
		return def, nil
	}
	parts := strings.Split(v, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out, nil
}

// SetBool 写布尔键（"true"/"false"）。
func (s *Store) SetBool(ctx context.Context, key string, value bool, category string) error {
	return s.repo.Set(ctx, key, strconv.FormatBool(value), category)
}

// SetInt 写整数键（十进制字面量）。
func (s *Store) SetInt(ctx context.Context, key string, value int, category string) error {
	return s.repo.Set(ctx, key, strconv.Itoa(value), category)
}

// SetStringList 写字符串数组键（换行分隔）。
func (s *Store) SetStringList(ctx context.Context, key string, value []string, category string) error {
	return s.repo.Set(ctx, key, strings.Join(value, "\n"), category)
}

// SetIfNotMasked 掩码感知写入：value == dto.MaskedSecret 时跳过（保留原值），
// 返回是否实际写入（共享知识 18）。
func (s *Store) SetIfNotMasked(ctx context.Context, key, value, category string) (bool, error) {
	if value == dto.MaskedSecret {
		return false, nil
	}
	if err := s.repo.Set(ctx, key, value, category); err != nil {
		return false, err
	}
	return true, nil
}

// HasAnyPrefix 报告前缀下是否已有任意键（用于 smtp/ldap 未配置判定）。
func (s *Store) HasAnyPrefix(ctx context.Context, prefix string) (bool, error) {
	rows, err := s.repo.GetAllByPrefix(ctx, prefix)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// Keys 返回前缀下全部键名（不含值）。
func (s *Store) Keys(ctx context.Context, prefix string) ([]string, error) {
	rows, err := s.repo.GetAllByPrefix(ctx, prefix)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Key)
	}
	return out, nil
}

// Delete 删单键。
func (s *Store) Delete(ctx context.Context, key string) error {
	return s.repo.DeleteByKey(ctx, key)
}
