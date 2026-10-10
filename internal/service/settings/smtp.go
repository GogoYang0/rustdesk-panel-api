// Package settings 本文件：smtp.* 键目录、掩码回读/跳更与连通性测试
// （设计事实④，M3 T07）。
//
// 7 键：smtp.host/port/secure/user/pass/from/enabled。pass 回读恒
// '******'，PUT 命中掩码跳过更新；无配置时 GET 404
// 'SMTP configuration does not exist'。POST test 恒 200（连接失败也是
// 200 + success:false）。
package settings

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/repository"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/rbac"
)

// smtp.* 键目录（共享知识 18）。
const (
	KeySMTPHost    = "smtp.host"
	KeySMTPPort    = "smtp.port"
	KeySMTPSecure  = "smtp.secure"
	KeySMTPUser    = "smtp.user"
	KeySMTPPass    = "smtp.pass"
	KeySMTPFrom    = "smtp.from"
	KeySMTPEnabled = "smtp.enabled"
)

// smtpCategory system_settings.category 归段。
const smtpCategory = "smtp"

// 缺省值（无配置时由 GET 判定 404，故此处仅用于类型化回退）。
const (
	defaultSMTPPort    = 587
	defaultSMTPSecure  = false
	defaultSMTPEnabled = false
)

// smtpTestTimeout 连通性测试超时（避免任一失效主机长时间挂住请求）。
const smtpTestTimeout = 8 * time.Second

// SmtpService SMTP 配置读写与测试。
type SmtpService struct {
	store *Store
}

// NewSmtpService 构建服务。
func NewSmtpService(store *Store) *SmtpService {
	return &SmtpService{store: store}
}

// Get 读取配置：无任何 smtp.* 键时 404 固定文案；pass 恒掩码。
func (s *SmtpService) Get(ctx context.Context) (dto.SmtpConfigDto, error) {
	configured, err := s.store.HasAnyPrefix(ctx, "smtp.")
	if err != nil {
		return dto.SmtpConfigDto{}, err
	}
	if !configured {
		return dto.SmtpConfigDto{}, rbac.ErrNotFoundErr(errMsgSMTPNotConfigured)
	}
	host, err := s.store.GetString(ctx, KeySMTPHost, "")
	if err != nil {
		return dto.SmtpConfigDto{}, err
	}
	port, err := s.store.GetInt(ctx, KeySMTPPort, defaultSMTPPort)
	if err != nil {
		return dto.SmtpConfigDto{}, err
	}
	secure, err := s.store.GetBool(ctx, KeySMTPSecure, defaultSMTPSecure)
	if err != nil {
		return dto.SmtpConfigDto{}, err
	}
	user, err := s.store.GetString(ctx, KeySMTPUser, "")
	if err != nil {
		return dto.SmtpConfigDto{}, err
	}
	from, err := s.store.GetString(ctx, KeySMTPFrom, "")
	if err != nil {
		return dto.SmtpConfigDto{}, err
	}
	enabled, err := s.store.GetBool(ctx, KeySMTPEnabled, defaultSMTPEnabled)
	if err != nil {
		return dto.SmtpConfigDto{}, err
	}
	masked := dto.MaskedSecret
	return dto.SmtpConfigDto{
		Host:    &host,
		Port:    &port,
		Secure:  &secure,
		User:    &user,
		Pass:    &masked,
		From:    &from,
		Enabled: &enabled,
	}, nil
}

// Update 写入配置（pass 命中掩码跳过），返回更新后视图。
func (s *SmtpService) Update(ctx context.Context, req *dto.SmtpConfigDto) (dto.SmtpConfigDto, error) {
	if req.Host != nil {
		if err := s.store.Set(ctx, KeySMTPHost, *req.Host, smtpCategory); err != nil {
			return dto.SmtpConfigDto{}, err
		}
	}
	if req.Port != nil {
		if err := s.store.SetInt(ctx, KeySMTPPort, *req.Port, smtpCategory); err != nil {
			return dto.SmtpConfigDto{}, err
		}
	}
	if req.Secure != nil {
		if err := s.store.SetBool(ctx, KeySMTPSecure, *req.Secure, smtpCategory); err != nil {
			return dto.SmtpConfigDto{}, err
		}
	}
	if req.User != nil {
		if err := s.store.Set(ctx, KeySMTPUser, *req.User, smtpCategory); err != nil {
			return dto.SmtpConfigDto{}, err
		}
	}
	if req.Pass != nil {
		// 掩码跳更：客户端回写的 ****** 不覆盖真实口令（共享知识 18）。
		if _, err := s.store.SetIfNotMasked(ctx, KeySMTPPass, *req.Pass, smtpCategory); err != nil {
			return dto.SmtpConfigDto{}, err
		}
	}
	if req.From != nil {
		if err := s.store.Set(ctx, KeySMTPFrom, *req.From, smtpCategory); err != nil {
			return dto.SmtpConfigDto{}, err
		}
	}
	if req.Enabled != nil {
		if err := s.store.SetBool(ctx, KeySMTPEnabled, *req.Enabled, smtpCategory); err != nil {
			return dto.SmtpConfigDto{}, err
		}
	}
	return s.Get(ctx)
}

// Test 连通性测试：body 可省略（nil → 用已存配置）；恒返回 (result, nil)，
// 失败以 success:false + message 表达（不抛出错误 → handler 恒 200）。
func (s *SmtpService) Test(ctx context.Context, req *dto.SmtpConfigDto) (dto.SettingsTestResultView, error) {
	cfg, err := s.effective(ctx, req)
	if err != nil {
		return dto.SettingsTestResultView{Success: false, Message: err.Error()}, nil
	}
	if strings.TrimSpace(deref(cfg.Host)) == "" {
		return dto.SettingsTestResultView{Success: false, Message: "SMTP host is not configured"}, nil
	}
	if err := probeSMTP(cfg); err != nil {
		return dto.SettingsTestResultView{Success: false, Message: err.Error()}, nil
	}
	return dto.SettingsTestResultView{Success: true, Message: "SMTP connection successful"}, nil
}

// effective 合并已存配置与请求覆盖项（请求项优先，pass 掩码视为未提供）。
func (s *SmtpService) effective(ctx context.Context, req *dto.SmtpConfigDto) (dto.SmtpConfigDto, error) {
	stored, err := s.Get(ctx)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			stored = dto.SmtpConfigDto{}
		} else {
			return dto.SmtpConfigDto{}, err
		}
	}
	if req == nil {
		if stored.Pass != nil {
			real, _, perr := s.store.Get(ctx, KeySMTPPass)
			if perr != nil {
				return dto.SmtpConfigDto{}, perr
			}
			stored.Pass = &real
		}
		return stored, nil
	}
	if req.Host != nil {
		stored.Host = req.Host
	}
	if req.Port != nil {
		stored.Port = req.Port
	}
	if req.Secure != nil {
		stored.Secure = req.Secure
	}
	if req.User != nil {
		stored.User = req.User
	}
	if req.From != nil {
		stored.From = req.From
	}
	if req.Enabled != nil {
		stored.Enabled = req.Enabled
	}
	if req.Pass != nil && *req.Pass != dto.MaskedSecret {
		stored.Pass = req.Pass
	} else {
		// 掩码或未提供 → 取库内真实口令。
		real, _, perr := s.store.Get(ctx, KeySMTPPass)
		if perr != nil {
			return dto.SmtpConfigDto{}, perr
		}
		stored.Pass = &real
	}
	return stored, nil
}

// probeSMTP 建立到 SMTP 服务器的连接并校验握手（不实际投递邮件）。
//
// secure=true 使用隐式 TLS（465 形态）；false 走明文 + STARTTLS 尝试
// （服务器不支持时以明文继续，与"连通性"语义一致）。
func probeSMTP(cfg dto.SmtpConfigDto) error {
	host := strings.TrimSpace(deref(cfg.Host))
	port := defaultSMTPPort
	if cfg.Port != nil {
		port = *cfg.Port
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: smtpTestTimeout}
	if cfg.Secure != nil && *cfg.Secure {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err != nil {
			return fmt.Errorf("SMTP connection failed: %w", err)
		}
		defer func() { _ = conn.Close() }()
		return smtpHandshake(conn, host, cfg, true)
	}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("SMTP connection failed: %w", err)
	}
	defer func() { _ = conn.Close() }()
	return smtpHandshake(conn, host, cfg, false)
}

// smtpHandshake 在已建立连接上完成 EHLO（必要时 AUTH），不投递邮件。
func smtpHandshake(conn net.Conn, host string, cfg dto.SmtpConfigDto, implicitTLS bool) error {
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP handshake failed: %w", err)
	}
	defer func() { _ = client.Close() }()
	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("SMTP STARTTLS failed: %w", err)
			}
		}
	}
	user := deref(cfg.User)
	pass := deref(cfg.Pass)
	if user != "" {
		auth := smtp.PlainAuth("", user, pass, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}
	if err := client.Noop(); err != nil {
		return fmt.Errorf("SMTP noop failed: %w", err)
	}
	return nil
}

// deref 字符串指针安全解引用。
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
