// Package settings 本文件：ldap.* 键目录、掩码回读/跳更与连通性测试
// （设计事实④，M3 T07）。
//
// 13 键：urls/bindDN/bindCredentials/searchBase/searchFilter/
// searchAttributes/groupSearchBase/groupSearchFilter/adminGroups/
// tlsOptions(ca,cert,key,servername)/enabled。bindCredentials 回读恒
// '******'，PUT 命中掩码跳过。POST test 语义同 smtp（恒 200）。
package settings

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/dto"
)

// ldap.* 键目录（共享知识 18）。
const (
	KeyLdapURLs              = "ldap.urls"
	KeyLdapBindDN            = "ldap.bindDN"
	KeyLdapBindCredentials   = "ldap.bindCredentials"
	KeyLdapSearchBase        = "ldap.searchBase"
	KeyLdapSearchFilter      = "ldap.searchFilter"
	KeyLdapSearchAttributes  = "ldap.searchAttributes"
	KeyLdapGroupSearchBase   = "ldap.groupSearchBase"
	KeyLdapGroupSearchFilter = "ldap.groupSearchFilter"
	KeyLdapAdminGroups       = "ldap.adminGroups"
	KeyLdapTLSCa             = "ldap.tlsOptions.ca"
	KeyLdapTLSCert           = "ldap.tlsOptions.cert"
	KeyLdapTLSKey            = "ldap.tlsOptions.key"
	KeyLdapTLSServername     = "ldap.tlsOptions.servername"
	KeyLdapEnabled           = "ldap.enabled"
)

// ldapCategory system_settings.category 归段。
const ldapCategory = "ldap"

// 缺省值。
const (
	defaultLdapSearchFilter = "(uid=%s)"
	defaultLdapEnabled      = false
)

// ldapTestTimeout 连通性测试超时。
const ldapTestTimeout = 8 * time.Second

// errMsgSMTPNotConfigured 固定文案（共享知识 16）。
const errMsgSMTPNotConfigured = "SMTP configuration does not exist"

// LdapService LDAP 配置读写与测试。
type LdapService struct {
	store *Store
}

// NewLdapService 构建服务。
func NewLdapService(store *Store) *LdapService {
	return &LdapService{store: store}
}

// Get 读取配置：bindCredentials 恒掩码；库值缺失逐键回退缺省。
func (s *LdapService) Get(ctx context.Context) (dto.LdapConfigDto, error) {
	urls, err := s.store.GetStringList(ctx, KeyLdapURLs, nil)
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	bindDN, err := s.store.GetString(ctx, KeyLdapBindDN, "")
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	searchBase, err := s.store.GetString(ctx, KeyLdapSearchBase, "")
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	searchFilter, err := s.store.GetString(ctx, KeyLdapSearchFilter, defaultLdapSearchFilter)
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	searchAttributes, err := s.store.GetStringList(ctx, KeyLdapSearchAttributes, nil)
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	groupSearchBase, err := s.store.GetString(ctx, KeyLdapGroupSearchBase, "")
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	groupSearchFilter, err := s.store.GetString(ctx, KeyLdapGroupSearchFilter, "")
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	adminGroups, err := s.store.GetStringList(ctx, KeyLdapAdminGroups, nil)
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	enabled, err := s.store.GetBool(ctx, KeyLdapEnabled, defaultLdapEnabled)
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	ca, err := s.store.GetString(ctx, KeyLdapTLSCa, "")
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	cert, err := s.store.GetString(ctx, KeyLdapTLSCert, "")
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	key, err := s.store.GetString(ctx, KeyLdapTLSKey, "")
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	servername, err := s.store.GetString(ctx, KeyLdapTLSServername, "")
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	masked := dto.MaskedSecret
	return dto.LdapConfigDto{
		Urls:              &urls,
		BindDN:            &bindDN,
		BindCredentials:   &masked,
		SearchBase:        &searchBase,
		SearchFilter:      &searchFilter,
		SearchAttributes:  &searchAttributes,
		GroupSearchBase:   &groupSearchBase,
		GroupSearchFilter: &groupSearchFilter,
		AdminGroups:       &adminGroups,
		Enabled:           &enabled,
		TlsOptions: &struct {
			Ca         *string `json:"ca,omitempty"`
			Cert       *string `json:"cert,omitempty"`
			Key        *string `json:"key,omitempty"`
			Servername *string `json:"servername,omitempty"`
		}{Ca: &ca, Cert: &cert, Key: &key, Servername: &servername},
	}, nil
}

// Update 写入配置（bindCredentials 命中掩码跳过），返回更新后视图。
func (s *LdapService) Update(ctx context.Context, req *dto.LdapConfigDto) (dto.LdapConfigDto, error) {
	if req.Urls != nil {
		if err := s.store.SetStringList(ctx, KeyLdapURLs, *req.Urls, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.BindDN != nil {
		if err := s.store.Set(ctx, KeyLdapBindDN, *req.BindDN, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.BindCredentials != nil {
		// 掩码跳更（共享知识 18）。
		if _, err := s.store.SetIfNotMasked(ctx, KeyLdapBindCredentials, *req.BindCredentials, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.SearchBase != nil {
		if err := s.store.Set(ctx, KeyLdapSearchBase, *req.SearchBase, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.SearchFilter != nil {
		if err := s.store.Set(ctx, KeyLdapSearchFilter, *req.SearchFilter, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.SearchAttributes != nil {
		if err := s.store.SetStringList(ctx, KeyLdapSearchAttributes, *req.SearchAttributes, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.GroupSearchBase != nil {
		if err := s.store.Set(ctx, KeyLdapGroupSearchBase, *req.GroupSearchBase, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.GroupSearchFilter != nil {
		if err := s.store.Set(ctx, KeyLdapGroupSearchFilter, *req.GroupSearchFilter, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.AdminGroups != nil {
		if err := s.store.SetStringList(ctx, KeyLdapAdminGroups, *req.AdminGroups, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	if req.TlsOptions != nil {
		if req.TlsOptions.Ca != nil {
			if err := s.store.Set(ctx, KeyLdapTLSCa, *req.TlsOptions.Ca, ldapCategory); err != nil {
				return dto.LdapConfigDto{}, err
			}
		}
		if req.TlsOptions.Cert != nil {
			if err := s.store.Set(ctx, KeyLdapTLSCert, *req.TlsOptions.Cert, ldapCategory); err != nil {
				return dto.LdapConfigDto{}, err
			}
		}
		if req.TlsOptions.Key != nil {
			if err := s.store.Set(ctx, KeyLdapTLSKey, *req.TlsOptions.Key, ldapCategory); err != nil {
				return dto.LdapConfigDto{}, err
			}
		}
		if req.TlsOptions.Servername != nil {
			if err := s.store.Set(ctx, KeyLdapTLSServername, *req.TlsOptions.Servername, ldapCategory); err != nil {
				return dto.LdapConfigDto{}, err
			}
		}
	}
	if req.Enabled != nil {
		if err := s.store.SetBool(ctx, KeyLdapEnabled, *req.Enabled, ldapCategory); err != nil {
			return dto.LdapConfigDto{}, err
		}
	}
	return s.Get(ctx)
}

// Test 连通性测试：body 可省略（nil → 用已存配置）；恒返回 (result, nil)。
// 成功语义为「连接 + bind（提供凭据时）+ 可选 search」通过。
func (s *LdapService) Test(ctx context.Context, req *dto.LdapConfigDto) (dto.SettingsTestResultView, error) {
	cfg, err := s.effective(ctx, req)
	if err != nil {
		return dto.SettingsTestResultView{Success: false, Message: err.Error()}, nil
	}
	urls := derefList(cfg.Urls)
	if len(urls) == 0 {
		return dto.SettingsTestResultView{Success: false, Message: "LDAP url is not configured"}, nil
	}
	if err := probeLDAP(cfg, urls[0]); err != nil {
		return dto.SettingsTestResultView{Success: false, Message: err.Error()}, nil
	}
	return dto.SettingsTestResultView{Success: true, Message: "LDAP connection successful"}, nil
}

// effective 合并已存配置与请求覆盖项（bindCredentials 掩码视为未提供）。
func (s *LdapService) effective(ctx context.Context, req *dto.LdapConfigDto) (dto.LdapConfigDto, error) {
	stored, err := s.Get(ctx)
	if err != nil {
		return dto.LdapConfigDto{}, err
	}
	if req == nil {
		return stored, nil
	}
	if req.Urls != nil {
		stored.Urls = req.Urls
	}
	if req.BindDN != nil {
		stored.BindDN = req.BindDN
	}
	if req.SearchBase != nil {
		stored.SearchBase = req.SearchBase
	}
	if req.SearchFilter != nil {
		stored.SearchFilter = req.SearchFilter
	}
	if req.SearchAttributes != nil {
		stored.SearchAttributes = req.SearchAttributes
	}
	if req.GroupSearchBase != nil {
		stored.GroupSearchBase = req.GroupSearchBase
	}
	if req.GroupSearchFilter != nil {
		stored.GroupSearchFilter = req.GroupSearchFilter
	}
	if req.AdminGroups != nil {
		stored.AdminGroups = req.AdminGroups
	}
	if req.Enabled != nil {
		stored.Enabled = req.Enabled
	}
	if req.TlsOptions != nil {
		stored.TlsOptions = req.TlsOptions
	}
	if req.BindCredentials != nil && *req.BindCredentials != dto.MaskedSecret {
		stored.BindCredentials = req.BindCredentials
	} else {
		real, _, perr := s.store.Get(ctx, KeyLdapBindCredentials)
		if perr != nil {
			return dto.LdapConfigDto{}, perr
		}
		stored.BindCredentials = &real
	}
	return stored, nil
}

// probeLDAP 连接 LDAP（ldaps 走隐式 TLS），bind 并提供 searchBase 时试搜。
func probeLDAP(cfg dto.LdapConfigDto, url string) error {
	tlsCfg, err := ldapTLSConfig(cfg, url)
	if err != nil {
		return err
	}
	conn, err := ldap.DialURL(url,
		ldap.DialWithTLSConfig(tlsCfg),
		ldap.DialWithDialer(&net.Dialer{Timeout: ldapTestTimeout}),
	)
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer func() { _ = conn.Close() }()
	conn.SetTimeout(ldapTestTimeout)
	bindDN := deref(cfg.BindDN)
	bindPass := deref(cfg.BindCredentials)
	if bindDN != "" {
		if err := conn.Bind(bindDN, bindPass); err != nil {
			return fmt.Errorf("LDAP bind failed: %w", err)
		}
	}
	if base := deref(cfg.SearchBase); base != "" {
		attrs := derefList(cfg.SearchAttributes)
		if len(attrs) == 0 {
			attrs = []string{"dn"}
		}
		_, err := conn.Search(ldap.NewSearchRequest(
			base,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			1, int(ldapTestTimeout.Seconds()), false,
			"(objectClass=*)", attrs, nil,
		))
		if err != nil {
			// search 受限（ACL 等）不否定连通性：bind 已通过即视为成功。
			if !strings.Contains(err.Error(), "No Such Object") {
				return nil
			}
			return fmt.Errorf("LDAP search failed: %w", err)
		}
	}
	return nil
}

// ldapTLSConfig 依配置组装 TLS 配置（ca 为 PEM 根证书；
// servername 覆盖 SNI）。
func ldapTLSConfig(cfg dto.LdapConfigDto, rawURL string) (*tls.Config, error) {
	out := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TlsOptions == nil {
		return out, nil
	}
	if cfg.TlsOptions.Servername != nil && *cfg.TlsOptions.Servername != "" {
		out.ServerName = *cfg.TlsOptions.Servername
	}
	if cfg.TlsOptions.Ca != nil && *cfg.TlsOptions.Ca != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(*cfg.TlsOptions.Ca)) {
			return nil, errors.New("LDAP tlsOptions.ca is not valid PEM")
		}
		out.RootCAs = pool
	}
	if cfg.TlsOptions.Cert != nil && cfg.TlsOptions.Key != nil &&
		*cfg.TlsOptions.Cert != "" && *cfg.TlsOptions.Key != "" {
		pair, err := tls.X509KeyPair([]byte(*cfg.TlsOptions.Cert), []byte(*cfg.TlsOptions.Key))
		if err != nil {
			return nil, fmt.Errorf("LDAP client certificate is invalid: %w", err)
		}
		out.Certificates = []tls.Certificate{pair}
	}
	return out, nil
}

// derefList 字符串切片指针安全解引用。
func derefList(s *[]string) []string {
	if s == nil {
		return nil
	}
	return *s
}
