package rbac

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mwx "github.com/rustdesk-panel/rustdesk-panel-api/internal/middleware"
)

// identContext 注入已认证身份的请求。
func identContext(guid string) (*httptest.ResponseRecorder, *http.Request) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	ctx := mwx.IdentityFromContext(req.Context())
	_ = ctx
	// 用包内导出的 context 注入方式（middleware 提供私有键，这里经
	// JWTAuth 不便；直接构造带身份的 ctx 由导出辅助完成）。
	req = req.WithContext(mwx.WithIdentity(req.Context(), &mwx.Identity{UserGuid: guid}))
	return rec, req
}

// TestRequirePermissionMiddleware 覆盖 403 包络形状（NestJS {statusCode,message,error}）。
func TestRequirePermissionMiddleware(t *testing.T) {
	svc := newTestAuthz(t)
	mw := NewMiddleware(svc)
	handler := mw.RequirePermission(CodeDevicesDisconnect)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("denied envelope shape", func(t *testing.T) {
		rec, req := identContext("target")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{`"statusCode":403`, `"message":"Access denied"`, `"error":"Forbidden"`} {
			if !strings.Contains(body, want) {
				t.Errorf("body %q missing %s", body, want)
			}
		}
	})

	t.Run("disabled user gets 401", func(t *testing.T) {
		rec, req := identContext("disabled")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("code = %d, want 401", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Account does not exist or has been disabled") {
			t.Errorf("body = %s", rec.Body.String())
		}
	})

	t.Run("allowed passes through", func(t *testing.T) {
		rec, req := identContext("admin")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d, want 200", rec.Code)
		}
	})
}

// TestSuperAdminMiddlewareWords 覆盖双文案中间件。
func TestSuperAdminMiddlewareWords(t *testing.T) {
	svc := newTestAuthz(t)
	mw := NewMiddleware(svc)

	t.Run("super admin", func(t *testing.T) {
		handler := mw.RequireSuperAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		rec, req := identContext("scoped")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden ||
			!strings.Contains(rec.Body.String(), "Super administrator permission required") {
			t.Fatalf("code = %d body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("admin guard", func(t *testing.T) {
		handler := mw.RequireAdminGuard()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		rec, req := identContext("scoped")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden ||
			!strings.Contains(rec.Body.String(), "Access denied: administrator privileges required") {
			t.Fatalf("code = %d body = %s", rec.Code, rec.Body.String())
		}
	})
}

// TestAuditRedaction 覆盖脱敏序列化。
func TestAuditRedaction(t *testing.T) {
	in := map[string]any{
		"name":       "databk",
		"password":   "p@ss",
		"api_key":    "ak-123",
		"apiKey":     "ak-456",
		"secret":     "s",
		"nested":     map[string]any{"access_token": "tok", "keep": "v"},
		"list":       []any{map[string]any{"clientSecret": "cs"}},
		"note":       "passwordless 是普通文本键名？不，它含 password 子串",
		"identities": "plain",
	}
	out := RedactJSON(in)
	for _, banned := range []string{
		`"password":"p@ss"`, `"api_key":"ak-123"`, `"apiKey":"ak-456"`,
		`"secret":"s"`, `"access_token":"tok"`, `"clientSecret":"cs"`,
	} {
		if strings.Contains(out, banned) {
			t.Errorf("redacted output leaks %s: %s", banned, out)
		}
	}
	if !strings.Contains(out, `"password":"[REDACTED]"`) {
		t.Errorf("password not redacted: %s", out)
	}
	if !strings.Contains(out, `"keep":"v"`) {
		t.Errorf("non-sensitive nested key dropped: %s", out)
	}
}

// TestAuditStoreFailureTolerance 覆盖 RecordDenied 失败仅告警。
func TestAuditStoreFailureTolerance(t *testing.T) {
	svc := NewAuditService(failStore{}, nil)
	// 不 panic 即通过。
	svc.RecordDenied(context.Background(), AuditRecord{Action: "test"})
	if err := svc.Record(context.Background(), AuditRecord{Action: "test"}); err == nil {
		t.Error("Record must propagate store error")
	}
}

type failStore struct{}

func (failStore) CreateAudit(context.Context, AuditRecord) error {
	return errors.New("db down")
}
