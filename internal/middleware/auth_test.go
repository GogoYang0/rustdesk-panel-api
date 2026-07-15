package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJWTAuthBearerPriority(t *testing.T) {
	val := ValidatorFunc(func(_ context.Context, raw string) (*Identity, error) {
		if raw == "good-token" {
			return &Identity{UserGuid: "u1", Username: "alice", Jti: "j1"}, nil
		}
		return nil, ErrTokenInvalid
	})
	h := JWTAuth(val)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := IdentityFromContext(r.Context())
		if ident == nil {
			t.Error("identity should be injected")
			w.WriteHeader(500)
			return
		}
		if ident.UserGuid != "u1" {
			t.Errorf("identity = %+v", ident)
		}
		w.WriteHeader(200)
	}))

	t.Run("bearer first", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/sessions", nil)
		req.Header.Set("Authorization", "Bearer good-token")
		req.AddCookie(&http.Cookie{Name: "access_token", Value: "bad-token"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("code = %d, want 200 (bearer wins over cookie)", rec.Code)
		}
	})

	t.Run("cookie fallback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/sessions", nil)
		req.AddCookie(&http.Cookie{Name: "access_token", Value: "good-token"})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("code = %d, want 200 (cookie fallback)", rec.Code)
		}
	})

	t.Run("missing token -> 401 fixed message", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/sessions", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("code = %d, want 401", rec.Code)
		}
		assert401Body(t, rec.Body.String())
	})

	t.Run("invalid token -> 401 fixed message", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/sessions", nil)
		req.Header.Set("Authorization", "Bearer bad-token")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("code = %d, want 401", rec.Code)
		}
		assert401Body(t, rec.Body.String())
	})

	t.Run("non-bearer scheme -> 401", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/sessions", nil)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("code = %d, want 401", rec.Code)
		}
	})
}

func assert401Body(t *testing.T, body string) {
	t.Helper()
	want := `"message":"Token expired or revoked"`
	if !contains(body, want) {
		t.Errorf("body = %s, want to contain %s", body, want)
	}
	if !contains(body, `"statusCode":401`) || !contains(body, `"error":"Unauthorized"`) {
		t.Errorf("body = %s, want envelope shape", body)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestRequestIDAndCORS(t *testing.T) {
	handler := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}), RequestID, CORS)

	t.Run("generates request id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Header().Get("X-Request-Id") == "" {
			t.Error("X-Request-Id should be set")
		}
	})

	t.Run("echoes origin with credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://panel.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://panel.example.com" {
			t.Errorf("ACAO = %q", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Errorf("ACAC = %q", got)
		}
	})

	t.Run("preflight short-circuits 204", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/login", nil)
		req.Header.Set("Origin", "https://panel.example.com")
		rec := httptest.NewRecorder()
		called := false
		h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }),
			RequestID, CORS)
		h.ServeHTTP(rec, req)
		if called {
			t.Error("preflight should short-circuit")
		}
		if rec.Code != 204 {
			t.Errorf("code = %d, want 204", rec.Code)
		}
	})
}

func TestClientIP(t *testing.T) {
	t.Run("x-forwarded-for first entry", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.2")
		if got := ClientIP(req); got != "203.0.113.7" {
			t.Errorf("ClientIP = %q", got)
		}
	})
	t.Run("remote addr fallback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		if got := ClientIP(req); got != "10.0.0.1" {
			t.Errorf("ClientIP = %q", got)
		}
	})
}
