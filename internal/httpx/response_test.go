package httpx

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	WriteJSON(w, 200, map[string]any{"access_token": "abc", "type": "account"})
	if w.Code != 200 {
		t.Errorf("code = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if body["access_token"] != "abc" || body["type"] != "account" {
		t.Errorf("body = %v", body)
	}
}

// TestErrorEnvelopeShapes 覆盖共享知识 1 的全部错误形态。
func TestErrorEnvelopeShapes(t *testing.T) {
	t.Run("business object message (400)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ErrBadRequest(w, "Username and password are required")
		assertEnvelope(t, w, 400, map[string]any{"error": "Username and password are required"}, "Bad Request")
	})

	t.Run("plain text message (401)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ErrUnauthorized(w, "Token expired or revoked")
		assertEnvelope(t, w, 401, "Token expired or revoked", "Unauthorized")
	})

	t.Run("not found (404)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ErrNotFound(w, "User not found")
		assertEnvelope(t, w, 404, "User not found", "Not Found")
	})

	t.Run("conflict (409)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ErrConflict(w, "Username already exists")
		assertEnvelope(t, w, 409, "Username already exists", "Conflict")
	})

	t.Run("too many requests (429)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ErrTooMany(w)
		assertEnvelope(t, w, 429, "ThrottlerException: Too many requests", "Too Many Requests")
	})

	t.Run("internal (500)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ErrInternal(w)
		assertEnvelope(t, w, 500, "Internal server error", "Internal Server Error")
	})

	t.Run("validation array message (400)", func(t *testing.T) {
		w := httptest.NewRecorder()
		ErrBadRequestMessages(w, []string{"username should not be empty", "password should not be empty"})
		assertEnvelope(t, w, 400, []any{"username should not be empty", "password should not be empty"}, "Bad Request")
	})
}

// assertEnvelope 断言包络三字段精确形状（字段名是契约：statusCode/message/error）。
func assertEnvelope(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantMessage any, wantErr string) {
	t.Helper()
	var env ErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("envelope not json: %v", err)
	}
	if env.StatusCode != wantStatus {
		t.Errorf("statusCode = %d, want %d", env.StatusCode, wantStatus)
	}
	if env.Error != wantErr {
		t.Errorf("error = %q, want %q", env.Error, wantErr)
	}
	switch want := wantMessage.(type) {
	case string:
		s, ok := env.Message.(string)
		if !ok || s != want {
			t.Errorf("message = %#v, want string %q", env.Message, want)
		}
	case []any:
		arr, ok := env.Message.([]any)
		if !ok {
			t.Fatalf("message = %#v, want array", env.Message)
		}
		if len(arr) != len(want) {
			t.Fatalf("message len = %d, want %d", len(arr), len(want))
		}
		for i := range want {
			if arr[i] != want[i] {
				t.Errorf("message[%d] = %v, want %v", i, arr[i], want[i])
			}
		}
	case map[string]any:
		m, ok := env.Message.(map[string]any)
		if !ok {
			t.Fatalf("message = %#v, want object", env.Message)
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("message[%q] = %v, want %v", k, m[k], v)
			}
		}
	}
}

func TestFailGeneric(t *testing.T) {
	w := httptest.NewRecorder()
	Fail(w, 418, "teapot")
	var env ErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("envelope not json: %v", err)
	}
	if env.StatusCode != 418 || env.Error != "I'm a teapot" || env.Message != "teapot" {
		t.Errorf("envelope = %+v", env)
	}
}

// TestDecodeJSONValidation 覆盖绑定校验：message 数组、未知字段拒绝、语法错误。
func TestDecodeJSONValidation(t *testing.T) {
	type loginReq struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required,min=6"`
		TfaCode  string `json:"tfaCode" validate:"omitempty,len=6"`
	}

	t.Run("ok", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"u","password":"123456"}`))
		w := httptest.NewRecorder()
		req, ok := DecodeJSON[loginReq](w, r)
		if !ok {
			t.Fatalf("DecodeJSON failed: %s", w.Body.String())
		}
		if req.Username != "u" || req.Password != "123456" {
			t.Errorf("decoded = %+v", req)
		}
	})

	t.Run("missing required -> message array", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		if _, ok := DecodeJSON[loginReq](w, r); ok {
			t.Fatal("DecodeJSON should fail")
		}
		var env ErrorEnvelope
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		arr, isArr := env.Message.([]any)
		if !isArr {
			t.Fatalf("message = %#v, want array (class-validator shape)", env.Message)
		}
		if len(arr) < 2 {
			t.Errorf("messages = %v, want >= 2 entries", arr)
		}
		if env.StatusCode != 400 || env.Error != "Bad Request" {
			t.Errorf("envelope = %+v", env)
		}
	})

	t.Run("unknown field rejected (forbidNonWhitelisted)", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"u","password":"123456","hack":true}`))
		w := httptest.NewRecorder()
		if _, ok := DecodeJSON[loginReq](w, r); ok {
			t.Fatal("DecodeJSON should reject unknown field")
		}
		if w.Code != 400 {
			t.Errorf("code = %d, want 400", w.Code)
		}
	})

	t.Run("min length message", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"u","password":"123"}`))
		w := httptest.NewRecorder()
		if _, ok := DecodeJSON[loginReq](w, r); ok {
			t.Fatal("DecodeJSON should fail on min=6")
		}
		if !strings.Contains(w.Body.String(), "must be longer than or equal to 6 characters") {
			t.Errorf("message = %s", w.Body.String())
		}
	})

	t.Run("malformed json -> plain text", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{`))
		w := httptest.NewRecorder()
		if _, ok := DecodeJSON[loginReq](w, r); ok {
			t.Fatal("DecodeJSON should fail on malformed json")
		}
		if w.Code != 400 {
			t.Errorf("code = %d, want 400", w.Code)
		}
	})
}

func TestValidationMessage(t *testing.T) {
	type sample struct {
		Email string `json:"email" validate:"omitempty,email"`
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"email":"not-an-email"}`))
	if _, ok := DecodeJSON[sample](w, r); ok {
		t.Fatal("should fail email validation")
	}
	if !strings.Contains(w.Body.String(), "must be an email") {
		t.Errorf("message = %s", w.Body.String())
	}
}
