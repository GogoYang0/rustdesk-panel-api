package config

import (
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr default = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.DBDriver != "sqlite" {
		t.Errorf("DBDriver default = %q, want sqlite", cfg.DBDriver)
	}
	if cfg.JWTExpiryDays != 30 {
		t.Errorf("JWTExpiryDays default = %d, want 30", cfg.JWTExpiryDays)
	}
	if !cfg.JWTSecretIsDefault() {
		t.Error("JWTSecretIsDefault() = false for default secret, want true")
	}
	if cfg.AdminUsername != "databk" || cfg.AdminEmail != "databk@github.com" || cfg.AdminPassword != "databk" {
		t.Errorf("admin seed defaults wrong: %v", cfg)
	}
	if !cfg.RateLimitEnabled {
		t.Error("RateLimitEnabled default = false, want true")
	}
	if cfg.WebAuthnRPID != "localhost" {
		t.Errorf("WebAuthnRPID default = %q, want localhost", cfg.WebAuthnRPID)
	}
	if len(cfg.WebAuthnOrigins) != 1 || cfg.WebAuthnOrigins[0] != "http://localhost:8080" {
		t.Errorf("WebAuthnOrigins default = %v, want [http://localhost:8080]", cfg.WebAuthnOrigins)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	t.Setenv("HTTP_ADDR", ":9090")
	t.Setenv("DB_DRIVER", "mysql")
	t.Setenv("JWT_SECRET", "production-secret")
	t.Setenv("JWT_EXPIRY_DAYS", "7")
	t.Setenv("WEBAUTHN_ORIGINS", "https://a.example.com,https://b.example.com")
	t.Setenv("ADMIN_USERNAME", "boss")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != ":9090" || cfg.DBDriver != "mysql" {
		t.Errorf("env override failed: %v", cfg)
	}
	if cfg.JWTExpiryDays != 7 {
		t.Errorf("JWTExpiryDays = %d, want 7", cfg.JWTExpiryDays)
	}
	if cfg.JWTSecretIsDefault() {
		t.Error("JWTSecretIsDefault() = true after explicit secret, want false")
	}
	if len(cfg.WebAuthnOrigins) != 2 {
		t.Errorf("WebAuthnOrigins = %v, want 2 entries", cfg.WebAuthnOrigins)
	}
	if cfg.AdminUsername != "boss" {
		t.Errorf("AdminUsername = %q, want boss", cfg.AdminUsername)
	}
}

func TestLoadValidation(t *testing.T) {
	t.Setenv("JWT_EXPIRY_DAYS", "0")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with JWT_EXPIRY_DAYS=0 should fail")
	}

	t.Setenv("JWT_EXPIRY_DAYS", "30")
	t.Setenv("DB_DRIVER", "postgres")
	if _, err := Load(); err == nil {
		t.Fatal("Load() with DB_DRIVER=postgres should fail")
	}
}
