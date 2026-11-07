package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigAppliesSecureDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	contents := `{
		"listen": "127.0.0.1:8443",
		"users": {"media": "` + strings.Repeat("42", 16) + `"},
		"tls_domain": "example.org"
	}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.EnableSecure || !cfg.EnableTLS {
		t.Fatalf("secure transports were not enabled by default: %+v", cfg)
	}
	if !cfg.Mask {
		t.Fatal("masking must be enabled by default")
	}
	if cfg.MaskHost != "example.org" {
		t.Fatalf("mask host = %q, want TLS domain", cfg.MaskHost)
	}
	if cfg.HandshakeTimeout != 10 || cfg.ReplayCacheSize != 65536 {
		t.Fatalf("safety defaults were not applied: %+v", cfg)
	}
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	contents := `{"users":{"media":"` + strings.Repeat("42", 16) + `"},"unknown":true}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown configuration fields must be rejected")
	}
}
