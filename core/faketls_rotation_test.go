package core

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestFakeTLSSecretRotationOverlapAndExpiry(t *testing.T) {
	oldSecret := strings.Repeat("42", 16)
	newSecret := strings.Repeat("24", 16)
	cfg := testConfig()
	cfg.Users = map[string]string{"old": oldSecret}
	proxy, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	proxy.users.now = func() time.Time { return now }
	if err := proxy.ReloadUsers(map[string]string{"new": newSecret}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	oldKey, _ := hex.DecodeString(oldSecret)
	newKey, _ := hex.DecodeString(newSecret)
	if _, _, err := proxy.handleFakeTLS(&captureConn{}, makeClientHello(t, oldKey)); err != nil {
		t.Fatalf("previous fake-TLS secret rejected during grace: %v", err)
	}
	if _, _, err := proxy.handleFakeTLS(&captureConn{}, makeClientHello(t, newKey)); err != nil {
		t.Fatalf("new fake-TLS secret rejected: %v", err)
	}
	now = now.Add(6 * time.Minute)
	if _, _, err := proxy.handleFakeTLS(&captureConn{}, makeClientHello(t, oldKey)); err == nil {
		t.Fatal("previous fake-TLS secret accepted after grace")
	}
	if _, _, err := proxy.handleFakeTLS(&captureConn{}, makeClientHello(t, newKey)); err != nil {
		t.Fatalf("new fake-TLS secret rejected after grace: %v", err)
	}
}
