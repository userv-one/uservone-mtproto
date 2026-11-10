package core

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestSecretRotationOverlapAndExpiry(t *testing.T) {
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
	oldHandshake, _, _ := makeClientHandshake(t, oldKey, 1)
	if _, err := proxy.decodeClientHandshake(oldHandshake, true); err != nil {
		t.Fatalf("previous secret must work during grace period: %v", err)
	}
	newKey, _ := hex.DecodeString(newSecret)
	newHandshake, _, _ := makeClientHandshake(t, newKey, 1)
	if _, err := proxy.decodeClientHandshake(newHandshake, true); err != nil {
		t.Fatalf("new secret must work immediately: %v", err)
	}

	now = now.Add(6 * time.Minute)
	expiredHandshake, _, _ := makeClientHandshake(t, oldKey, 1)
	if _, err := proxy.decodeClientHandshake(expiredHandshake, true); err == nil {
		t.Fatal("previous secret must stop working after grace period")
	}
	anotherNewHandshake, _, _ := makeClientHandshake(t, newKey, 1)
	if _, err := proxy.decodeClientHandshake(anotherNewHandshake, true); err != nil {
		t.Fatalf("new secret must remain active after grace period: %v", err)
	}
}
