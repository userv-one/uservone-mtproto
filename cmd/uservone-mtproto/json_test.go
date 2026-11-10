package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionJSON(t *testing.T) {
	var output bytes.Buffer
	if code := run([]string{"-version-json"}, &output, &output); code != 0 {
		t.Fatalf("version-json exit code %d: %s", code, output.String())
	}
	var info map[string]string
	if err := json.Unmarshal(output.Bytes(), &info); err != nil {
		t.Fatal(err)
	}
	if info["name"] != appName || info["version"] != version || info["go_version"] == "" {
		t.Fatalf("unexpected version information: %+v", info)
	}
}

func TestLinksJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	config := `{"listen":"127.0.0.1:8443","users":{"media":"` + strings.Repeat("42", 16) + `"},"tls_domain":"example.org"}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code := run([]string{"-config", path, "-links-host", "proxy.example.com", "--format", "json"}, &output, &output)
	if code != 0 {
		t.Fatalf("links JSON exit code %d: %s", code, output.String())
	}
	var links []struct {
		User      string `json:"user"`
		Transport string `json:"transport"`
		URL       string `json:"url"`
	}
	if err := json.Unmarshal(output.Bytes(), &links); err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 || links[0].User != "media" {
		t.Fatalf("unexpected links: %+v", links)
	}
	if !strings.Contains(links[0].URL, "secret=dd") || !strings.Contains(links[1].URL, "secret=ee") {
		t.Fatalf("unexpected links: %+v", links)
	}
}

func TestConfigErrorsDoNotLeakSecrets(t *testing.T) {
	const secret = "private-secret-value"
	path := filepath.Join(t.TempDir(), "proxy.json")
	config := `{"users":{"media":"` + secret + `"}}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if code := run([]string{"-config", path, "-check-config"}, &output, &output); code == 0 {
		t.Fatal("invalid secret was accepted")
	}
	if strings.Contains(output.String(), secret) {
		t.Fatalf("configuration output leaked the secret: %q", output.String())
	}
}
