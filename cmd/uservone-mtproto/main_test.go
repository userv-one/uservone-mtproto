package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckConfigAndPrintLinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	config := `{
		"listen":"127.0.0.1:8443",
		"users":{"media":"` + strings.Repeat("42", 16) + `"},
		"tls_domain":"example.org"
	}`
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if code := run([]string{"-config", path, "-check-config"}, &output, &output); code != 0 {
		t.Fatalf("check-config exit code %d: %s", code, output.String())
	}
	if !strings.Contains(output.String(), "configuration OK") {
		t.Fatalf("unexpected output %q", output.String())
	}

	output.Reset()
	if code := run([]string{"-config", path, "-links-host", "proxy.example.com"}, &output, &output); code != 0 {
		t.Fatalf("links exit code %d: %s", code, output.String())
	}
	if !strings.Contains(output.String(), "secret=dd") || !strings.Contains(output.String(), "secret=ee") {
		t.Fatalf("secure links missing from %q", output.String())
	}
}
