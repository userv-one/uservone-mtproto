package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/userv-one/uservone-mtproto/core"
)

const testSecret = "42424242424242424242424242424242"

func TestRunGeneratesPrivateCoreCompatibleConfig(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "entitled.json")
	output := filepath.Join(dir, "config.json")
	contents := `[{"uuid":"123e4567-e89b-12d3-a456-426614174000","secret":"` + testSecret + `","entitled":true}]`
	if err := os.WriteFile(input, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-input", input,
		"-output", output,
		"-listen", "127.0.0.1:8443",
		"-tls-domain", "proxy.example.com",
		"-mask-host", "mask.example.com",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("generator must not print credentials: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode = %o, want 600", info.Mode().Perm())
	}
	cfg, err := core.LoadConfig(output)
	if err != nil {
		t.Fatalf("generated output is not accepted by core.LoadConfig: %v", err)
	}
	if cfg.Users["123e4567-e89b-12d3-a456-426614174000"] != testSecret || cfg.Listen != "127.0.0.1:8443" {
		t.Fatalf("unexpected generated config: %+v", cfg)
	}
	if cfg.TLSDomain != "proxy.example.com" || cfg.MaskHost != "mask.example.com" || !cfg.EnableSecure || !cfg.EnableTLS || !cfg.Mask {
		t.Fatalf("transport settings not preserved: %+v", cfg)
	}
}

func TestRunFailureDoesNotLeakSecretOrReplaceOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "entitled.json")
	output := filepath.Join(dir, "config.json")
	const invalidSecret = "super-secret-input-value"
	contents := `[{"uuid":"123e4567-e89b-12d3-a456-426614174000","secret":"` + invalidSecret + `","entitled":true}]`
	if err := os.WriteFile(input, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	const original = "existing configuration must survive"
	if err := os.WriteFile(output, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-input", input, "-output", output}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("invalid credential must fail")
	}
	if bytes.Contains(stdout.Bytes(), []byte(invalidSecret)) || bytes.Contains(stderr.Bytes(), []byte(invalidSecret)) {
		t.Fatalf("secret leaked: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != original {
		t.Fatalf("output changed after failure: %q", after)
	}
}
