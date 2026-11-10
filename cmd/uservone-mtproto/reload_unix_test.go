//go:build !windows

package main

import (
	"bytes"
	"context"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/userv-one/uservone-mtproto/core"
)

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func TestSIGHUPReloadsSecretsWithoutLoggingThem(t *testing.T) {
	oldSecret := strings.Repeat("42", 16)
	newSecret := strings.Repeat("24", 16)
	path := filepath.Join(t.TempDir(), "proxy.json")
	writeConfig := func(secret string) {
		contents := `{"listen":"127.0.0.1:8443","users":{"media":"` + secret + `"},"tls_domain":"example.org","match_mask_host":false}`
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(oldSecret)
	cfg, err := core.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logs synchronizedBuffer
	watchReload(ctx, path, proxy, log.New(&logs, "", 0))
	writeConfig(newSecret)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		links, err := proxy.Links("proxy.example.com")
		if err != nil {
			t.Fatal(err)
		}
		parsed, _ := url.Parse(links[0].URL)
		if parsed.Query().Get("secret") == "dd"+newSecret {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP did not activate the new secret")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for !strings.Contains(logs.String(), "secrets reloaded\n") {
		if time.Now().After(deadline) {
			t.Fatal("SIGHUP reload was not logged")
		}
		time.Sleep(10 * time.Millisecond)
	}
	logOutput := logs.String()
	if strings.Contains(logOutput, oldSecret) || strings.Contains(logOutput, newSecret) {
		t.Fatalf("reload log leaked a secret: %q", logOutput)
	}
}
