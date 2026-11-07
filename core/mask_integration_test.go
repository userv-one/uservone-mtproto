package core

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUnknownTLSClientIsMasked(t *testing.T) {
	secret, _ := hex.DecodeString(strings.Repeat("42", 16))
	probe := makeClientHello(t, secret)
	probe[100] ^= 0xff // invalidate the fake-TLS HMAC
	maskResponse := []byte("real-HTTPS-host-response")

	maskListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer maskListener.Close()
	maskResult := make(chan error, 1)
	go func() {
		conn, err := maskListener.Accept()
		if err != nil {
			maskResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		received := make([]byte, len(probe))
		if _, err := io.ReadFull(conn, received); err != nil {
			maskResult <- err
			return
		}
		if string(received) != string(probe) {
			maskResult <- fmt.Errorf("mask host received a modified ClientHello")
			return
		}
		if _, err := conn.Write(maskResponse); err != nil {
			maskResult <- err
			return
		}
		maskResult <- nil
	}()

	cfg := DefaultConfig()
	cfg.Users = map[string]string{"media": strings.Repeat("42", 16)}
	maskHost, maskPortText, _ := net.SplitHostPort(maskListener.Addr().String())
	cfg.MaskHost = maskHost
	cfg.MaskPort, _ = strconv.Atoi(maskPortText)
	proxy, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer listener.Close()
	serveResult := make(chan error, 1)
	go func() { serveResult <- proxy.Serve(ctx, listener) }()

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(probe); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(maskResponse))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != string(maskResponse) {
		t.Fatalf("response = %q, want mask host response %q", response, maskResponse)
	}
	if err := <-maskResult; err != nil {
		t.Fatal(err)
	}

	cancel()
	_ = listener.Close()
	if err := <-serveResult; err != nil {
		t.Fatalf("serve: %v", err)
	}
}
