package core

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClientHandshakeReplayRejected(t *testing.T) {
	secret, _ := hex.DecodeString(strings.Repeat("42", 16))
	proxy, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	handshake, _, _ := makeClientHandshake(t, secret, 1)

	if _, err := proxy.decodeClientHandshake(handshake, true); err != nil {
		t.Fatalf("first handshake must be accepted: %v", err)
	}
	if _, err := proxy.decodeClientHandshake(handshake, true); err == nil {
		t.Fatal("replayed MTProto handshake must be rejected")
	}
}

func TestFakeTLSClientHelloReplayRejected(t *testing.T) {
	secret, _ := hex.DecodeString(strings.Repeat("42", 16))
	proxy, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	hello := makeClientHello(t, secret)

	if _, _, err := proxy.handleFakeTLS(&captureConn{}, hello); err != nil {
		t.Fatalf("first ClientHello must be accepted: %v", err)
	}
	if _, _, err := proxy.handleFakeTLS(&captureConn{}, hello); err == nil {
		t.Fatal("replayed fake-TLS ClientHello must be rejected")
	}
}

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.Users = map[string]string{"media": strings.Repeat("42", 16)}
	return cfg
}

type captureConn struct {
	bytes.Buffer
}

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }
