package core

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func makeClientHello(t *testing.T, secret []byte) []byte {
	t.Helper()
	hello := make([]byte, 5+512)
	if _, err := rand.Read(hello); err != nil {
		t.Fatal(err)
	}
	copy(hello[:5], []byte{0x16, 0x03, 0x01, 0x02, 0x00})
	hello[5] = 0x01
	copy(hello[9:11], []byte{0x03, 0x03})
	hello[43] = 32
	for i := 11; i < 43; i++ {
		hello[i] = 0
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(hello)
	computedDigest := mac.Sum(nil)
	xoredDigest := make([]byte, 32)
	binary.LittleEndian.PutUint32(xoredDigest[28:], uint32(time.Now().Unix()))
	for i := 0; i < 32; i++ {
		hello[11+i] = computedDigest[i] ^ xoredDigest[i]
	}
	verifyMessage := append([]byte(nil), hello...)
	for i := 11; i < 43; i++ {
		verifyMessage[i] = 0
	}
	verifyMAC := hmac.New(sha256.New, secret)
	_, _ = verifyMAC.Write(verifyMessage)
	verifyDigest := verifyMAC.Sum(nil)
	for i := 0; i < 28; i++ {
		if hello[11+i]^verifyDigest[i] != 0 {
			t.Fatalf("test generated an invalid ClientHello digest at byte %d", i)
		}
	}
	return hello
}

type testTLSWriter struct{ conn net.Conn }

func (w testTLSWriter) Write(data []byte) (int, error) {
	header := []byte{0x17, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(header[3:], uint16(len(data)))
	if _, err := w.conn.Write(header); err != nil {
		return 0, err
	}
	return w.conn.Write(data)
}

type testTLSReader struct {
	conn net.Conn
	buf  bytes.Buffer
}

func (r *testTLSReader) Read(out []byte) (int, error) {
	for r.buf.Len() == 0 {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r.conn, header); err != nil {
			return 0, err
		}
		if header[1] != 0x03 || header[2] != 0x03 {
			return 0, fmt.Errorf("unexpected TLS version %x", header[1:3])
		}
		body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
		if _, err := io.ReadFull(r.conn, body); err != nil {
			return 0, err
		}
		if header[0] == 0x17 {
			r.buf.Write(body)
		} else if header[0] != 0x14 {
			return 0, fmt.Errorf("unexpected TLS record type %x", header[0])
		}
	}
	return r.buf.Read(out)
}

func readFakeTLSServerHello(conn net.Conn, secret, clientDigest []byte) error {
	readRecord := func() ([]byte, []byte, error) {
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, nil, err
		}
		body := make([]byte, int(binary.BigEndian.Uint16(header[3:])))
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, nil, err
		}
		return header, body, nil
	}

	var raw bytes.Buffer
	for index, expectedType := range []byte{0x16, 0x14, 0x17} {
		header, body, err := readRecord()
		if err != nil {
			return err
		}
		if header[0] != expectedType {
			return fmt.Errorf("record %d has type %x", index, header[0])
		}
		raw.Write(header)
		raw.Write(body)
	}
	response := raw.Bytes()
	if len(response) < 43 {
		return fmt.Errorf("short fake-TLS response")
	}
	receivedDigest := append([]byte(nil), response[11:43]...)
	for i := 11; i < 43; i++ {
		response[i] = 0
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(clientDigest)
	_, _ = mac.Write(response)
	if !hmac.Equal(receivedDigest, mac.Sum(nil)) {
		return fmt.Errorf("bad fake-TLS server HMAC")
	}
	return nil
}

func TestFakeTLSEndToEnd(t *testing.T) {
	secret, _ := hex.DecodeString(strings.Repeat("42", 16))
	payload := []byte{12, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	response := []byte("pong")
	telegram, telegramResult := startFakeTelegram(t, payload, response)
	defer telegram.Close()

	cfg := DefaultConfig()
	cfg.Users = map[string]string{"media": strings.Repeat("42", 16)}
	cfg.EnableSecure = false
	cfg.FakeCertLen = 1024
	proxy, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	proxy.datacenters = map[int]string{1: telegram.Addr().String()}

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

	clientHello := makeClientHello(t, secret)
	if _, err := conn.Write(clientHello); err != nil {
		t.Fatal(err)
	}
	if err := readFakeTLSServerHello(conn, secret, clientHello[11:43]); err != nil {
		t.Fatal(err)
	}

	handshake, decryptor, encryptor := makeClientHandshake(t, secret, 1)
	tlsWriter := testTLSWriter{conn: conn}
	if _, err := tlsWriter.Write(handshake); err != nil {
		t.Fatal(err)
	}
	clientWriter := cipher.StreamWriter{S: encryptor, W: tlsWriter}
	if _, err := clientWriter.Write(payload); err != nil {
		t.Fatal(err)
	}

	tlsReader := &testTLSReader{conn: conn}
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(cipher.StreamReader{S: decryptor, R: tlsReader}, gotResponse); err != nil {
		t.Fatal(err)
	}
	if string(gotResponse) != string(response) {
		t.Fatalf("response = %q, want %q", gotResponse, response)
	}
	if err := <-telegramResult; err != nil {
		t.Fatal(err)
	}

	cancel()
	_ = listener.Close()
	if err := <-serveResult; err != nil {
		t.Fatalf("serve: %v", err)
	}
}
