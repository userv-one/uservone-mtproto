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

func referenceClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	random := func(n int) []byte {
		out := make([]byte, n)
		if _, err := rand.Read(out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	appendUint16 := func(msg []byte, value int) []byte {
		return append(msg, byte(value>>8), byte(value))
	}

	msg := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03}
	msg = append(msg, random(32)...)
	msg = append(msg, 0x20)
	msg = append(msg, random(32)...)
	msg = append(msg,
		0x00, 0x22, 0x4a, 0x4a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9,
		0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x01, 0x91,
		0xda, 0xda, 0x00, 0x00, 0x00, 0x00)
	msg = appendUint16(msg, len(serverName)+5)
	msg = appendUint16(msg, len(serverName)+3)
	msg = append(msg, 0x00)
	msg = appendUint16(msg, len(serverName))
	msg = append(msg, serverName...)
	msg = append(msg,
		0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0xaa, 0xaa, 0x00, 0x1d, 0x00,
		0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02,
		0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06,
		0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x33, 0x00, 0x2b, 0x00, 0x29, 0xaa, 0xaa, 0x00, 0x01, 0x00, 0x00,
		0x1d, 0x00, 0x20)
	msg = append(msg, random(32)...)
	msg = append(msg,
		0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x0b, 0x0a, 0xba, 0xba, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03,
		0x01, 0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x02, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x15)
	msg = appendUint16(msg, 517-len(msg)-2)
	msg = append(msg, make([]byte, 517-len(msg))...)
	return msg
}

func TestClientHelloMatchesReferenceShape(t *testing.T) {
	hello := referenceClientHello(t, "www.google.com")
	if len(hello) != 517 {
		t.Fatalf("ClientHello length = %d, want 517", len(hello))
	}
	if got := binary.BigEndian.Uint16(hello[3:5]); got != 512 {
		t.Fatalf("TLS record payload length = %d, want 512", got)
	}
	if hello[5] != 0x01 || hello[43] != 32 {
		t.Fatalf("unexpected ClientHello structure")
	}
	if !bytes.Contains(hello, []byte("www.google.com")) {
		t.Fatal("ClientHello does not contain its TLS SNI")
	}
}

func makeClientHello(t *testing.T, secret []byte) []byte {
	t.Helper()
	hello := referenceClientHello(t, "www.google.com")
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
