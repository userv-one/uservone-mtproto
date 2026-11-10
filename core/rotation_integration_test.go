package core

import (
	"context"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRotationKeepsActiveConnection(t *testing.T) {
	oldSecret := strings.Repeat("42", 16)
	newSecret := strings.Repeat("24", 16)
	payload := []byte{12, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	response := []byte("still-connected")
	telegram, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer telegram.Close()
	upstreamReady := make(chan struct{})
	upstreamResult := make(chan error, 1)
	go func() {
		conn, err := telegram.Accept()
		if err != nil {
			upstreamResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		handshake := make([]byte, 64)
		if _, err := io.ReadFull(conn, handshake); err != nil {
			upstreamResult <- err
			return
		}
		incoming := testCTR(handshake[8:40], handshake[40:56])
		decrypted := make([]byte, 64)
		incoming.XORKeyStream(decrypted, handshake)
		if string(decrypted[56:60]) != string(testSecureTag) {
			upstreamResult <- fmt.Errorf("bad secure tag")
			return
		}
		close(upstreamReady)
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(cipher.StreamReader{S: incoming, R: conn}, received); err != nil {
			upstreamResult <- err
			return
		}
		if string(received) != string(payload) {
			upstreamResult <- fmt.Errorf("payload changed during rotation")
			return
		}
		outgoingKeyAndIV := reverseBytes(handshake[8:56])
		writer := cipher.StreamWriter{S: testCTR(outgoingKeyAndIV[:32], outgoingKeyAndIV[32:]), W: conn}
		if _, err := writer.Write(response); err != nil {
			upstreamResult <- err
			return
		}
		upstreamResult <- nil
	}()

	cfg := testConfig()
	cfg.Users = map[string]string{"old": oldSecret}
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
	secret, _ := hex.DecodeString(oldSecret)
	handshake, decryptor, encryptor := makeClientHandshake(t, secret, 1)
	if _, err := conn.Write(handshake); err != nil {
		t.Fatal(err)
	}
	select {
	case <-upstreamReady:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream handshake did not complete")
	}
	if err := proxy.ReloadUsers(map[string]string{"new": newSecret}, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	writer := cipher.StreamWriter{S: encryptor, W: conn}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(cipher.StreamReader{S: decryptor, R: conn}, gotResponse); err != nil {
		t.Fatal(err)
	}
	if string(gotResponse) != string(response) {
		t.Fatalf("response = %q", gotResponse)
	}
	if err := <-upstreamResult; err != nil {
		t.Fatal(err)
	}
	cancel()
	_ = listener.Close()
	if err := <-serveResult; err != nil {
		t.Fatal(err)
	}
}
