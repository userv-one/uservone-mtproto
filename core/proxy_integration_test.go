package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
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

var testSecureTag = []byte{0xdd, 0xdd, 0xdd, 0xdd}

func testCTR(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCTR(block, iv)
}

func reverseBytes(in []byte) []byte {
	out := append([]byte(nil), in...)
	for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
		out[left], out[right] = out[right], out[left]
	}
	return out
}

func makeClientHandshake(t *testing.T, secret []byte, dc int) (handshake []byte, decryptor, encryptor cipher.Stream) {
	t.Helper()
	handshake = make([]byte, 64)
	if _, err := rand.Read(handshake); err != nil {
		t.Fatal(err)
	}
	copy(handshake[56:60], testSecureTag)
	binary.LittleEndian.PutUint16(handshake[60:62], uint16(int16(dc)))

	encKeyAndIV := append([]byte(nil), handshake[8:56]...)
	encKeyInput := append(append([]byte(nil), encKeyAndIV[:32]...), secret...)
	encKey := sha256.Sum256(encKeyInput)
	encryptor = testCTR(encKey[:], encKeyAndIV[32:])

	decKeyAndIV := reverseBytes(encKeyAndIV)
	decKeyInput := append(append([]byte(nil), decKeyAndIV[:32]...), secret...)
	decKey := sha256.Sum256(decKeyInput)
	decryptor = testCTR(decKey[:], decKeyAndIV[32:])

	encrypted := make([]byte, 64)
	encryptor.XORKeyStream(encrypted, handshake)
	copy(handshake[56:], encrypted[56:])
	return handshake, decryptor, encryptor
}

func startFakeTelegram(t *testing.T, expectedPayload, response []byte) (net.Listener, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		defer close(result)
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		handshake := make([]byte, 64)
		if _, err := io.ReadFull(conn, handshake); err != nil {
			result <- fmt.Errorf("read upstream handshake: %w", err)
			return
		}
		incoming := testCTR(handshake[8:40], handshake[40:56])
		decrypted := make([]byte, 64)
		incoming.XORKeyStream(decrypted, handshake)
		if string(decrypted[56:60]) != string(testSecureTag) {
			result <- fmt.Errorf("upstream protocol tag = %x", decrypted[56:60])
			return
		}

		payload := make([]byte, len(expectedPayload))
		if _, err := io.ReadFull(cipher.StreamReader{S: incoming, R: conn}, payload); err != nil {
			result <- fmt.Errorf("read payload: %w", err)
			return
		}
		if string(payload) != string(expectedPayload) {
			result <- fmt.Errorf("payload changed: got %x, want %x", payload, expectedPayload)
			return
		}

		outgoingKeyAndIV := reverseBytes(handshake[8:56])
		outgoing := testCTR(outgoingKeyAndIV[:32], outgoingKeyAndIV[32:])
		writer := cipher.StreamWriter{S: outgoing, W: conn}
		if _, err := writer.Write(response); err != nil {
			result <- fmt.Errorf("write response: %w", err)
			return
		}
		result <- nil
	}()
	return listener, result
}

func TestSecureRandomPaddingEndToEnd(t *testing.T) {
	secret, _ := hex.DecodeString(strings.Repeat("42", 16))
	payload := []byte{12, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	response := []byte("pong")
	telegram, telegramResult := startFakeTelegram(t, payload, response)
	defer telegram.Close()

	cfg := DefaultConfig()
	cfg.Users = map[string]string{"media": strings.Repeat("42", 16)}
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

	handshake, decryptor, encryptor := makeClientHandshake(t, secret, 1)
	probeKeyInput := append(append([]byte(nil), handshake[8:40]...), secret...)
	probeKey := sha256.Sum256(probeKeyInput)
	probe := testCTR(probeKey[:], handshake[40:56])
	probeDecrypted := make([]byte, 64)
	probe.XORKeyStream(probeDecrypted, handshake)
	if string(probeDecrypted[56:60]) != string(testSecureTag) {
		t.Fatalf("test generated an invalid handshake: %x", probeDecrypted[56:60])
	}
	if _, err := conn.Write(handshake); err != nil {
		t.Fatal(err)
	}
	clientWriter := cipher.StreamWriter{S: encryptor, W: conn}
	if _, err := clientWriter.Write(payload); err != nil {
		t.Fatal(err)
	}

	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(cipher.StreamReader{S: decryptor, R: conn}, gotResponse); err != nil {
		select {
		case telegramErr := <-telegramResult:
			t.Fatalf("read response: %v; Telegram emulator: %v", err, telegramErr)
		default:
			t.Fatal(err)
		}
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
