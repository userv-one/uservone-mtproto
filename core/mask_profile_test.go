package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestRefreshMaskProfileMatchesCertificateRecord(t *testing.T) {
	const certificateLen = 2345
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	probeResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			probeResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		hello := make([]byte, 517)
		if _, err := io.ReadFull(conn, hello); err != nil {
			probeResult <- err
			return
		}
		if hello[0] != 0x16 || binary.BigEndian.Uint16(hello[3:5]) != 512 {
			probeResult <- fmt.Errorf("invalid mask probe ClientHello")
			return
		}
		writeRecord := func(recordType byte, body []byte) error {
			header := []byte{recordType, 0x03, 0x03, 0, 0}
			binary.BigEndian.PutUint16(header[3:], uint16(len(body)))
			if _, err := conn.Write(header); err != nil {
				return err
			}
			_, err := conn.Write(body)
			return err
		}
		if err := writeRecord(0x16, make([]byte, 80)); err != nil {
			probeResult <- err
			return
		}
		if err := writeRecord(0x14, []byte{0x01}); err != nil {
			probeResult <- err
			return
		}
		if err := writeRecord(0x17, make([]byte, certificateLen)); err != nil {
			probeResult <- err
			return
		}
		probeResult <- nil
	}()

	cfg := testConfig()
	cfg.MaskHost = "127.0.0.1"
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	_, _ = fmt.Sscanf(portText, "%d", &cfg.MaskPort)
	proxy, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := proxy.RefreshMaskProfile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := int(proxy.fakeCertLen.Load()); got != certificateLen {
		t.Fatalf("fake certificate length = %d, want %d", got, certificateLen)
	}
	if err := <-probeResult; err != nil {
		t.Fatal(err)
	}
}

func TestMakeMaskClientHelloSNIBoundaries(t *testing.T) {
	tests := []struct {
		name          string
		serverNameLen int
		wantHelloLen  int
	}{
		{name: "216 bytes", serverNameLen: 216, wantHelloLen: 517},
		{name: "217 bytes", serverNameLen: 217, wantHelloLen: 518},
		{name: "253 bytes", serverNameLen: 253, wantHelloLen: 554},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hello, err := makeMaskClientHello(strings.Repeat("a", tt.serverNameLen))
			if err != nil {
				t.Fatal(err)
			}
			if len(hello) != tt.wantHelloLen {
				t.Fatalf("ClientHello length = %d, want %d", len(hello), tt.wantHelloLen)
			}
			if got := int(binary.BigEndian.Uint16(hello[3:5])); got != len(hello)-5 {
				t.Errorf("TLS record payload length = %d, want %d", got, len(hello)-5)
			}
			if got := int(hello[6])<<16 | int(hello[7])<<8 | int(hello[8]); got != len(hello)-9 {
				t.Errorf("handshake payload length = %d, want %d", got, len(hello)-9)
			}
			if got := int(binary.BigEndian.Uint16(hello[114:116])); got != len(hello)-116 {
				t.Errorf("extensions length = %d, want %d", got, len(hello)-116)
			}
		})
	}
}
