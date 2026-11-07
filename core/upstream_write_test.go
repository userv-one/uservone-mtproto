package core

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type chunkWriteConn struct {
	net.Conn
	max int
}

func (c *chunkWriteConn) Write(data []byte) (int, error) {
	if len(data) > c.max {
		data = data[:c.max]
	}
	return c.Conn.Write(data)
}

func TestOpenTelegramWritesFullHandshakeWithShortWrites(t *testing.T) {
	proxy, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	proxy.datacenters = map[int]string{1: "upstream"}
	conn, peer := net.Pipe()
	defer peer.Close()
	proxy.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return &chunkWriteConn{Conn: conn, max: 7}, nil
	}
	_ = peer.SetDeadline(time.Now().Add(100 * time.Millisecond))
	readResult := make(chan error, 1)
	go func() {
		handshake := make([]byte, handshakeLen)
		_, err := io.ReadFull(peer, handshake)
		readResult <- err
	}()

	upstream, _, _, err := proxy.openTelegram(context.Background(), 1, &connectionTracker{})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	if err := <-readResult; err != nil {
		t.Fatalf("upstream received a truncated handshake: %v", err)
	}
}
