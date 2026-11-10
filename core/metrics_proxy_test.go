package core

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyMetricsTrackHandshakeErrors(t *testing.T) {
	cfg := testConfig()
	cfg.Mask = false
	proxy, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client, accepted := net.Pipe()
	done := make(chan struct{})
	go func() {
		proxy.handleConn(context.Background(), accepted, &connectionTracker{})
		close(done)
	}()
	if _, err := client.Write(make([]byte, handshakeLen)); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("invalid handshake did not finish")
	}
	if got := proxy.metrics.snapshot().handshakeErrors["invalid"]; got != 1 {
		t.Fatalf("invalid handshake errors = %d, want 1", got)
	}
}

func TestProxyMetricsTrackDCReachability(t *testing.T) {
	proxy, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	proxy.datacenters = map[int]string{1: "upstream"}
	conn, peer := net.Pipe()
	defer peer.Close()
	proxy.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	}
	go func() { _, _ = io.ReadFull(peer, make([]byte, handshakeLen)) }()
	upstream, _, _, err := proxy.openTelegram(context.Background(), 1, &connectionTracker{})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	status, found := proxy.metrics.DCStatus(1)
	if !found || !status.Reachable || status.Successes != 1 || status.Failures != 0 {
		t.Fatalf("unexpected DC status: %+v, found=%t", status, found)
	}
}

func TestProxyMetricsTrackAcceptedConnection(t *testing.T) {
	proxy, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	listener := newChannelListener()
	client, accepted := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = proxy.Serve(ctx, listener) }()
	listener.connections <- accepted
	deadline := time.Now().Add(time.Second)
	for {
		current, _ := proxy.metrics.ClientCounts()
		if current == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("accepted connection was not counted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	deadline = time.Now().Add(time.Second)
	for {
		current, _ := proxy.metrics.ClientCounts()
		if current == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("closed connection was not removed from metrics")
		}
		time.Sleep(time.Millisecond)
	}
}
