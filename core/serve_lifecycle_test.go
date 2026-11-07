package core

import (
	"context"
	"crypto/cipher"
	"encoding/hex"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type closeTrackingListener struct {
	net.Listener
	closeCalls chan struct{}
}

func (l *closeTrackingListener) Close() error {
	err := l.Listener.Close()
	l.closeCalls <- struct{}{}
	return err
}

func TestServeStopsContextWatcherWhenListenerCloses(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &closeTrackingListener{
		Listener:   baseListener,
		closeCalls: make(chan struct{}, 2),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveResult := make(chan error, 1)
	go func() { serveResult <- (&Proxy{}).Serve(ctx, listener) }()

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	<-listener.closeCalls
	select {
	case err := <-serveResult:
		if err != nil {
			t.Fatalf("Serve returned an error after external listener close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after external listener close")
	}

	cancel()
	select {
	case <-listener.closeCalls:
		t.Fatal("context watcher closed the listener after Serve returned")
	case <-time.After(200 * time.Millisecond):
	}
}

type channelListener struct {
	connections chan net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
}

func newChannelListener() *channelListener {
	return &channelListener{
		connections: make(chan net.Conn),
		closed:      make(chan struct{}),
	}
}

func (l *channelListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *channelListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *channelListener) Addr() net.Addr { return nil }

func waitForActiveRelay(t *testing.T, active <-chan struct{}) {
	t.Helper()
	select {
	case <-active:
	case <-time.After(time.Second):
		t.Fatal("relay did not become active")
	}
}

func checkServeStopped(t *testing.T, serveResult <-chan error) {
	t.Helper()
	select {
	case err := <-serveResult:
		if err != nil {
			t.Errorf("Serve returned an error after cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Serve did not return after cancellation")
	}
}

func checkConnectionClosed(t *testing.T, conn net.Conn, name string, upstreamResult <-chan error) {
	t.Helper()
	if upstreamResult != nil {
		select {
		case err := <-upstreamResult:
			if err == nil {
				t.Errorf("%s read succeeded instead of observing closure", name)
			}
		case <-time.After(time.Second):
			t.Errorf("%s remained blocked after cancellation", name)
		}
		return
	}

	readResult := make(chan error, 1)
	go func() {
		var oneByte [1]byte
		_, err := conn.Read(oneByte[:])
		readResult <- err
	}()
	select {
	case err := <-readResult:
		if err == nil {
			t.Errorf("%s read succeeded instead of observing closure", name)
		}
	case <-time.After(time.Second):
		t.Errorf("%s remained blocked after cancellation", name)
	}
}

func TestServeCancellationClosesActiveRawProxyConnections(t *testing.T) {
	secret, _ := hex.DecodeString(strings.Repeat("42", 16))
	cfg := DefaultConfig()
	cfg.Users = map[string]string{"media": strings.Repeat("42", 16)}
	proxy, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	proxy.datacenters = map[int]string{1: "upstream"}

	client, accepted := net.Pipe()
	defer client.Close()
	upstream, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()
	proxy.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return upstream, nil
	}

	payload := []byte("active raw proxy payload")
	active := make(chan struct{})
	upstreamResult := make(chan error, 1)
	go func() {
		handshake := make([]byte, handshakeLen)
		if _, err := io.ReadFull(upstreamPeer, handshake); err != nil {
			upstreamResult <- err
			return
		}
		incoming := testCTR(handshake[8:40], handshake[40:56])
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(cipher.StreamReader{S: incoming, R: upstreamPeer}, received); err != nil {
			upstreamResult <- err
			return
		}
		close(active)
		var oneByte [1]byte
		_, err := upstreamPeer.Read(oneByte[:])
		upstreamResult <- err
	}()

	listener := newChannelListener()
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- proxy.Serve(ctx, listener) }()
	listener.connections <- accepted

	handshake, _, encryptor := makeClientHandshake(t, secret, 1)
	if _, err := client.Write(handshake); err != nil {
		t.Fatal(err)
	}
	if _, err := (cipher.StreamWriter{S: encryptor, W: client}).Write(payload); err != nil {
		t.Fatal(err)
	}
	waitForActiveRelay(t, active)

	cancel()
	checkServeStopped(t, serveResult)
	checkConnectionClosed(t, client, "raw proxy client", nil)
	checkConnectionClosed(t, upstreamPeer, "raw proxy upstream", upstreamResult)
}

func TestServeCancellationClosesActiveMaskingConnections(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Users = map[string]string{"media": strings.Repeat("42", 16)}
	proxy, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	client, accepted := net.Pipe()
	defer client.Close()
	upstream, upstreamPeer := net.Pipe()
	defer upstreamPeer.Close()
	proxy.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return upstream, nil
	}

	captured := make([]byte, handshakeLen)
	active := make(chan struct{})
	upstreamResult := make(chan error, 1)
	go func() {
		received := make([]byte, len(captured))
		if _, err := io.ReadFull(upstreamPeer, received); err != nil {
			upstreamResult <- err
			return
		}
		close(active)
		var oneByte [1]byte
		_, err := upstreamPeer.Read(oneByte[:])
		upstreamResult <- err
	}()

	listener := newChannelListener()
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveResult := make(chan error, 1)
	go func() { serveResult <- proxy.Serve(ctx, listener) }()
	listener.connections <- accepted

	if _, err := client.Write(captured); err != nil {
		t.Fatal(err)
	}
	waitForActiveRelay(t, active)

	cancel()
	checkServeStopped(t, serveResult)
	checkConnectionClosed(t, client, "masking client", nil)
	checkConnectionClosed(t, upstreamPeer, "masking upstream", upstreamResult)
}
