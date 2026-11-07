package core

import (
	"net"
	"testing"
	"time"
)

func TestConnectionLimiter(t *testing.T) {
	t.Run("per IP", func(t *testing.T) {
		tracker := &connectionTracker{}
		first, peer1 := net.Pipe()
		defer first.Close()
		defer peer1.Close()
		second, peer2 := net.Pipe()
		defer second.Close()
		defer peer2.Close()
		if !tracker.addClient(first, "192.0.2.1", 10, 1) {
			t.Fatal("first connection was rejected")
		}
		if tracker.addClient(second, "192.0.2.1", 10, 1) {
			t.Fatal("connection above the per-IP limit was accepted")
		}
		tracker.removeClient(first, "192.0.2.1")
		if !tracker.addClient(second, "192.0.2.1", 10, 1) {
			t.Fatal("connection was rejected after a slot was released")
		}
	})

	t.Run("global", func(t *testing.T) {
		tracker := &connectionTracker{}
		first, peer1 := net.Pipe()
		defer first.Close()
		defer peer1.Close()
		second, peer2 := net.Pipe()
		defer second.Close()
		defer peer2.Close()
		if !tracker.addClient(first, "192.0.2.1", 1, 0) {
			t.Fatal("first connection was rejected")
		}
		if tracker.addClient(second, "192.0.2.2", 1, 0) {
			t.Fatal("connection above the global limit was accepted")
		}
	})
}

func TestDeadlineReaderRefreshesReadDeadline(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	reader := &deadlineReader{conn: conn, reader: conn, timeout: 40 * time.Millisecond}
	start := time.Now()
	_, err := reader.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("read without traffic did not time out")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("read timeout took %s", elapsed)
	}
}
