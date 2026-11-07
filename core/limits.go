package core

import (
	"io"
	"net"
	"time"
)

type deadlineReader struct {
	conn    net.Conn
	reader  io.Reader
	timeout time.Duration
}

func (r *deadlineReader) Read(data []byte) (int, error) {
	if r.timeout > 0 {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.timeout))
	}
	return r.reader.Read(data)
}

func withReadTimeout(conn net.Conn, reader io.Reader, seconds int) io.Reader {
	if seconds <= 0 {
		return reader
	}
	return &deadlineReader{conn: conn, reader: reader, timeout: time.Duration(seconds) * time.Second}
}

func remoteIP(conn net.Conn) string {
	address := conn.RemoteAddr().String()
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
