package core

import "testing"

func FuzzClientHandshakeDoesNotPanic(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Add([]byte{0x01})
	f.Add(make([]byte, 63))
	f.Add(make([]byte, 65))
	proxy, err := New(testConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = proxy.decodeClientHandshake(data, true)
	})
}

func FuzzFakeTLSHelloDoesNotPanic(f *testing.F) {
	f.Add(make([]byte, 517))
	f.Add([]byte{0x16, 0x03, 0x01})
	f.Add(make([]byte, 517))
	proxy, err := New(testConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = proxy.handleFakeTLS(&captureConn{}, data)
	})
}
