package core

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

const (
	tlsDigestPos     = 11
	tlsDigestLen     = 32
	tlsSessionLenPos = tlsDigestPos + tlsDigestLen
	tlsSessionPos    = tlsSessionLenPos + 1
)

type fakeTLSReader struct {
	conn net.Conn
	buf  bytes.Buffer
}

func (r *fakeTLSReader) Read(out []byte) (int, error) {
	for r.buf.Len() == 0 {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r.conn, header); err != nil {
			return 0, err
		}
		if header[1] != 0x03 || header[2] != 0x03 {
			return 0, fmt.Errorf("unexpected fake-TLS record version %x", header[1:3])
		}
		body := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
		if _, err := io.ReadFull(r.conn, body); err != nil {
			return 0, err
		}
		switch header[0] {
		case 0x14:
			continue
		case 0x17:
			r.buf.Write(body)
		default:
			return 0, fmt.Errorf("unexpected fake-TLS record type %x", header[0])
		}
	}
	return r.buf.Read(out)
}

type fakeTLSWriter struct{ conn net.Conn }

func (w *fakeTLSWriter) Write(data []byte) (int, error) {
	const maxChunk = 16384 + 24
	written := 0
	for len(data) > 0 {
		chunk := len(data)
		if chunk > maxChunk {
			chunk = maxChunk
		}
		header := []byte{0x17, 0x03, 0x03, 0, 0}
		binary.BigEndian.PutUint16(header[3:], uint16(chunk))
		if err := writeFull(w.conn, header); err != nil {
			return written, err
		}
		if err := writeFull(w.conn, data[:chunk]); err != nil {
			return written, err
		}
		written += chunk
		data = data[chunk:]
	}
	return written, nil
}

func (p *Proxy) handleFakeTLS(client net.Conn, hello []byte) (*fakeTLSReader, *fakeTLSWriter, error) {
	if !p.config.EnableTLS {
		return nil, nil, errors.New("fake-TLS transport is disabled")
	}
	if len(hello) < 5+512 || len(hello) <= tlsSessionPos {
		return nil, nil, errors.New("short fake-TLS ClientHello")
	}
	sessionLen := int(hello[tlsSessionLenPos])
	if tlsSessionPos+sessionLen > len(hello) {
		return nil, nil, errors.New("invalid fake-TLS session ID")
	}

	clientDigest := hello[tlsDigestPos : tlsDigestPos+tlsDigestLen]
	for _, candidate := range p.users {
		message := append([]byte(nil), hello...)
		for i := tlsDigestPos; i < tlsDigestPos+tlsDigestLen; i++ {
			message[i] = 0
		}
		mac := hmac.New(sha256.New, candidate.secret)
		_, _ = mac.Write(message)
		computed := mac.Sum(nil)
		xored := make([]byte, tlsDigestLen)
		for i := range xored {
			xored[i] = clientDigest[i] ^ computed[i]
		}
		if subtle.ConstantTimeCompare(xored[:28], make([]byte, 28)) != 1 {
			continue
		}

		timestamp := int64(binary.LittleEndian.Uint32(xored[28:]))
		skew := time.Since(time.Unix(timestamp, 0))
		clientTimeIsSmall := timestamp < 60*60*24*1000
		if !p.config.IgnoreTimeSkew && !clientTimeIsSmall &&
			(skew <= -20*time.Minute || skew >= 10*time.Minute) {
			continue
		}

		if p.replay.seenOrAdd("tls:" + string(clientDigest[:16])) {
			return nil, nil, errors.New("replayed fake-TLS ClientHello")
		}
		response, err := p.makeFakeTLSServerHello(candidate.secret, clientDigest, hello[tlsSessionPos:tlsSessionPos+sessionLen])
		if err != nil {
			return nil, nil, err
		}
		if err := writeFull(client, response); err != nil {
			return nil, nil, err
		}
		return &fakeTLSReader{conn: client}, &fakeTLSWriter{conn: client}, nil
	}
	return nil, nil, errors.New("no matching fake-TLS user")
}

func (p *Proxy) makeFakeTLSServerHello(secret, clientDigest, sessionID []byte) ([]byte, error) {
	serverHello := make([]byte, 0, 128)
	serverHello = append(serverHello, 0x03, 0x03)
	serverHello = append(serverHello, make([]byte, 32)...)
	serverHello = append(serverHello, byte(len(sessionID)))
	serverHello = append(serverHello, sessionID...)
	serverHello = append(serverHello, 0x13, 0x01, 0x00)
	serverHello = append(serverHello, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20)
	publicKey, err := x25519PublicKey()
	if err != nil {
		return nil, err
	}
	serverHello = append(serverHello, publicKey...)
	serverHello = append(serverHello, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	response := []byte{0x16, 0x03, 0x03, 0, 0}
	binary.BigEndian.PutUint16(response[3:], uint16(len(serverHello)+4))
	response = append(response, 0x02, 0, 0, 0)
	handshakeLenPos := len(response) - 3
	response = append(response, serverHello...)
	response[handshakeLenPos] = byte(len(serverHello) >> 16)
	response[handshakeLenPos+1] = byte(len(serverHello) >> 8)
	response[handshakeLenPos+2] = byte(len(serverHello))
	response = append(response, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
	response = append(response, 0x17, 0x03, 0x03, 0, 0)

	certLen := int(p.fakeCertLen.Load())
	certificate := make([]byte, certLen)
	if _, err := rand.Read(certificate); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(response[len(response)-2:], uint16(certLen))
	response = append(response, certificate...)

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(clientDigest)
	_, _ = mac.Write(response)
	copy(response[tlsDigestPos:tlsDigestPos+tlsDigestLen], mac.Sum(nil))
	return response, nil
}

func x25519PublicKey() ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	for left, right := 0, len(random)-1; left < right; left, right = left+1, right-1 {
		random[left], random[right] = random[right], random[left]
	}
	modulus := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	n := new(big.Int).SetBytes(random)
	n.Mod(n, modulus)
	n.Exp(n, big.NewInt(2), modulus)
	encoded := n.FillBytes(make([]byte, 32))
	for left, right := 0, len(encoded)-1; left < right; left, right = left+1, right-1 {
		encoded[left], encoded[right] = encoded[right], encoded[left]
	}
	return encoded, nil
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
