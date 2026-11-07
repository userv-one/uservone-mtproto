package core

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// RefreshMaskProfile measures the certificate record returned by mask_host.
func (p *Proxy) RefreshMaskProfile(ctx context.Context) error {
	if p.config.FakeCertLen != 0 {
		return nil
	}
	if p.config.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(p.config.ConnectTimeout)*time.Second)
		defer cancel()
	}
	address := net.JoinHostPort(p.config.MaskHost, strconv.Itoa(p.config.MaskPort))
	conn, err := p.dialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("connect to mask host: %w", err)
	}
	defer conn.Close()
	if p.config.HandshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(time.Duration(p.config.HandshakeTimeout) * time.Second))
	}
	hello, err := makeMaskClientHello(p.config.TLSDomain)
	if err != nil {
		return err
	}
	if err := writeFull(conn, hello); err != nil {
		return fmt.Errorf("write mask probe: %w", err)
	}

	recordType, _, err := readMaskRecord(conn)
	if err != nil {
		return err
	}
	if recordType != 0x16 {
		return fmt.Errorf("mask host returned record %x, want ServerHello", recordType)
	}
	recordType, _, err = readMaskRecord(conn)
	if err != nil {
		return err
	}
	if recordType != 0x14 {
		return fmt.Errorf("mask host returned record %x, want change-cipher-spec", recordType)
	}
	recordType, certificate, err := readMaskRecord(conn)
	if err != nil {
		return err
	}
	if recordType != 0x17 {
		return fmt.Errorf("mask host returned record %x, want certificate data", recordType)
	}
	if len(certificate) < 1024 {
		recordType, certificate, err = readMaskRecord(conn)
		if err != nil {
			return err
		}
		if recordType != 0x17 {
			return fmt.Errorf("mask host returned record %x, want certificate data", recordType)
		}
	}
	if len(certificate) < 1024 || len(certificate) > 65535 {
		return fmt.Errorf("unsupported mask certificate length %d", len(certificate))
	}
	p.fakeCertLen.Store(int64(len(certificate)))
	return nil
}

func readMaskRecord(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, fmt.Errorf("read mask TLS record: %w", err)
	}
	if header[1] != 0x03 || header[2] != 0x03 {
		return 0, nil, fmt.Errorf("unexpected mask TLS version %x", header[1:3])
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, fmt.Errorf("read mask TLS payload: %w", err)
	}
	return header[0], body, nil
}

func makeMaskClientHello(serverName string) ([]byte, error) {
	random := func(n int) ([]byte, error) {
		out := make([]byte, n)
		_, err := rand.Read(out)
		return out, err
	}
	appendUint16 := func(msg []byte, value int) []byte {
		return append(msg, byte(value>>8), byte(value))
	}

	msg := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03}
	random32, err := random(32)
	if err != nil {
		return nil, err
	}
	msg = append(msg, random32...)
	msg = append(msg, 0x20)
	random32, err = random(32)
	if err != nil {
		return nil, err
	}
	msg = append(msg, random32...)
	msg = append(msg,
		0x00, 0x22, 0x4a, 0x4a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9,
		0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a, 0x01, 0x00, 0x01, 0x91,
		0xda, 0xda, 0x00, 0x00, 0x00, 0x00)
	msg = appendUint16(msg, len(serverName)+5)
	msg = appendUint16(msg, len(serverName)+3)
	msg = append(msg, 0x00)
	msg = appendUint16(msg, len(serverName))
	msg = append(msg, serverName...)
	msg = append(msg,
		0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0xaa, 0xaa, 0x00, 0x1d, 0x00,
		0x17, 0x00, 0x18, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02,
		0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06,
		0x06, 0x01, 0x02, 0x01, 0x00, 0x12, 0x00, 0x00, 0x00, 0x33, 0x00, 0x2b, 0x00, 0x29, 0xaa, 0xaa, 0x00, 0x01, 0x00, 0x00,
		0x1d, 0x00, 0x20)
	publicKey, err := x25519PublicKey()
	if err != nil {
		return nil, err
	}
	msg = append(msg, publicKey...)
	msg = append(msg,
		0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x2b, 0x00, 0x0b, 0x0a, 0xba, 0xba, 0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03,
		0x01, 0x00, 0x1b, 0x00, 0x03, 0x02, 0x00, 0x02, 0x3a, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x15)
	paddingLen := 517 - len(msg) - 2
	if paddingLen < 0 {
		paddingLen = 0
	}
	helloLen := len(msg) + 2 + paddingLen
	binary.BigEndian.PutUint16(msg[3:5], uint16(helloLen-5))
	msg[6] = byte((helloLen - 9) >> 16)
	msg[7] = byte((helloLen - 9) >> 8)
	msg[8] = byte(helloLen - 9)
	binary.BigEndian.PutUint16(msg[114:116], uint16(helloLen-116))
	msg = appendUint16(msg, paddingLen)
	msg = append(msg, make([]byte, paddingLen)...)
	return msg, nil
}
