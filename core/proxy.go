package core

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	handshakeLen = 64
	protoTagPos  = 56
	dcIndexPos   = 60
)

var secureProtocolTag = []byte{0xdd, 0xdd, 0xdd, 0xdd}

type user struct {
	name   string
	secret []byte
}

type clientSession struct {
	user      string
	dc        int
	decryptor cipher.Stream
	encryptor cipher.Stream
}

// Proxy serves MTProto connections.
type Proxy struct {
	config      Config
	users       []user
	datacenters map[int]string
	dialContext func(context.Context, string, string) (net.Conn, error)
	fakeCertLen atomic.Int64
	replay      *replayCache
}

// New validates cfg and returns a Proxy.
func New(cfg Config) (*Proxy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	fakeCertLen := cfg.FakeCertLen
	if fakeCertLen == 0 {
		var random [2]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		fakeCertLen = 1024 + int(binary.BigEndian.Uint16(random[:]))%(4096-1024)
	}
	proxy := &Proxy{
		config:      cfg,
		datacenters: defaultDatacenters(),
		dialContext: (&net.Dialer{}).DialContext,
		replay:      newReplayCache(cfg.ReplayCacheSize),
	}
	proxy.fakeCertLen.Store(int64(fakeCertLen))
	for name, encodedSecret := range cfg.Users {
		secret, _ := hex.DecodeString(encodedSecret)
		proxy.users = append(proxy.users, user{name: name, secret: secret})
	}
	return proxy, nil
}

func defaultDatacenters() map[int]string {
	return map[int]string{
		1: "149.154.175.50:443",
		2: "149.154.167.51:443",
		3: "149.154.175.100:443",
		4: "149.154.167.91:443",
		5: "149.154.171.5:443",
	}
}

type connectionTracker struct {
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	byIP        map[string]int
	clients     int
	closing     bool
}

func (t *connectionTracker) add(conn net.Conn) bool {
	t.mu.Lock()
	if t.closing {
		t.mu.Unlock()
		_ = conn.Close()
		return false
	}
	if t.connections == nil {
		t.connections = make(map[net.Conn]struct{})
	}
	t.connections[conn] = struct{}{}
	t.mu.Unlock()
	return true
}

func (t *connectionTracker) addClient(conn net.Conn, ip string, maxClients, maxPerIP int) bool {
	t.mu.Lock()
	if t.closing {
		t.mu.Unlock()
		_ = conn.Close()
		return false
	}
	if (maxClients > 0 && t.clients >= maxClients) || (maxPerIP > 0 && t.byIP[ip] >= maxPerIP) {
		t.mu.Unlock()
		return false
	}
	if t.connections == nil {
		t.connections = make(map[net.Conn]struct{})
	}
	if t.byIP == nil {
		t.byIP = make(map[string]int)
	}
	t.connections[conn] = struct{}{}
	t.clients++
	t.byIP[ip]++
	t.mu.Unlock()
	return true
}

func (t *connectionTracker) removeClient(conn net.Conn, ip string) {
	t.mu.Lock()
	if _, found := t.connections[conn]; found {
		delete(t.connections, conn)
		t.clients--
		t.byIP[ip]--
		if t.byIP[ip] == 0 {
			delete(t.byIP, ip)
		}
	}
	t.mu.Unlock()
}

func (t *connectionTracker) remove(conn net.Conn) {
	t.mu.Lock()
	delete(t.connections, conn)
	t.mu.Unlock()
}

func (t *connectionTracker) closeAll() {
	t.mu.Lock()
	t.closing = true
	connections := make([]net.Conn, 0, len(t.connections))
	for conn := range t.connections {
		connections = append(connections, conn)
	}
	t.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

// Serve accepts connections until ctx is cancelled or the listener is closed.
func (p *Proxy) Serve(ctx context.Context, listener net.Listener) error {
	connections := &connectionTracker{}
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			select {
			case <-serveDone:
				return
			default:
			}
			connections.closeAll()
			_ = listener.Close()
		case <-serveDone:
		}
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			if temporary, ok := err.(interface{ Temporary() bool }); ok && temporary.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		ip := remoteIP(conn)
		if !connections.addClient(conn, ip, p.config.MaxConnections, p.config.MaxConnectionsPerIP) {
			_ = conn.Close()
			continue
		}
		go func() {
			defer connections.removeClient(conn, ip)
			p.handleConn(ctx, conn, connections)
		}()
	}
}

func (p *Proxy) handleConn(ctx context.Context, client net.Conn, connections *connectionTracker) {
	defer client.Close()
	if p.config.HandshakeTimeout > 0 {
		_ = client.SetDeadline(time.Now().Add(time.Duration(p.config.HandshakeTimeout) * time.Second))
	}

	prefix := make([]byte, 3)
	if _, err := io.ReadFull(client, prefix); err != nil {
		return
	}
	isTLS := string(prefix) == "\x16\x03\x01"
	var transportReader io.Reader = client
	var transportWriter io.Writer = client
	handshake := make([]byte, handshakeLen)
	if isTLS {
		lengthBytes := make([]byte, 2)
		if _, err := io.ReadFull(client, lengthBytes); err != nil {
			return
		}
		clientHelloLen := int(binary.BigEndian.Uint16(lengthBytes))
		clientHello := make([]byte, 5+clientHelloLen)
		copy(clientHello, prefix)
		copy(clientHello[3:], lengthBytes)
		if _, err := io.ReadFull(client, clientHello[5:]); err != nil {
			return
		}
		tlsReader, tlsWriter, err := p.handleFakeTLS(client, clientHello)
		if err != nil {
			p.maskBadClient(ctx, client, clientHello, connections)
			return
		}
		transportReader = tlsReader
		transportWriter = tlsWriter
		if _, err := io.ReadFull(transportReader, handshake); err != nil {
			return
		}
	} else {
		copy(handshake, prefix)
		if _, err := io.ReadFull(transportReader, handshake[len(prefix):]); err != nil {
			return
		}
	}
	transportEnabled := p.config.EnableSecure
	if isTLS {
		transportEnabled = p.config.EnableTLS
	}
	session, err := p.decodeClientHandshake(handshake, transportEnabled)
	if err != nil {
		if !isTLS {
			p.maskBadClient(ctx, client, handshake, connections)
		}
		return
	}

	telegram, telegramReader, telegramWriter, err := p.openTelegram(ctx, session.dc, connections)
	if err != nil {
		return
	}
	defer connections.remove(telegram)
	defer telegram.Close()
	_ = client.SetDeadline(time.Time{})

	clientReader := withReadTimeout(client, cipher.StreamReader{S: session.decryptor, R: transportReader}, p.config.ReadTimeout)
	clientWriter := cipher.StreamWriter{S: session.encryptor, W: transportWriter}
	telegramReader = withReadTimeout(telegram, telegramReader, p.config.ReadTimeout)
	relay(client, telegram, clientReader, clientWriter, telegramReader, telegramWriter)
}

func (p *Proxy) decodeClientHandshake(handshake []byte, transportEnabled bool) (*clientSession, error) {
	if len(handshake) != handshakeLen {
		return nil, errors.New("invalid MTProto handshake length")
	}
	if !transportEnabled {
		return nil, errors.New("requested secure transport is disabled")
	}
	for _, candidate := range p.users {
		decKeyAndIV := handshake[8:56]
		decKeyInput := append(append([]byte(nil), decKeyAndIV[:32]...), candidate.secret...)
		decKey := sha256.Sum256(decKeyInput)
		decryptor := newCTR(decKey[:], decKeyAndIV[32:48])
		decrypted := make([]byte, handshakeLen)
		decryptor.XORKeyStream(decrypted, handshake)
		if !equalBytes(decrypted[protoTagPos:protoTagPos+4], secureProtocolTag) {
			continue
		}
		dc := int(int16(binary.LittleEndian.Uint16(decrypted[dcIndexPos : dcIndexPos+2])))
		if dc == 0 || dc < -5 || dc > 5 {
			continue
		}
		if p.replay.seenOrAdd("mtproto:" + string(decKeyAndIV)) {
			continue
		}

		encKeyAndIV := reversed(decKeyAndIV)
		encKeyInput := append(append([]byte(nil), encKeyAndIV[:32]...), candidate.secret...)
		encKey := sha256.Sum256(encKeyInput)
		return &clientSession{
			user:      candidate.name,
			dc:        dc,
			decryptor: decryptor,
			encryptor: newCTR(encKey[:], encKeyAndIV[32:48]),
		}, nil
	}
	return nil, errors.New("no matching user or secure protocol tag")
}

func (p *Proxy) openTelegram(ctx context.Context, dc int, connections *connectionTracker) (net.Conn, io.Reader, io.Writer, error) {
	index := dc
	if index < 0 {
		index = -index
	}
	address, found := p.datacenters[index]
	if !found {
		return nil, nil, nil, fmt.Errorf("unsupported Telegram DC %d", dc)
	}
	if p.config.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(p.config.ConnectTimeout)*time.Second)
		defer cancel()
	}
	conn, err := p.dialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, nil, err
	}
	if !connections.add(conn) {
		return nil, nil, nil, ctx.Err()
	}

	nonce, err := telegramNonce()
	if err != nil {
		connections.remove(conn)
		conn.Close()
		return nil, nil, nil, err
	}
	encryptor := newCTR(nonce[8:40], nonce[40:56])
	encrypted := make([]byte, handshakeLen)
	encryptor.XORKeyStream(encrypted, nonce)
	copy(nonce[56:], encrypted[56:])
	if err := writeFull(conn, nonce); err != nil {
		connections.remove(conn)
		conn.Close()
		return nil, nil, nil, err
	}

	decKeyAndIV := reversed(nonce[8:56])
	decryptor := newCTR(decKeyAndIV[:32], decKeyAndIV[32:48])
	return conn,
		cipher.StreamReader{S: decryptor, R: conn},
		cipher.StreamWriter{S: encryptor, W: conn},
		nil
}

func telegramNonce() ([]byte, error) {
	reservedFirst := []byte{0xef}
	reservedBeginnings := [][]byte{
		[]byte("HEAD"), []byte("POST"), []byte("GET "),
		{0xee, 0xee, 0xee, 0xee}, {0xdd, 0xdd, 0xdd, 0xdd}, {0x16, 0x03, 0x01, 0x02},
	}
	for {
		nonce := make([]byte, handshakeLen)
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		if nonce[0] == reservedFirst[0] || equalBytes(nonce[4:8], make([]byte, 4)) {
			continue
		}
		reserved := false
		for _, beginning := range reservedBeginnings {
			if equalBytes(nonce[:4], beginning) {
				reserved = true
				break
			}
		}
		if reserved {
			continue
		}
		copy(nonce[protoTagPos:protoTagPos+4], secureProtocolTag)
		return nonce, nil
	}
}

func newCTR(key, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // all call sites use fixed-size AES keys and IVs
	}
	return cipher.NewCTR(block, iv)
}

func reversed(in []byte) []byte {
	out := append([]byte(nil), in...)
	for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
		out[left], out[right] = out[right], out[left]
	}
	return out
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}

func relay(client, telegram net.Conn, clientReader io.Reader, clientWriter io.Writer, telegramReader io.Reader, telegramWriter io.Writer) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(telegramWriter, clientReader)
		closeWrite(telegram)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientWriter, telegramReader)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	_ = telegram.Close()
	_ = client.Close()
	<-done
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}
