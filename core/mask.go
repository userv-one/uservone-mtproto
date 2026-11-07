package core

import (
	"context"
	"net"
	"strconv"
	"time"
)

// maskBadClient forwards an unrecognised connection to a real HTTPS host.
// The captured bytes are replayed unchanged so active probes see the mask host.
func (p *Proxy) maskBadClient(ctx context.Context, client net.Conn, captured []byte, connections *connectionTracker) {
	if !p.config.Mask {
		return
	}
	if p.config.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(p.config.ConnectTimeout)*time.Second)
		defer cancel()
	}
	address := net.JoinHostPort(p.config.MaskHost, strconv.Itoa(p.config.MaskPort))
	mask, err := p.dialContext(ctx, "tcp", address)
	if err != nil {
		return
	}
	if !connections.add(mask) {
		return
	}
	defer connections.remove(mask)
	defer mask.Close()
	if err := writeFull(mask, captured); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	_ = mask.SetDeadline(time.Time{})
	clientReader := withReadTimeout(client, client, p.config.ReadTimeout)
	maskReader := withReadTimeout(mask, mask, p.config.ReadTimeout)
	relay(client, mask, clientReader, client, maskReader, mask)
}
