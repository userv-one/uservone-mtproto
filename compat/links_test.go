package compat

import (
	"encoding/hex"
	"net/url"
	"testing"

	"github.com/userv-one/uservone-mtproto/core"
)

func TestGeneratedConfigLinksMatchTelegramFormats(t *testing.T) {
	const (
		uuid      = "123e4567-e89b-12d3-a456-426614174000"
		secret    = "42424242424242424242424242424242"
		tlsDomain = "proxy.example.com"
	)
	cfg, err := Generate([]Record{{UUID: uuid, Secret: secret, Entitled: true}}, Options{
		Listen: ":443", TLSDomain: tlsDomain, MaskHost: "mask.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	links, err := proxy.Links("edge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Fatalf("got %d links, want dd and fake-TLS", len(links))
	}

	wantSecrets := map[string]string{
		"dd":       "dd" + secret,
		"fake-tls": "ee" + secret + hex.EncodeToString([]byte(tlsDomain)),
	}
	for _, link := range links {
		if link.User != uuid {
			t.Fatalf("link user = %q, want %q", link.User, uuid)
		}
		parsed, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal(err)
		}
		query := parsed.Query()
		if parsed.Scheme != "tg" || parsed.Host != "proxy" || query.Get("server") != "edge.example.com" || query.Get("port") != "443" {
			t.Fatalf("invalid Telegram endpoint: %q", link.URL)
		}
		wantSecret, found := wantSecrets[link.Transport]
		if !found || query.Get("secret") != wantSecret {
			t.Fatalf("transport %q secret = %q, want %q", link.Transport, query.Get("secret"), wantSecret)
		}
		delete(wantSecrets, link.Transport)
	}
	if len(wantSecrets) != 0 {
		t.Fatalf("missing transports: %#v", wantSecrets)
	}
}
