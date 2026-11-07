package core

import (
	"net/url"
	"strings"
	"testing"
)

func TestProxyLinksContainSecureAndFakeTLSSecrets(t *testing.T) {
	proxy, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	links, err := proxy.Links("proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Fatalf("got %d links, want secure and fake-TLS", len(links))
	}

	seen := make(map[string]bool)
	for _, link := range links {
		seen[link.Transport] = true
		parsed, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal(err)
		}
		query := parsed.Query()
		if query.Get("server") != "proxy.example.com" || query.Get("port") != "443" {
			t.Fatalf("wrong endpoint in %q", link.URL)
		}
		secret := query.Get("secret")
		switch link.Transport {
		case "dd":
			if secret != "dd"+strings.Repeat("42", 16) {
				t.Fatalf("wrong dd secret %q", secret)
			}
		case "fake-tls":
			want := "ee" + strings.Repeat("42", 16) + "7777772e676f6f676c652e636f6d"
			if secret != want {
				t.Fatalf("wrong fake-TLS secret %q, want %q", secret, want)
			}
		default:
			t.Fatalf("unexpected transport %q", link.Transport)
		}
	}
	if !seen["dd"] || !seen["fake-tls"] {
		t.Fatalf("missing transport in %+v", links)
	}
}
