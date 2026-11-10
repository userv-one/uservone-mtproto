package core

import (
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"sort"
	"strings"
)

// Link is a Telegram deep link for one user and transport.
type Link struct {
	User      string `json:"user"`
	Transport string `json:"transport"`
	URL       string `json:"url"`
}

// Links generates dd and fake-TLS links for a public server name or address.
func (p *Proxy) Links(publicHost string) ([]Link, error) {
	if strings.TrimSpace(publicHost) == "" {
		return nil, errors.New("public host is required")
	}
	_, port, err := net.SplitHostPort(p.config.Listen)
	if err != nil {
		return nil, err
	}
	users := p.users.currentUsers()
	sort.Slice(users, func(i, j int) bool { return users[i].name < users[j].name })

	links := make([]Link, 0, len(users)*2)
	for _, account := range users {
		secret := hex.EncodeToString(account.secret)
		if p.config.EnableSecure {
			links = append(links, Link{
				User: account.name, Transport: "dd",
				URL: proxyURL(publicHost, port, "dd"+secret),
			})
		}
		if p.config.EnableTLS {
			tlsSecret := "ee" + secret + hex.EncodeToString([]byte(p.config.TLSDomain))
			links = append(links, Link{
				User: account.name, Transport: "fake-tls",
				URL: proxyURL(publicHost, port, tlsSecret),
			})
		}
	}
	return links, nil
}

func proxyURL(host, port, secret string) string {
	query := url.Values{}
	query.Set("server", host)
	query.Set("port", port)
	query.Set("secret", secret)
	return "tg://proxy?" + query.Encode()
}
