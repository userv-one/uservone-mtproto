package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config contains the public settings needed to embed the proxy core.
type Config struct {
	Listen           string            `json:"listen"`
	Users            map[string]string `json:"users"`
	EnableSecure     bool              `json:"enable_secure"`
	EnableTLS        bool              `json:"enable_tls"`
	TLSDomain        string            `json:"tls_domain"`
	Mask             bool              `json:"mask"`
	MaskHost         string            `json:"mask_host"`
	MaskPort         int               `json:"mask_port"`
	HandshakeTimeout int               `json:"handshake_timeout_seconds"`
	ConnectTimeout   int               `json:"connect_timeout_seconds"`
	ReplayCacheSize  int               `json:"replay_cache_size"`
	FakeCertLen      int               `json:"fake_cert_len"`
	IgnoreTimeSkew   bool              `json:"ignore_time_skew"`
}

// DefaultConfig enables only the secure/random-padding and fake-TLS transports.
func DefaultConfig() Config {
	return Config{
		Listen:           ":443",
		Users:            make(map[string]string),
		EnableSecure:     true,
		EnableTLS:        true,
		TLSDomain:        "www.google.com",
		Mask:             true,
		MaskHost:         "www.google.com",
		MaskPort:         443,
		HandshakeTimeout: 10,
		ConnectTimeout:   10,
		ReplayCacheSize:  65536,
	}
}

// LoadConfig reads a JSON configuration on top of the secure defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("decode config: multiple JSON values")
		}
		return Config{}, fmt.Errorf("decode config trailer: %w", err)
	}
	if cfg.MaskHost == "www.google.com" && cfg.TLSDomain != "www.google.com" {
		cfg.MaskHost = cfg.TLSDomain
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate rejects configurations that would silently create an unsafe proxy.
func (c Config) Validate() error {
	if !c.EnableSecure && !c.EnableTLS {
		return errors.New("at least one of secure or fake-TLS transport must be enabled")
	}
	_, listenPortText, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	listenPort, err := strconv.Atoi(listenPortText)
	if err != nil || listenPort < 1 || listenPort > 65535 {
		return errors.New("listen port must be between 1 and 65535")
	}
	if c.EnableTLS && strings.TrimSpace(c.TLSDomain) == "" {
		return errors.New("TLS domain is required when fake-TLS is enabled")
	}
	if c.Mask {
		if strings.TrimSpace(c.MaskHost) == "" {
			return errors.New("mask host is required when masking is enabled")
		}
		if c.MaskPort < 1 || c.MaskPort > 65535 {
			return errors.New("mask port must be between 1 and 65535")
		}
	}
	if c.HandshakeTimeout <= 0 || c.ConnectTimeout <= 0 {
		return errors.New("handshake and connect timeouts must be positive")
	}
	if c.ReplayCacheSize < 0 {
		return errors.New("replay cache size cannot be negative")
	}
	if c.FakeCertLen != 0 && (c.FakeCertLen < 1024 || c.FakeCertLen > 65535) {
		return errors.New("fake certificate length must be zero or between 1024 and 65535")
	}
	if len(c.Users) == 0 {
		return errors.New("at least one user is required")
	}

	unsafeSecrets := map[string]struct{}{
		strings.Repeat("0", 32):            {},
		strings.Repeat("0", 31) + "1":      {},
		"0123456789abcdef0123456789abcdef": {},
	}
	for name, secret := range c.Users {
		decoded, err := hex.DecodeString(secret)
		if err != nil || len(decoded) != 16 {
			return fmt.Errorf("user %q: secret must contain exactly 32 hexadecimal characters", name)
		}
		if _, found := unsafeSecrets[strings.ToLower(secret)]; found {
			return fmt.Errorf("user %q: default or well-known secret is forbidden", name)
		}
	}
	return nil
}
