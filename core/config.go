package core

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxRotationGraceSeconds = math.MaxInt64 / int64(time.Second)

// Config is the proxy configuration.
type Config struct {
	Listen               string            `json:"listen"`
	MetricsListen        string            `json:"metrics_listen"`
	Users                map[string]string `json:"users"`
	EnableSecure         bool              `json:"enable_secure"`
	EnableTLS            bool              `json:"enable_tls"`
	UseMiddleProxy       bool              `json:"use_middle_proxy"`
	ADTag                string            `json:"ad_tag"`
	TLSDomain            string            `json:"tls_domain"`
	Mask                 bool              `json:"mask"`
	MaskHost             string            `json:"mask_host"`
	MaskPort             int               `json:"mask_port"`
	HandshakeTimeout     int               `json:"handshake_timeout_seconds"`
	ConnectTimeout       int               `json:"connect_timeout_seconds"`
	ReadTimeout          int               `json:"read_timeout_seconds"`
	MaxConnections       int               `json:"max_connections"`
	MaxConnectionsPerIP  int               `json:"max_connections_per_ip"`
	ReplayCacheSize      int               `json:"replay_cache_size"`
	RotationGraceSeconds int               `json:"rotation_grace_seconds"`
	FakeCertLen          int               `json:"fake_cert_len"`
	MatchMaskHost        bool              `json:"match_mask_host"`
	IgnoreTimeSkew       bool              `json:"ignore_time_skew"`
}

// DefaultConfig enables only the secure/random-padding and fake-TLS transports.
func DefaultConfig() Config {
	return Config{
		Listen:               ":443",
		Users:                make(map[string]string),
		EnableSecure:         true,
		EnableTLS:            true,
		TLSDomain:            "www.google.com",
		Mask:                 true,
		MaskHost:             "www.google.com",
		MaskPort:             443,
		HandshakeTimeout:     10,
		ConnectTimeout:       10,
		ReadTimeout:          600,
		MaxConnections:       4096,
		MaxConnectionsPerIP:  64,
		ReplayCacheSize:      65536,
		RotationGraceSeconds: 300,
		MatchMaskHost:        true,
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

// Validate checks c for invalid or unsafe values.
func (c Config) Validate() error {
	if c.UseMiddleProxy || c.ADTag != "" {
		return errors.New("middle-proxy and AD_TAG are not supported; keep the Python implementation for this node")
	}
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
	if c.MetricsListen != "" {
		_, metricsPortText, err := net.SplitHostPort(c.MetricsListen)
		if err != nil {
			return fmt.Errorf("invalid metrics listen address: %w", err)
		}
		metricsPort, err := strconv.Atoi(metricsPortText)
		if err != nil || metricsPort < 1 || metricsPort > 65535 {
			return errors.New("metrics port must be between 1 and 65535")
		}
	}
	if c.EnableTLS {
		if strings.TrimSpace(c.TLSDomain) == "" {
			return errors.New("TLS domain is required when fake-TLS is enabled")
		}
		if len(c.TLSDomain) > 253 {
			return errors.New("TLS domain is too long")
		}
		for _, char := range c.TLSDomain {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
				(char < '0' || char > '9') && char != '.' && char != '-' {
				return errors.New("TLS domain must be an ASCII host name")
			}
		}
	}
	if c.Mask {
		if strings.TrimSpace(c.MaskHost) == "" {
			return errors.New("mask host is required when masking is enabled")
		}
		if c.MaskPort < 1 || c.MaskPort > 65535 {
			return errors.New("mask port must be between 1 and 65535")
		}
	}
	if c.HandshakeTimeout <= 0 || c.ConnectTimeout <= 0 || c.ReadTimeout <= 0 {
		return errors.New("handshake, connect and read timeouts must be positive")
	}
	if c.MaxConnections < 0 || c.MaxConnectionsPerIP < 0 {
		return errors.New("connection limits cannot be negative")
	}
	if c.ReplayCacheSize < 0 {
		return errors.New("replay cache size cannot be negative")
	}
	if c.RotationGraceSeconds < 0 {
		return errors.New("rotation grace period cannot be negative")
	}
	if int64(c.RotationGraceSeconds) > maxRotationGraceSeconds {
		return fmt.Errorf("rotation grace period cannot exceed %d seconds", maxRotationGraceSeconds)
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
