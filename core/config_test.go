package core

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigEnablesOnlySecureTransports(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Users = map[string]string{"media": strings.Repeat("42", 16)}

	if !cfg.EnableSecure || !cfg.EnableTLS {
		t.Fatalf("secure and fake-TLS transports must be enabled by default: %+v", cfg)
	}
	if cfg.RotationGraceSeconds != 300 {
		t.Fatalf("default rotation grace = %d seconds, want 300", cfg.RotationGraceSeconds)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config with a real secret must be valid: %v", err)
	}
}

func TestValidateRotationGracePeriodFitsDuration(t *testing.T) {
	maxSeconds := int64(math.MaxInt64) / int64(time.Second)
	if maxSeconds > math.MaxInt {
		t.Skip("duration-overflowing values cannot be represented by int on this platform")
	}

	tests := []struct {
		name    string
		seconds int64
		wantErr bool
	}{
		{name: "normal five minutes", seconds: 300},
		{name: "maximum whole-second duration", seconds: maxSeconds},
		{name: "duration overflow", seconds: maxSeconds + 1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.RotationGraceSeconds = int(test.seconds)
			err := cfg.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() with %d grace seconds returned %v, wantErr %t", test.seconds, err, test.wantErr)
			}
		})
	}
}

func TestValidateRejectsUnsafeSecrets(t *testing.T) {
	for _, secret := range []string{
		strings.Repeat("0", 32),
		strings.Repeat("0", 31) + "1",
		"0123456789abcdef0123456789abcdef",
		"not-a-secret",
	} {
		cfg := DefaultConfig()
		cfg.Users = map[string]string{"media": secret}
		if err := cfg.Validate(); err == nil {
			t.Errorf("secret %q must be rejected", secret)
		}
	}
}

func TestValidateRequiresAtLeastOneTransport(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Users = map[string]string{"media": strings.Repeat("42", 16)}
	cfg.EnableSecure = false
	cfg.EnableTLS = false

	if err := cfg.Validate(); err == nil {
		t.Fatal("config without secure or fake-TLS transport must be rejected")
	}
}

func TestValidateRejectsInvalidNetworkAndSafetyLimits(t *testing.T) {
	tests := map[string]func(*Config){
		"empty listen address":  func(c *Config) { c.Listen = "" },
		"listen without port":   func(c *Config) { c.Listen = "127.0.0.1" },
		"invalid listen port":   func(c *Config) { c.Listen = ":70000" },
		"empty TLS domain":      func(c *Config) { c.TLSDomain = "" },
		"empty mask host":       func(c *Config) { c.MaskHost = "" },
		"invalid mask port":     func(c *Config) { c.MaskPort = 0 },
		"no handshake timeout":  func(c *Config) { c.HandshakeTimeout = 0 },
		"no connect timeout":    func(c *Config) { c.ConnectTimeout = 0 },
		"no read timeout":       func(c *Config) { c.ReadTimeout = 0 },
		"negative global limit": func(c *Config) { c.MaxConnections = -1 },
		"negative IP limit":     func(c *Config) { c.MaxConnectionsPerIP = -1 },
		"long TLS domain":       func(c *Config) { c.TLSDomain = strings.Repeat("a", 254) },
		"non-ASCII TLS domain":  func(c *Config) { c.TLSDomain = "приклад.рф" },
		"negative replay size":  func(c *Config) { c.ReplayCacheSize = -1 },
		"short fake cert":       func(c *Config) { c.FakeCertLen = 100 },
		"oversized fake cert":   func(c *Config) { c.FakeCertLen = 65536 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("invalid config was accepted: %+v", cfg)
			}
		})
	}
}
