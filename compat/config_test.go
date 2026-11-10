package compat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/userv-one/uservone-mtproto/core"
)

func TestGenerateUsesOnlyEntitledRecords(t *testing.T) {
	entitled := Record{
		UUID:     "123e4567-e89b-12d3-a456-426614174000",
		Secret:   "42424242424242424242424242424242",
		Entitled: true,
	}
	revoked := Record{
		UUID:     "123e4567-e89b-12d3-a456-426614174001",
		Secret:   "43434343434343434343434343434343",
		Entitled: false,
	}

	cfg, err := Generate([]Record{entitled, revoked}, Options{
		Listen:    "127.0.0.1:8443",
		TLSDomain: "proxy.example.com",
		MaskHost:  "mask.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Users) != 1 || cfg.Users[entitled.UUID] != entitled.Secret {
		t.Fatalf("users = %#v, want only the entitled UUID", cfg.Users)
	}
	if _, found := cfg.Users[revoked.UUID]; found {
		t.Fatal("non-entitled UUID was included")
	}
	if cfg.Listen != "127.0.0.1:8443" || cfg.TLSDomain != "proxy.example.com" || cfg.MaskHost != "mask.example.com" {
		t.Fatalf("connection settings not applied: %+v", cfg)
	}
	if !cfg.EnableSecure || !cfg.EnableTLS || !cfg.Mask {
		t.Fatalf("secure, TLS, and mask must be enabled: %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("generated config is not core-compatible: %v", err)
	}
	if cfg.HandshakeTimeout != core.DefaultConfig().HandshakeTimeout {
		t.Fatal("core safety defaults were not preserved")
	}
}

func TestGenerateRejectsInvalidEntitledUUID(t *testing.T) {
	record := Record{
		UUID:     "not-a-uuid",
		Secret:   "42424242424242424242424242424242",
		Entitled: true,
	}
	if _, err := Generate([]Record{record}, validOptions()); err == nil {
		t.Fatal("invalid entitled UUID must be rejected")
	}
}

func TestRecordUnmarshalJSONRejectsDuplicateKeys(t *testing.T) {
	tests := map[string]string{
		"uuid":     `{"uuid":"first","uuid":"second","secret":"secret","entitled":true}`,
		"secret":   `{"uuid":"uuid","secret":"first","secret":"second","entitled":true}`,
		"entitled": `{"uuid":"uuid","secret":"secret","entitled":false,"entitled":true}`,
		"unknown":  `{"uuid":"uuid","secret":"secret","entitled":true,"extra":1,"extra":2}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var record Record
			err := json.Unmarshal([]byte(input), &record)
			if err == nil {
				t.Fatal("duplicate object key must be rejected")
			}
			if !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("error = %q, want duplicate-key error", err)
			}
		})
	}
}

func validOptions() Options {
	return Options{Listen: ":443", TLSDomain: "proxy.example.com", MaskHost: "mask.example.com"}
}

func TestGenerateRejectsInvalidEntitledSecret(t *testing.T) {
	record := Record{
		UUID:     "123e4567-e89b-12d3-a456-426614174000",
		Secret:   "not-a-secret",
		Entitled: true,
	}
	if _, err := Generate([]Record{record}, validOptions()); err == nil {
		t.Fatal("invalid entitled secret must be rejected")
	}
}

func TestGenerateRejectsMalformedNonEntitledRecord(t *testing.T) {
	records := []Record{
		{
			UUID:     "123e4567-e89b-12d3-a456-426614174000",
			Secret:   "42424242424242424242424242424242",
			Entitled: true,
		},
		{
			UUID:   "not-a-uuid",
			Secret: "not-a-secret",
		},
	}
	if _, err := Generate(records, validOptions()); err == nil {
		t.Fatal("malformed non-entitled records must be rejected")
	}
}

func TestGenerateRejectsDuplicateEntitledUUID(t *testing.T) {
	record := Record{
		UUID:     "123e4567-e89b-12d3-a456-426614174000",
		Secret:   "42424242424242424242424242424242",
		Entitled: true,
	}
	duplicate := record
	duplicate.Secret = "43434343434343434343434343434343"
	if _, err := Generate([]Record{record, duplicate}, validOptions()); err == nil {
		t.Fatal("duplicate entitled UUID must be rejected")
	}
}

func TestGenerateRejectsCaseInsensitiveDuplicateUUID(t *testing.T) {
	record := Record{
		UUID:     "123e4567-e89b-12d3-a456-426614174000",
		Secret:   "42424242424242424242424242424242",
		Entitled: true,
	}
	duplicate := record
	duplicate.UUID = "123E4567-E89B-12D3-A456-426614174000"
	if _, err := Generate([]Record{record, duplicate}, validOptions()); err == nil {
		t.Fatal("UUID duplicates must be detected case-insensitively")
	}
}

func TestGenerateStoresNormalizedUUID(t *testing.T) {
	record := Record{
		UUID:     "123E4567-E89B-12D3-A456-426614174000",
		Secret:   "42424242424242424242424242424242",
		Entitled: true,
	}
	cfg, err := Generate([]Record{record}, validOptions())
	if err != nil {
		t.Fatal(err)
	}
	const normalized = "123e4567-e89b-12d3-a456-426614174000"
	if len(cfg.Users) != 1 || cfg.Users[normalized] != record.Secret {
		t.Fatalf("users = %#v, want lowercase UUID key", cfg.Users)
	}
}

func TestGenerateRejectsNoEntitledUsers(t *testing.T) {
	record := Record{
		UUID:   "123e4567-e89b-12d3-a456-426614174000",
		Secret: "42424242424242424242424242424242",
	}
	if _, err := Generate([]Record{record}, validOptions()); err == nil {
		t.Fatal("configuration without entitled users must be rejected")
	}
}

func TestGenerateJSONDecodesInputArray(t *testing.T) {
	input := `[
		{"uuid":"123e4567-e89b-12d3-a456-426614174000","secret":"42424242424242424242424242424242","entitled":true},
		{"uuid":"123e4567-e89b-12d3-a456-426614174001","secret":"43434343434343434343434343434343","entitled":false}
	]`
	cfg, err := GenerateJSON([]byte(input), validOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Users) != 1 || cfg.Users["123e4567-e89b-12d3-a456-426614174000"] != "42424242424242424242424242424242" {
		t.Fatalf("unexpected users: %#v", cfg.Users)
	}
}

func TestGenerateRejectsInvalidCoreOptions(t *testing.T) {
	record := Record{
		UUID:     "123e4567-e89b-12d3-a456-426614174000",
		Secret:   "42424242424242424242424242424242",
		Entitled: true,
	}
	options := validOptions()
	options.Listen = "not-a-listen-address"
	if _, err := Generate([]Record{record}, options); err == nil {
		t.Fatal("invalid core listener must be rejected")
	}
}

func TestGenerateJSONRejectsUnknownRecordFields(t *testing.T) {
	input := `[{"uuid":"123e4567-e89b-12d3-a456-426614174000","secret":"42424242424242424242424242424242","entitled":true,"extra":true}]`
	if _, err := GenerateJSON([]byte(input), validOptions()); err == nil {
		t.Fatal("unknown input record fields must be rejected")
	}
}

func TestGenerateJSONRequiresExactCompleteNonNullRecords(t *testing.T) {
	const valid = `{"uuid":"123e4567-e89b-12d3-a456-426614174000","secret":"42424242424242424242424242424242","entitled":true}`
	tests := map[string]string{
		"missing entitled":  `[` + valid + `,{"uuid":"123e4567-e89b-12d3-a456-426614174001","secret":"42424242424242424242424242424242"}]`,
		"null entitled":     `[` + valid + `,{"uuid":"123e4567-e89b-12d3-a456-426614174001","secret":"42424242424242424242424242424242","entitled":null}]`,
		"null element":      `[` + valid + `,null]`,
		"UUID key case":     `[` + valid + `,{"UUID":"123e4567-e89b-12d3-a456-426614174001","secret":"42424242424242424242424242424242","entitled":false}]`,
		"secret key case":   `[` + valid + `,{"uuid":"123e4567-e89b-12d3-a456-426614174001","Secret":"42424242424242424242424242424242","entitled":false}]`,
		"entitled key case": `[` + valid + `,{"uuid":"123e4567-e89b-12d3-a456-426614174001","secret":"42424242424242424242424242424242","Entitled":false}]`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := GenerateJSON([]byte(input), validOptions()); err == nil {
				t.Fatal("invalid record must be rejected")
			}
		})
	}
}
