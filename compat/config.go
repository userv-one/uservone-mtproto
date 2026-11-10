// Package compat converts entitled user records into core proxy configurations.
package compat

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/userv-one/uservone-mtproto/core"
)

// Record is one UUID credential and its entitlement state.
type Record struct {
	UUID     string `json:"uuid"`
	Secret   string `json:"secret"`
	Entitled bool   `json:"entitled"`
}

// UnmarshalJSON enforces the exact input schema, including required fields.
func (r *Record) UnmarshalJSON(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	opening, err := decoder.Token()
	if err != nil {
		return err
	}
	if opening == nil {
		return fmt.Errorf("record must be an object, not null")
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("record must be an object")
	}

	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return err
		}
		name := key.(string)
		if _, found := fields[name]; found {
			return fmt.Errorf("duplicate field %q", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("field %q: %w", name, err)
		}
		fields[name] = value
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("record must contain one JSON object")
		}
		return err
	}

	for _, name := range []string{"uuid", "secret", "entitled"} {
		if _, found := fields[name]; !found {
			return fmt.Errorf("missing required field %q", name)
		}
	}
	for name := range fields {
		switch name {
		case "uuid", "secret", "entitled":
		default:
			return fmt.Errorf("unknown field %q", name)
		}
	}

	var uuid, secret *string
	var entitled *bool
	for name, destination := range map[string]any{
		"uuid": &uuid, "secret": &secret, "entitled": &entitled,
	} {
		if err := json.Unmarshal(fields[name], destination); err != nil {
			return fmt.Errorf("field %q: %w", name, err)
		}
	}
	if uuid == nil || secret == nil || entitled == nil {
		return fmt.Errorf("record fields must not be null")
	}
	*r = Record{UUID: *uuid, Secret: *secret, Entitled: *entitled}
	return nil
}

// Options controls the generated proxy's public transports and listener.
type Options struct {
	Listen    string
	TLSDomain string
	MaskHost  string
}

// Generate builds a core-compatible configuration from entitled records.
func Generate(records []Record, options Options) (core.Config, error) {
	cfg := core.DefaultConfig()
	cfg.Listen = options.Listen
	cfg.TLSDomain = options.TLSDomain
	cfg.MaskHost = options.MaskHost
	seen := make(map[string]struct{})
	for i, record := range records {
		if !validUUID(record.UUID) {
			return core.Config{}, fmt.Errorf("record %d: invalid UUID", i)
		}
		secret, err := hex.DecodeString(record.Secret)
		if err != nil || len(secret) != 16 {
			return core.Config{}, fmt.Errorf("record %d: secret must contain exactly 32 hexadecimal characters", i)
		}
		if !record.Entitled {
			continue
		}
		uuid := strings.ToLower(record.UUID)
		if _, found := seen[uuid]; found {
			return core.Config{}, fmt.Errorf("record %d: duplicate UUID", i)
		}
		seen[uuid] = struct{}{}
		cfg.Users[uuid] = record.Secret
	}
	if len(cfg.Users) == 0 {
		return core.Config{}, fmt.Errorf("no entitled users")
	}
	if err := cfg.Validate(); err != nil {
		return core.Config{}, fmt.Errorf("invalid generated config: %w", err)
	}
	return cfg, nil
}

func validUUID(uuid string) bool {
	if len(uuid) != 36 {
		return false
	}
	for i := 0; i < len(uuid); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if uuid[i] != '-' {
				return false
			}
			continue
		}
		char := uuid[i]
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return true
}

// GenerateJSON decodes an input array and builds a core configuration.
func GenerateJSON(input []byte, options Options) (core.Config, error) {
	var records []Record
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&records); err != nil {
		return core.Config{}, fmt.Errorf("decode input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return core.Config{}, fmt.Errorf("decode input: multiple JSON values")
		}
		return core.Config{}, fmt.Errorf("decode input trailer: %w", err)
	}
	return Generate(records, options)
}
