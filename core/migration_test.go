package core

import "testing"

func TestValidateRequiresPythonForMiddleProxy(t *testing.T) {
	cfg := testConfig()
	cfg.UseMiddleProxy = true
	if err := cfg.Validate(); err == nil {
		t.Fatal("middle-proxy mode must not be silently replaced with direct mode")
	}

	cfg = testConfig()
	cfg.ADTag = "3c09c680b76ee91a4c25ad51f742267d"
	if err := cfg.Validate(); err == nil {
		t.Fatal("AD_TAG requires the Python middle-proxy implementation")
	}
}
