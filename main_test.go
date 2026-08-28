package main

import (
	"testing"
	"time"
)

func TestValidTOTP(t *testing.T) {
	// RFC 6238 SHA-1 test secret; the RFC 8-digit value at 59 seconds is 94287082.
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if !validTOTP(secret, "287082", time.Unix(59, 0)) {
		t.Fatal("expected the RFC 6238-derived 6-digit code to validate")
	}
	if validTOTP(secret, "000000", time.Unix(59, 0)) {
		t.Fatal("unexpected invalid TOTP acceptance")
	}
}

func TestParseSiteURL(t *testing.T) {
	normalized, rpID, origin, err := parseSiteURL("https://dns.example.com:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "https://dns.example.com:8443" || origin != normalized || rpID != "dns.example.com" {
		t.Fatalf("unexpected site config: normalized=%q rpID=%q origin=%q", normalized, rpID, origin)
	}
	for _, invalid := range []string{"dns.example.com", "ftp://dns.example.com", "https://dns.example.com/panel", "https://dns.example.com?x=1"} {
		if _, _, _, err = parseSiteURL(invalid); err == nil {
			t.Errorf("expected invalid site URL %q to fail", invalid)
		}
	}
}
