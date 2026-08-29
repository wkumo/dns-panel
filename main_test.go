package main

import (
	"bytes"
	"encoding/base64"
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

func TestEncryptedBackupRoundTrip(t *testing.T) {
	plain := []byte(`{"version":1,"secret":"cloud-token"}`)
	encrypted, err := encryptBackup("correct horse battery staple", plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains([]byte(encrypted.Ciphertext), []byte("cloud-token")) {
		t.Fatal("encrypted backup leaked plaintext secret")
	}
	decrypted, err := decryptBackup("correct horse battery staple", encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plain) {
		t.Fatalf("decrypted backup differs: %q", decrypted)
	}
	if _, err = decryptBackup("wrong password", encrypted); err == nil {
		t.Fatal("wrong password unexpectedly decrypted backup")
	}
	ciphertext, _ := base64.RawStdEncoding.DecodeString(encrypted.Ciphertext)
	ciphertext[len(ciphertext)-1] ^= 1
	encrypted.Ciphertext = base64.RawStdEncoding.EncodeToString(ciphertext)
	if _, err = decryptBackup("correct horse battery staple", encrypted); err == nil {
		t.Fatal("tampered backup unexpectedly decrypted")
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
