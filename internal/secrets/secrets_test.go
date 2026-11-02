package secrets

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func testKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, KeySize))
}

func mustKeyring(t *testing.T, s string) *Keyring {
	t.Helper()
	kr, err := ParseKeyring(s)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func TestEncryptDecrypt(t *testing.T) {
	kr := mustKeyring(t, "k1="+testKey(1))
	ad := []byte("license_key|tnt_a|lic_1")
	ct, err := kr.Encrypt([]byte("LF-SECRET"), ad)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "v1.k1.") || strings.Contains(ct, "SECRET") {
		t.Fatalf("ciphertext %q", ct)
	}
	if pt, err := kr.Decrypt(ct, ad); err != nil || string(pt) != "LF-SECRET" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}
	ct2, _ := kr.Encrypt([]byte("LF-SECRET"), ad)
	if ct == ct2 {
		t.Fatal("same ciphertext twice: nonce reused")
	}
}

func TestDecryptRejects(t *testing.T) {
	kr := mustKeyring(t, "k1="+testKey(1))
	ad := []byte("license_key|tnt_a|lic_1")
	ct, _ := kr.Encrypt([]byte("LF-SECRET"), ad)
	sealed := ct[len("v1.k1."):]
	raw, _ := b64.DecodeString(sealed)
	raw[len(raw)-1] ^= 1
	other := mustKeyring(t, "k1="+testKey(2))
	for name, tc := range map[string]struct {
		kr *Keyring
		ct string
		ad string
	}{
		"other row (ad)":       {kr, ct, "license_key|tnt_a|lic_2"},
		"other tenant (ad)":    {kr, ct, "license_key|tnt_b|lic_1"},
		"tampered":             {kr, "v1.k1." + b64.EncodeToString(raw), string(ad)},
		"relabelled key id":    {mustKeyring(t, "k1="+testKey(1)+",k2="+testKey(1)), strings.Replace(ct, ".k1.", ".k2.", 1), string(ad)},
		"wrong key, same id":   {other, ct, string(ad)},
		"garbage":              {kr, "nope", string(ad)},
		"bad version":          {kr, strings.Replace(ct, "v1.", "v2.", 1), string(ad)},
		"non-canonical base64": {kr, ct + "=", string(ad)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.kr.Decrypt(tc.ct, []byte(tc.ad)); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("got %v, want ErrDecrypt", err)
			}
		})
	}
	if _, err := kr.Decrypt(strings.Replace(ct, ".k1.", ".k9.", 1), ad); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key id: got %v", err)
	}
}

func TestRotation(t *testing.T) {
	old := mustKeyring(t, "k1="+testKey(1))
	ad := []byte("ad")
	ct, _ := old.Encrypt([]byte("v"), ad)
	h := old.LookupHash("license_key", []byte("LF-X"))

	rotated := mustKeyring(t, "k2="+testKey(2)+",k1="+testKey(1))
	if rotated.ActiveID() != "k2" {
		t.Fatal("first key must be active")
	}
	if pt, err := rotated.Decrypt(ct, ad); err != nil || string(pt) != "v" {
		t.Fatalf("old ciphertext after rotation: %q, %v", pt, err)
	}
	if ct2, _ := rotated.Encrypt([]byte("v"), ad); !strings.HasPrefix(ct2, "v1.k2.") {
		t.Fatalf("new ciphertext uses %q", ct2)
	}
	hs := rotated.LookupHashes("license_key", []byte("LF-X"))
	if len(hs) != 2 || hs[1] != h || hs[0] == h {
		t.Fatalf("lookup hashes %v must include the pre-rotation hash %s", hs, h)
	}
}

func TestLookupHash(t *testing.T) {
	kr := mustKeyring(t, "k1="+testKey(1))
	a := kr.LookupHash("license_key", []byte("LF-X"))
	if a != kr.LookupHash("license_key", []byte("LF-X")) || len(a) != 64 {
		t.Fatal("lookup hash must be deterministic hex SHA-256")
	}
	if a == kr.LookupHash("api_token", []byte("LF-X")) || a == kr.LookupHash("license_key", []byte("LF-Y")) {
		t.Fatal("purpose and value must change the hash")
	}
	if a == mustKeyring(t, "k1="+testKey(2)).LookupHash("license_key", []byte("LF-X")) {
		t.Fatal("hash must depend on the key")
	}
}

func TestParseKeyring(t *testing.T) {
	urlKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, KeySize))
	if _, err := ParseKeyring("k1=" + urlKey); err != nil {
		t.Errorf("URL-safe base64: %v", err)
	}
	for _, bad := range []string{"", "k1", "=" + testKey(1), "K1=" + testKey(1), "k1=short", "k1=" + testKey(1) + ",k1=" + testKey(2), "k 1=" + testKey(1)} {
		_, err := ParseKeyring(bad)
		if err == nil {
			t.Errorf("ParseKeyring(%q) accepted", bad)
		} else if strings.Contains(err.Error(), testKey(1)) {
			t.Errorf("error leaks key material: %v", err)
		}
	}
}
