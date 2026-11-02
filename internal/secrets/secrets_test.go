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

var bind = Binding{Purpose: PurposeLicenseKey, TenantID: "tnt_a", RowID: "lic_1"}

func TestEncryptDecrypt(t *testing.T) {
	kr := mustKeyring(t, "k1="+testKey(1))
	ct, err := kr.Encrypt([]byte("LF-SECRET"), bind)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ct, "v1.k1.") || strings.Contains(ct, "SECRET") {
		t.Fatalf("ciphertext %q", ct)
	}
	if pt, err := kr.Decrypt(ct, bind); err != nil || string(pt) != "LF-SECRET" {
		t.Fatalf("Decrypt = %q, %v", pt, err)
	}
	if ct2, _ := kr.Encrypt([]byte("LF-SECRET"), bind); ct == ct2 {
		t.Fatal("same ciphertext twice: nonce reused")
	}
}

func TestDecryptRejects(t *testing.T) {
	kr := mustKeyring(t, "k1="+testKey(1))
	ct, _ := kr.Encrypt([]byte("LF-SECRET"), bind)
	raw, _ := b64.DecodeString(ct[len("v1.k1."):])
	raw[len(raw)-1] ^= 1
	sameMaterial := mustKeyring(t, "k1="+testKey(1)+",k2="+testKey(1))
	cases := map[string]struct {
		kr *Keyring
		ct string
		b  Binding
	}{
		"other row":            {kr, ct, Binding{PurposeLicenseKey, "tnt_a", "lic_2"}},
		"other tenant":         {kr, ct, Binding{PurposeLicenseKey, "tnt_b", "lic_1"}},
		"other purpose":        {kr, ct, Binding{"api_token", "tnt_a", "lic_1"}},
		"fields shifted":       {kr, ct, Binding{PurposeLicenseKey, "tnt_al", "ic_1"}},
		"tampered":             {kr, "v1.k1." + b64.EncodeToString(raw), bind},
		"relabelled key id":    {sameMaterial, strings.Replace(ct, ".k1.", ".k2.", 1), bind},
		"wrong key, same id":   {mustKeyring(t, "k1="+testKey(2)), ct, bind},
		"garbage":              {kr, "nope", bind},
		"bad version":          {kr, strings.Replace(ct, "v1.", "v2.", 1), bind},
		"non-canonical base64": {kr, ct + "=", bind},
		"invalid key id":       {kr, "v1.K\n1." + ct[len("v1.k1."):], bind},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.kr.Decrypt(tc.ct, tc.b); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("got %v, want ErrDecrypt", err)
			}
		})
	}
	if _, err := kr.Decrypt(strings.Replace(ct, ".k1.", ".k9.", 1), bind); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key id: got %v", err)
	}
	for _, b := range []Binding{{}, {Purpose: PurposeLicenseKey, TenantID: "t"}, {TenantID: "t", RowID: "r"}} {
		if _, err := kr.Encrypt([]byte("x"), b); err == nil {
			t.Errorf("incomplete binding %+v accepted", b)
		}
	}
}

func TestRotation(t *testing.T) {
	old := mustKeyring(t, "k1="+testKey(1))
	ct, _ := old.Encrypt([]byte("v"), bind)
	h, _ := old.LookupHash(PurposeLicenseKey, []byte("LF-X"))

	rotated := mustKeyring(t, "k2="+testKey(2)+",k1="+testKey(1))
	if rotated.ActiveID() != "k2" {
		t.Fatal("first key must be active")
	}
	if pt, err := rotated.Decrypt(ct, bind); err != nil || string(pt) != "v" {
		t.Fatalf("old ciphertext after rotation: %q, %v", pt, err)
	}
	if ct2, _ := rotated.Encrypt([]byte("v"), bind); !strings.HasPrefix(ct2, "v1.k2.") {
		t.Fatalf("new ciphertext uses %q", ct2)
	}
	hs := rotated.LookupHashes(PurposeLicenseKey, []byte("LF-X"))
	if len(hs) != 2 || hs[1] != h || hs[0] == h {
		t.Fatalf("lookup hashes %v must include the pre-rotation hash %s", hs, h)
	}
	if same := mustKeyring(t, "a="+testKey(3)+",b="+testKey(3)).LookupHashes(PurposeLicenseKey, []byte("x")); same[0] != same[1] {
		t.Fatal("same key material under two ids must give the same lookup hash")
	}
}

func TestLookupHash(t *testing.T) {
	kr := mustKeyring(t, "k1="+testKey(1))
	h := func(p Purpose, v string) string {
		s, err := kr.LookupHash(p, []byte(v))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a := h(PurposeLicenseKey, "LF-X")
	if a != h(PurposeLicenseKey, "LF-X") || len(a) != 64 {
		t.Fatal("lookup hash must be deterministic hex SHA-256")
	}
	if a == h("api_token", "LF-X") || a == h(PurposeLicenseKey, "LF-Y") || h("ab", "c") == h("a", "bc") {
		t.Fatal("purpose and value must be unambiguous inputs")
	}
	other, _ := mustKeyring(t, "k1="+testKey(2)).LookupHash(PurposeLicenseKey, []byte("LF-X"))
	if a == other {
		t.Fatal("hash must depend on the key")
	}
}

func TestEmptyKeyring(t *testing.T) {
	var kr Keyring
	if _, err := kr.Encrypt([]byte("x"), bind); !errors.Is(err, ErrEmptyKeyring) {
		t.Errorf("Encrypt: %v", err)
	}
	if _, err := kr.Decrypt("v1.k1.x", bind); !errors.Is(err, ErrEmptyKeyring) {
		t.Errorf("Decrypt: %v", err)
	}
	if _, err := kr.LookupHash(PurposeLicenseKey, nil); !errors.Is(err, ErrEmptyKeyring) {
		t.Errorf("LookupHash: %v", err)
	}
	if kr.ActiveID() != "" {
		t.Error("ActiveID of empty keyring")
	}
}

func TestParseKeyring(t *testing.T) {
	k := testKey(1)
	if _, err := ParseKeyring(" k1=" + k + " , k2=" + testKey(2) + " "); err != nil {
		t.Errorf("spaces around entries: %v", err)
	}
	unpadded := strings.TrimRight(k, "=")
	urlSafe := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, KeySize))
	for _, bad := range []string{
		"", ",", "k1", k, "k1:" + k, "=" + k, "K1=" + k, "k1=short",
		"k1=" + k + ",k1=" + testKey(2), "k 1=" + k, "k1=" + k + ",",
		"k1=" + unpadded, "k1=" + k + "==", "k1=" + k[:20] + "\n" + k[20:], "k1=" + urlSafe,
	} {
		_, err := ParseKeyring(bad)
		if err == nil {
			t.Errorf("ParseKeyring(%q) accepted", bad)
			continue
		}
		for _, secret := range []string{k, unpadded, urlSafe, k[:20]} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("ParseKeyring(%q): error leaks key material: %v", bad, err)
			}
		}
	}
}
