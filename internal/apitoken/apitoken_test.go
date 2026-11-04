package apitoken

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewCheck(t *testing.T) {
	a, b := New(), New()
	if a == b || len(a) != Len || !strings.HasPrefix(a, "lf_live_") {
		t.Fatalf("New: %q %q", a, b)
	}
	if err := Check(a); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(Hash(a), Hash(b)) || len(Hash(a)) != 32 {
		t.Error("Hash")
	}
	if d := Display(a); d != a[:16]+"…" {
		t.Errorf("Display = %q", d)
	}
}

func TestCheckRejects(t *testing.T) {
	good := New()
	body := good[8 : 8+52]
	flip := func(i int) string { // change one character to another valid one
		c := byte('a')
		if good[i] == 'a' {
			c = 'b'
		}
		return good[:i] + string(c) + good[i+1:]
	}
	// The last body character carries 4 unused bits (260 bits for 256); set
	// one to spell the same bytes another way, with a valid checksum.
	alphabet := "abcdefghijklmnopqrstuvwxyz234567"
	nc := "lf_live_" + body[:51] + string(alphabet[strings.IndexByte(alphabet, body[51])|1])
	nc += checksum(nc)
	for name, s := range map[string]string{
		"empty":           "",
		"short":           good[:Len-1],
		"long":            good + "a",
		"wrong prefix":    "lf_test_" + good[8:],
		"upper case":      strings.ToUpper(good),
		"body changed":    flip(20),
		"checksum change": flip(Len - 1),
		"not base32":      good[:30] + "1" + good[31:],
		"whitespace":      " " + good[1:],
		"non-canonical":   nc,
		"prefix only":     "lf_live_",
	} {
		if Check(s) == nil {
			t.Errorf("%s: accepted %q", name, s)
		}
	}
}

// Fixed vectors, computed independently (Python: base64.b32encode, zlib.crc32
// big-endian, hashlib.sha256). The format is an external contract for secret
// scanners and clients, and Hash is what stored tokens are found by.
func TestVectors(t *testing.T) {
	var ff [32]byte
	for i := range ff {
		ff[i] = 0xff
	}
	for _, v := range []struct {
		raw         [32]byte
		token, hash string
	}{
		{[32]byte{}, "lf_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatida6lq", "8fb5af68f3c9c95f71eb74177f276040b423387ccd466183e16f65d704f1ead4"},
		{ff, "lf_live_777777777777777777777777777777777777777777777777777qv3x4uxa", "d82cea83af04330af6b02239a534cd0d08ab8a4854c4814060d3b1cef404a960"},
	} {
		if got := encode(v.raw); got != v.token {
			t.Errorf("encode = %s, want %s", got, v.token)
		}
		if err := Check(v.token); err != nil {
			t.Error(err)
		}
		if got := hex.EncodeToString(Hash(v.token)); got != v.hash {
			t.Errorf("Hash = %s, want %s", got, v.hash)
		}
	}
}

func TestDisplayRejectsMalformed(t *testing.T) {
	for _, s := range []string{"", "short", "lf_live_", strings.Repeat("x", 100), New() + "x"} {
		if d := Display(s); d != "" {
			t.Errorf("Display(%q) = %q", s, d)
		}
	}
}
