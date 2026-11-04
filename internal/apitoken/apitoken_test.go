package apitoken

import (
	"bytes"
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
