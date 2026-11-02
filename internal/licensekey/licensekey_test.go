package licensekey

import (
	"errors"
	"regexp"
	"strings"
	"testing"
)

var canonical = regexp.MustCompile(`^LF-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{6}$`)

func TestNewIsCanonicalAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		k := New()
		if !canonical.MatchString(k) {
			t.Fatalf("New() = %q, not canonical", k)
		}
		if n, err := Normalize(k); err != nil || n != k {
			t.Fatalf("Normalize(New()) = %q, %v", n, err)
		}
		if seen[k] {
			t.Fatal("duplicate key")
		}
		seen[k] = true
	}
}

func TestNormalize(t *testing.T) {
	k := New()
	body := strings.ReplaceAll(strings.TrimPrefix(k, "LF-"), "-", "")
	for _, in := range []string{k, strings.ToLower(k), body, " " + body + " ", "lf " + strings.ToLower(body), strings.ReplaceAll(k, "-", " "), k + "\n", k + "\r\n", "\n" + k + "\n"} {
		if got, err := Normalize(in); err != nil || got != k {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, k)
		}
	}
	for _, in := range []string{"", "LF-", body[:25], body + "A", "9" + body[1:], "LF-ABCDE-FGHIJ-KLMNO-PQRST-UVWXY0"} {
		if _, err := Normalize(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("Normalize(%q): got %v, want ErrInvalid", in, err)
		}
	}
	// Bodies may start with LF (about 1 in 1024): the prefix is only stripped
	// from 28-character input.
	lfBody := "LFAAAAAAAAAAAAAAAAAAAAAAAA"
	if got, err := Normalize(lfBody); err != nil || got != "LF-LFAAA-AAAAA-AAAAA-AAAAA-AAAAAA" {
		t.Errorf("body starting with LF: %q, %v", got, err)
	}
	if got, err := Normalize("LF" + lfBody); err != nil || got != "LF-LFAAA-AAAAA-AAAAA-AAAAA-AAAAAA" {
		t.Errorf("prefixed body starting with LF: %q, %v", got, err)
	}
	// Look-alikes 0, 1, 8 map to O, I, B; non-ASCII is rejected.
	if got, err := Normalize("lf-018aa-aaaaa-aaaaa-aaaaa-aaaaaa"); err != nil || got != "LF-OIBAA-AAAAA-AAAAA-AAAAA-AAAAAA" {
		t.Errorf("look-alikes: %q, %v", got, err)
	}
	for _, in := range []string{"LF-\u017f" + body[1:], "LF-\u0131" + body[1:], "LF-" + body[:25] + "\u00e9"} {
		if _, err := Normalize(in); !errors.Is(err, ErrInvalid) {
			t.Errorf("non-ASCII %q: got %v", in, err)
		}
	}
	// 26 base32 chars carry 130 bits; the 2 unused trailing bits must be zero,
	// so each key has one spelling: ...AAAAAA is valid, ...AAAAAB is not.
	if _, err := Normalize("LF-AAAAA-AAAAA-AAAAA-AAAAA-AAAAAA"); err != nil {
		t.Errorf("canonical all-zero key: %v", err)
	}
	if _, err := Normalize("LF-AAAAA-AAAAA-AAAAA-AAAAA-AAAAAB"); !errors.Is(err, ErrInvalid) {
		t.Errorf("non-canonical trailing bits accepted: %v", err)
	}
}
