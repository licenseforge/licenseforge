// Package licensekey generates and normalises license keys (ADR-0025):
// "LF-" + 128 random bits as 26 uppercase base32 characters, grouped
// LF-XXXXX-XXXXX-XXXXX-XXXXX-XXXXXX.
package licensekey

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"strings"
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrInvalid means the input isn't a well-formed license key.
var ErrInvalid = errors.New("licensekey: invalid license key")

// New returns a new random license key in canonical form.
func New() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	return format(enc.EncodeToString(b[:]))
}

// Normalize accepts a key as a user may type or paste it (any case, with or
// without the LF prefix, dashes or spaces) and returns the canonical form.
// Each key has exactly one canonical form, so hashing it gives one lookup value.
func Normalize(s string) (string, error) {
	s = strings.ToUpper(strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, strings.TrimSpace(s)))
	s = strings.TrimPrefix(s, "LF")
	b, err := enc.DecodeString(s)
	// Re-encoding rejects non-canonical input (nonzero unused trailing bits),
	// so every key has exactly one accepted spelling.
	if err != nil || len(b) != 16 || enc.EncodeToString(b) != s {
		return "", ErrInvalid
	}
	return format(s), nil
}

func format(body string) string {
	return "LF-" + body[0:5] + "-" + body[5:10] + "-" + body[10:15] + "-" + body[15:20] + "-" + body[20:26]
}
