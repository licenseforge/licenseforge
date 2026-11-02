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

// Normalize accepts a key as a user may type or paste it (any ASCII case, with
// or without the LF prefix, dashes or spaces, and the look-alikes 0 for O,
// 1 for I and 8 for B, which base32 doesn't use) and returns the canonical
// form. Only one canonical form decodes to each key, so hashing it gives one
// lookup value.
func Normalize(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '-' || c == ' ' || c == '\t':
			continue
		case c >= 0x80:
			return "", ErrInvalid // no Unicode case folding (e.g. U+017F folds to S)
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		switch c {
		case '0':
			c = 'O'
		case '1':
			c = 'I'
		case '8':
			c = 'B'
		}
		b.WriteByte(c)
	}
	body := b.String()
	if len(body) == 28 && strings.HasPrefix(body, "LF") { // prefix only when present: bodies may start with LF
		body = body[2:]
	}
	raw, err := enc.DecodeString(body)
	// Re-encoding rejects non-canonical input (nonzero unused trailing bits),
	// so every key has exactly one canonical spelling.
	if err != nil || len(raw) != 16 || enc.EncodeToString(raw) != body {
		return "", ErrInvalid
	}
	return format(body), nil
}

func format(body string) string {
	return "LF-" + body[0:5] + "-" + body[5:10] + "-" + body[10:15] + "-" + body[15:20] + "-" + body[20:26]
}
