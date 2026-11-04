// Package apitoken generates and checks API tokens (ADR-0003, ADR-0019):
// opaque, shown once, stored as a hash, recognisable by their prefix.
//
// Format: "lf_live_" + 256 random bits as 52 lowercase base32 characters + a
// 7-character checksum (CRC-32 of everything before it). The fixed prefix and
// checksum let secret scanners find leaked tokens with few false positives,
// and let the server reject mistyped tokens without a database lookup.
package apitoken

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"strings"
)

// prefix marks LicenseForge API tokens. "live" leaves room for a future
// test-mode prefix; there is none today.
const prefix = "lf_live_"

const (
	bodyLen = 52 // 32 bytes in base32
	sumLen  = 7  // 4 bytes in base32
	Len     = len(prefix) + bodyLen + sumLen
)

var enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ErrInvalid means the input isn't a well-formed API token.
var ErrInvalid = errors.New("apitoken: invalid API token")

// New returns a new random token. Show it once; store only Hash and Display.
func New() string {
	var b [32]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	return encode(b)
}

func encode(b [32]byte) string {
	s := prefix + enc.EncodeToString(b[:])
	return s + checksum(s)
}

// checksum is CRC-32/IEEE of the prefix and body, big-endian, in the token
// alphabet. External scanners and clients compute the same; see the test
// vectors.
func checksum(s string) string {
	return enc.EncodeToString(binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE([]byte(s))))
}

// Check reports whether s is a well-formed token: prefix, length, alphabet,
// canonical encoding and checksum. It says nothing about whether the token
// exists; look up Hash for that.
func Check(s string) error {
	if len(s) != Len || !strings.HasPrefix(s, prefix) {
		return ErrInvalid
	}
	body, sum := s[len(prefix):len(prefix)+bodyLen], s[len(prefix)+bodyLen:]
	raw, err := enc.DecodeString(body)
	// Re-encoding rejects non-canonical bodies (nonzero unused trailing bits).
	if err != nil || enc.EncodeToString(raw) != body || checksum(s[:len(s)-sumLen]) != sum {
		return ErrInvalid
	}
	return nil
}

// Hash is what the database stores and looks tokens up by: SHA-256 of the
// whole token. The token is 256 random bits, so a plain hash can't be
// brute-forced and needs no key. Check the token first, so malformed input
// never reaches the database.
func Hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// Display is the part shown in lists so users can tell tokens apart:
// "lf_live_" + the first 8 body characters. It reveals 40 of the 256 bits.
// Anything that isn't a well-formed token gives "", never part of the input.
func Display(token string) string {
	if Check(token) != nil {
		return ""
	}
	return token[:len(prefix)+8] + "…"
}
