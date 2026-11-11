// Package licensefile signs and verifies LicenseForge license files (format lf1).
//
// An lf1 license is
//
//	lf1.<kid>.<base64url(payload)>.<base64url(signature)>
//
// optionally wrapped in "-----BEGIN LICENSEFORGE LICENSE-----" armor. The
// signature covers the ASCII bytes "lf1.<kid>.<base64url(payload)>", so the
// format version and key ID are authenticated. The signing algorithm comes
// from the trusted key, never from the file. See spec/license-format.md.
package licensefile

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	// Version is the format prefix produced and accepted by this package.
	Version = "lf1"
	// MaxSize is the largest encoded license accepted, in bytes.
	MaxSize = 64 << 10

	beginArmor = "-----BEGIN LICENSEFORGE LICENSE-----"
	endArmor   = "-----END LICENSEFORGE LICENSE-----"
)

// Supported key algorithms.
const AlgEd25519 = "ed25519"

// Error classes shared by all SDKs and the conformance vectors.
var (
	ErrMalformed      = errors.New("licensefile: malformed")
	ErrUnknownKey     = errors.New("licensefile: unknown key")
	ErrUnsupportedAlg = errors.New("licensefile: unsupported algorithm")
	ErrBadSignature   = errors.New("licensefile: bad signature")
	// ErrInvalidKeySet is a configuration error in the trusted keys (duplicate
	// kid or wrong key length), not a verdict about the license.
	ErrInvalidKeySet = errors.New("licensefile: invalid key set")
)

// PublicKey is a trusted verification key. Alg binds the algorithm to the key.
type PublicKey struct {
	KID string
	Alg string
	Key []byte
}

// KeySet holds the trusted keys an application accepts, usually embedded at build time.
type KeySet []PublicKey

// find returns the key for kid. Duplicate kids are a configuration error.
func (ks KeySet) find(kid string) (PublicKey, error) {
	var found []PublicKey
	for _, k := range ks {
		if k.KID == kid {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 0:
		return PublicKey{}, ErrUnknownKey
	case 1:
		return found[0], nil
	default:
		return PublicKey{}, fmt.Errorf("%w: duplicate kid %q", ErrInvalidKeySet, kid)
	}
}

var (
	kidRE = regexp.MustCompile(`^[A-Za-z0-9_:-]{1,128}$`)
	b64   = base64.RawURLEncoding.Strict()
)

// Sign returns an armored lf1 license for payload, signed by signer under kid.
// signer is any crypto.Signer holding an Ed25519 key (in-memory or KMS-backed).
func Sign(kid string, signer crypto.Signer, payload []byte) (string, error) {
	if !kidRE.MatchString(kid) {
		return "", fmt.Errorf("%w: invalid kid", ErrMalformed)
	}
	if len(payload) == 0 {
		return "", fmt.Errorf("%w: empty payload", ErrMalformed)
	}
	if _, ok := signer.Public().(ed25519.PublicKey); !ok {
		return "", ErrUnsupportedAlg
	}
	msg := Version + "." + kid + "." + b64.EncodeToString(payload)
	sig, err := signer.Sign(rand.Reader, []byte(msg), crypto.Hash(0))
	if err != nil {
		return "", fmt.Errorf("licensefile: sign: %w", err)
	}
	out := beginArmor + "\n" + msg + "." + b64.EncodeToString(sig) + "\n" + endArmor + "\n"
	if len(out) > MaxSize {
		return "", fmt.Errorf("%w: license exceeds %d bytes", ErrMalformed, MaxSize)
	}
	return out, nil
}

// Verify checks the license's envelope and signature against keys and returns
// the verified payload and the key ID used. Checks run in the order defined by
// the spec, so every SDK reports the same error class. The payload bytes are
// returned only after the signature is valid; callers parse them afterwards.
// Verify does not check expiry, binding or other claims.
func Verify(license string, keys KeySet) (payload []byte, kid string, err error) {
	if len(license) > MaxSize {
		return nil, "", fmt.Errorf("%w: too large", ErrMalformed)
	}
	parts, sig, err := envelope(license)
	if err != nil {
		return nil, "", err
	}
	kid = parts[1]

	key, err := keys.find(kid)
	if err != nil {
		return nil, "", err
	}
	msg := []byte(parts[0] + "." + parts[1] + "." + parts[2])
	switch key.Alg {
	case AlgEd25519:
		if len(key.Key) != ed25519.PublicKeySize {
			return nil, "", fmt.Errorf("%w: ed25519 key for %q has length %d", ErrInvalidKeySet, kid, len(key.Key))
		}
		if weakEd25519(key.Key) {
			return nil, "", fmt.Errorf("%w: ed25519 key for %q is not a canonical, full-order point", ErrInvalidKeySet, kid)
		}
		if len(sig) != ed25519.SignatureSize {
			return nil, "", fmt.Errorf("%w: signature length", ErrMalformed)
		}
		// A weak R (spec): with R = identity and S = k·a, cofactorless
		// verification (crypto/ed25519) accepts and OpenSSL refuses.
		if weakEd25519(sig[:32]) {
			return nil, "", ErrBadSignature
		}
		// crypto/ed25519 rejects non-canonical S (S >= L), as the spec requires.
		if !ed25519.Verify(ed25519.PublicKey(key.Key), msg, sig) {
			return nil, "", ErrBadSignature
		}
	default:
		return nil, "", ErrUnsupportedAlg
	}

	payload, _ = b64.DecodeString(parts[2]) // validated above
	return payload, kid, nil
}

// smallOrder are the encodings of the eight points of order dividing 8 on
// edwards25519 (spec: weak keys). With one of them as the public key, a
// signature with R and S chosen to match verifies for any message under
// crypto/ed25519 (cofactorless verification), so the key set refuses them.
var smallOrder = [8]string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

// weakEd25519 reports a public key the spec refuses: a non-canonical
// encoding (y >= p, or the negative-zero x of y = 1 or y = p-1) or a
// small-order point. key is 32 bytes.
func weakEd25519(key []byte) bool {
	h := hex.EncodeToString(key)
	for _, s := range smallOrder {
		if h == s {
			return true
		}
	}
	// y is the little-endian value without the top bit; p = 2^255-19 is
	// ed ff .. ff 7f. y >= p only if bytes 1..30 are ff, byte 31 is 7f and
	// byte 0 is at least ed.
	y31 := key[31] & 0x7f
	high := y31 == 0x7f
	for _, b := range key[1:31] {
		high = high && b == 0xff
	}
	if high && key[0] >= 0xed {
		return true
	}
	// x = 0 (y = 1 or y = p-1) with the sign bit set: negative zero.
	if key[31]&0x80 != 0 {
		one := key[0] == 1 && y31 == 0
		minusOne := key[0] == 0xec && high
		for _, b := range key[1:31] {
			one = one && b == 0
		}
		if one || minusOne {
			return true
		}
	}
	return false
}

// envelope applies the spec's envelope rules up to the key lookup: armor,
// four parts, version, kid, canonical base64url payload and signature.
func envelope(license string) (parts []string, sig []byte, err error) {
	token, err := unarmor(license)
	if err != nil {
		return nil, nil, err
	}
	parts = strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != Version || !kidRE.MatchString(parts[1]) || parts[2] == "" {
		return nil, nil, ErrMalformed
	}
	if sig, err = b64.DecodeString(parts[3]); err != nil {
		return nil, nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	if _, err := b64.DecodeString(parts[2]); err != nil {
		return nil, nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	return parts, sig, nil
}

// unarmor applies the spec's whitespace, BOM and armor rules and returns the bare token.
func unarmor(s string) (string, error) {
	s = strings.TrimPrefix(s, "\uFEFF")
	s = strings.Trim(s, specWhitespace)
	if body, ok := strings.CutPrefix(s, beginArmor); ok {
		if body, ok = strings.CutSuffix(body, endArmor); !ok {
			return "", fmt.Errorf("%w: missing end armor", ErrMalformed)
		}
		s = body
	}
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune(specWhitespace, r) {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "", ErrMalformed
	}
	return s, nil
}

// specWhitespace is the only whitespace the spec allows: SP, HT, CR, LF.
const specWhitespace = " \t\r\n"
