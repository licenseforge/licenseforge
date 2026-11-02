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
	token, err := unarmor(license)
	if err != nil {
		return nil, "", err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != Version || !kidRE.MatchString(parts[1]) || parts[2] == "" {
		return nil, "", ErrMalformed
	}
	kid = parts[1]
	sig, err := b64.DecodeString(parts[3])
	if err != nil {
		return nil, "", fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	if _, err := b64.DecodeString(parts[2]); err != nil {
		return nil, "", fmt.Errorf("%w: payload encoding", ErrMalformed)
	}

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
		if len(sig) != ed25519.SignatureSize {
			return nil, "", fmt.Errorf("%w: signature length", ErrMalformed)
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
