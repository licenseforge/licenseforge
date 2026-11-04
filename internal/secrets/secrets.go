// Package secrets encrypts values at rest and derives lookup hashes with a
// keyring of master keys (ADR-0025).
//
// Limits: AES-GCM with random 96-bit nonces is safe for up to 2^32
// encryptions per key (NIST SP 800-38D). Rotate the active key well before
// that; rotation is an operator action, not automatic.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// KeySize is the master key length in bytes.
const KeySize = 32

var (
	// ErrDecrypt means a ciphertext is invalid, was modified, or is bound to
	// another context (purpose, tenant or row).
	ErrDecrypt = errors.New("secrets: cannot decrypt")
	// ErrUnknownKey means a ciphertext was made with a key not in the keyring.
	ErrUnknownKey = errors.New("secrets: unknown key id")
	// ErrEmptyKeyring means the Keyring wasn't built with ParseKeyring.
	ErrEmptyKeyring = errors.New("secrets: empty keyring; use ParseKeyring")

	kidRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	b64   = base64.RawURLEncoding.Strict()
)

// Purpose names what a value is, e.g. a license key. It is part of every
// ciphertext's binding and lookup hash, so values of different purposes can't
// be confused.
type Purpose string

// Purposes in use.
const (
	PurposeLicenseKey          Purpose = "license_key"
	PurposeIdempotencyResponse Purpose = "idempotency_response" // stored response bodies (internal/idempotency)
)

// Binding is what a ciphertext belongs to. Decrypt needs the same binding as
// Encrypt, so a ciphertext copied to another row, tenant or purpose fails.
type Binding struct {
	Purpose  Purpose
	TenantID string
	RowID    string
}

// encode is length-prefixed, so no field content can be read two ways.
func (b Binding) encode(kid string) ([]byte, error) {
	if b.Purpose == "" || b.TenantID == "" || b.RowID == "" {
		return nil, errors.New("secrets: binding needs purpose, tenant and row")
	}
	out := []byte("v1")
	for _, f := range []string{kid, string(b.Purpose), b.TenantID, b.RowID} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out, nil
}

type key struct {
	id         string
	enc, check []byte
}

// Keyring holds master keys. The first is active for new encryption; all of
// them decrypt and produce lookup hashes, so keys can be rotated without
// downtime. Build it with ParseKeyring.
type Keyring struct{ keys []key }

// ParseKeyring parses "id=base64key[,id=base64key...]", e.g. the
// LICENSEFORGE_MASTER_KEYS variable. Each key is exactly 32 random bytes in
// padded standard base64, as printed by `openssl rand -base64 32`. Errors never
// contain key material.
func ParseKeyring(s string) (*Keyring, error) {
	kr := &Keyring{}
	seen := map[string]bool{}
	for i, part := range strings.Split(strings.TrimSpace(s), ",") {
		id, enc, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !kidRE.MatchString(id) {
			return nil, fmt.Errorf("secrets: entry %d must be id=base64key with an id matching %s", i+1, kidRE)
		}
		if seen[id] {
			return nil, fmt.Errorf("secrets: duplicate key id %q", id)
		}
		seen[id] = true
		raw, err := base64.StdEncoding.Strict().DecodeString(enc)
		// Re-encoding must give the input back: one spelling per key (the
		// decoder alone skips embedded newlines).
		if err != nil || len(raw) != KeySize || base64.StdEncoding.EncodeToString(raw) != enc {
			return nil, fmt.Errorf("secrets: key %q must be %d bytes in padded standard base64 (openssl rand -base64 32)", id, KeySize)
		}
		k, err := derive(id, raw)
		if err != nil {
			return nil, err
		}
		kr.keys = append(kr.keys, k)
	}
	return kr, nil
}

// derive splits a master key into independent encryption and lookup subkeys.
func derive(id string, master []byte) (key, error) {
	enc, err := hkdf.Key(sha256.New, master, nil, "licenseforge secrets v1 encrypt", 32)
	if err != nil {
		return key{}, err
	}
	check, err := hkdf.Key(sha256.New, master, nil, "licenseforge secrets v1 lookup", 32)
	if err != nil {
		return key{}, err
	}
	return key{id: id, enc: enc, check: check}, nil
}

// ActiveID is the key ID new ciphertexts use ("" for an empty keyring).
func (kr *Keyring) ActiveID() string {
	if kr == nil || len(kr.keys) == 0 {
		return ""
	}
	return kr.keys[0].id
}

func (kr *Keyring) active() (key, error) {
	if kr == nil || len(kr.keys) == 0 {
		return key{}, ErrEmptyKeyring
	}
	return kr.keys[0], nil
}

func (kr *Keyring) find(id string) (key, bool) {
	for _, k := range kr.keys {
		if k.id == id {
			return k, true
		}
	}
	return key{}, false
}

func gcm(k key) (cipher.AEAD, error) {
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return nil, err
	}
	// Nonce generated inside the AEAD: the FIPS 140-3 approved mode.
	return cipher.NewGCMWithRandomNonce(block)
}

// Encrypt encrypts plaintext with the active key, bound to b. The result is
// "v1.<key id>.<base64url>".
func (kr *Keyring) Encrypt(plaintext []byte, b Binding) (string, error) {
	k, err := kr.active()
	if err != nil {
		return "", err
	}
	ad, err := b.encode(k.id)
	if err != nil {
		return "", err
	}
	aead, err := gcm(k)
	if err != nil {
		return "", err
	}
	return "v1." + k.id + "." + b64.EncodeToString(aead.Seal(nil, nil, plaintext, ad)), nil
}

// Decrypt reverses Encrypt with the key named in the ciphertext; b must equal
// the binding used to encrypt.
func (kr *Keyring) Decrypt(ciphertext string, b Binding) ([]byte, error) {
	if kr == nil || len(kr.keys) == 0 {
		return nil, ErrEmptyKeyring
	}
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 3 || parts[0] != "v1" || !kidRE.MatchString(parts[1]) {
		return nil, ErrDecrypt
	}
	k, ok := kr.find(parts[1])
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownKey, parts[1]) // validated by kidRE: safe to log
	}
	sealed, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrDecrypt
	}
	ad, err := b.encode(k.id)
	if err != nil {
		return nil, err
	}
	aead, err := gcm(k)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nil, sealed, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// LookupHash is the hex HMAC-SHA256 of value under the active key's lookup
// subkey, stored next to a ciphertext. Callers pass the value's canonical form
// (license keys: licensekey.Normalize), or equal values won't match.
func (kr *Keyring) LookupHash(p Purpose, value []byte) (string, error) {
	k, err := kr.active()
	if err != nil {
		return "", err
	}
	return lookup(k, p, value), nil
}

// LookupHashes returns value's lookup hash under every key, for queries that
// must match rows hashed before a rotation. Rows should be re-hashed under the
// active key after a rotation, so old keys can eventually be removed.
func (kr *Keyring) LookupHashes(p Purpose, value []byte) []string {
	if kr == nil {
		return nil
	}
	out := make([]string, len(kr.keys))
	for i, k := range kr.keys {
		out[i] = lookup(k, p, value)
	}
	return out
}

func lookup(k key, p Purpose, value []byte) string {
	h := hmac.New(sha256.New, k.check)
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p))))
	h.Write([]byte(p))
	h.Write(value)
	return hex.EncodeToString(h.Sum(nil))
}
