// Package secrets encrypts values at rest and derives lookup hashes with a
// keyring of master keys (ADR-0025).
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// KeySize is the master key length in bytes.
const KeySize = 32

var (
	// ErrDecrypt means a ciphertext is invalid, was modified, or belongs to
	// another row (additional data mismatch).
	ErrDecrypt = errors.New("secrets: cannot decrypt")
	// ErrUnknownKey means a ciphertext was made with a key not in the keyring.
	ErrUnknownKey = errors.New("secrets: unknown key id")

	kidRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	b64   = base64.RawURLEncoding.Strict()
)

type key struct {
	id         string
	enc, check []byte
}

// Keyring holds master keys. The first is active for new encryption; all of
// them decrypt and produce lookup hashes, so keys can be rotated without
// downtime.
type Keyring struct{ keys []key }

// ParseKeyring parses "id=base64key[,id=base64key...]" (standard or URL-safe
// base64 of 32 random bytes), e.g. the LICENSEFORGE_MASTER_KEYS variable.
func ParseKeyring(s string) (*Keyring, error) {
	kr := &Keyring{}
	seen := map[string]bool{}
	for part := range strings.SplitSeq(strings.TrimSpace(s), ",") {
		id, enc, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !kidRE.MatchString(id) {
			return nil, fmt.Errorf("secrets: entry %q must be id=base64key with id matching %s", redact(part), kidRE)
		}
		if seen[id] {
			return nil, fmt.Errorf("secrets: duplicate key id %q", id)
		}
		seen[id] = true
		raw, err := decodeKey(enc)
		if err != nil || len(raw) != KeySize {
			return nil, fmt.Errorf("secrets: key %q must be %d bytes of base64", id, KeySize)
		}
		k, err := derive(id, raw)
		if err != nil {
			return nil, err
		}
		kr.keys = append(kr.keys, k)
	}
	if len(kr.keys) == 0 {
		return nil, errors.New("secrets: empty keyring")
	}
	return kr, nil
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// redact keeps an entry's id for error messages and hides the key material.
func redact(entry string) string {
	id, _, _ := strings.Cut(entry, "=")
	return strings.TrimSpace(id) + "=…"
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

// ActiveID is the key ID new ciphertexts use.
func (kr *Keyring) ActiveID() string { return kr.keys[0].id }

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
	// Random nonce generated inside the AEAD: the FIPS 140-3 approved mode.
	return cipher.NewGCMWithRandomNonce(block)
}

// Encrypt encrypts plaintext with the active key. ad (additional data) binds
// the ciphertext to its context, e.g. purpose, tenant and row ID; Decrypt needs
// the same ad. The result is "v1.<key id>.<base64url>".
func (kr *Keyring) Encrypt(plaintext, ad []byte) (string, error) {
	k := kr.keys[0]
	aead, err := gcm(k)
	if err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, nil, plaintext, adFor(k.id, ad))
	return "v1." + k.id + "." + b64.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt with the key named in the ciphertext.
func (kr *Keyring) Decrypt(ciphertext string, ad []byte) ([]byte, error) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return nil, ErrDecrypt
	}
	k, ok := kr.find(parts[1])
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownKey, parts[1])
	}
	sealed, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, ErrDecrypt
	}
	aead, err := gcm(k)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, nil, sealed, adFor(k.id, ad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// adFor also binds the key ID and format version, so a ciphertext can't be
// relabelled with another key ID.
func adFor(kid string, ad []byte) []byte {
	return append([]byte("v1|"+kid+"|"), ad...)
}

// LookupHash is the HMAC-SHA256 (hex) of value under the active key's lookup
// subkey, for storing alongside a ciphertext.
func (kr *Keyring) LookupHash(purpose string, value []byte) string {
	return lookup(kr.keys[0], purpose, value)
}

// LookupHashes returns value's lookup hash under every key, for queries that
// must match rows hashed before a rotation.
func (kr *Keyring) LookupHashes(purpose string, value []byte) []string {
	out := make([]string, len(kr.keys))
	for i, k := range kr.keys {
		out[i] = lookup(k, purpose, value)
	}
	return out
}

func lookup(k key, purpose string, value []byte) string {
	h := hmac.New(sha256.New, k.check)
	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write(value)
	return fmt.Sprintf("%x", h.Sum(nil))
}
