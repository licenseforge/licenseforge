package licensefile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// ParseKeySet reads a trusted key set in the license format's JSON form: an
// array of objects with exactly the fields "kid", "alg" and "public_key"
// (case-sensitive, no duplicates), public_key in base64url without padding (as
// the LicenseForge dashboard shows it). As the spec says, keys load as given:
// an unknown or empty alg, a duplicate kid or a key of the wrong length
// surface in Verify (ErrUnsupportedAlg, ErrInvalidKeySet). What can't be
// represented is ErrInvalidKeySet here: malformed JSON or UTF-8, other,
// missing or repeated fields, a kid outside the spec's pattern, public_key
// not canonical base64url, an empty set.
func ParseKeySet(data []byte) (KeySet, error) {
	bad := func(format string, a ...any) (KeySet, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{ErrInvalidKeySet}, a...)...)
	}
	// The payload's rules (exact-case keys, no duplicates, no lone surrogates),
	// so one file can't read as different keys to different parsers.
	if !utf8.Valid(data) {
		return bad("not valid UTF-8")
	}
	if err := checkSurrogates(data); err != nil {
		return bad("%v", err)
	}
	var raw []json.RawMessage
	d := json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&raw); err != nil {
		return bad("%v", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return bad("data after the key set")
	}
	if len(raw) == 0 {
		return bad("no keys")
	}
	ks := make(KeySet, 0, len(raw))
	for i, e := range raw {
		m, err := object(e, false)
		if err != nil {
			return bad("key %d: %v", i, err)
		}
		if len(m) != 3 {
			return bad("key %d needs exactly kid, alg and public_key", i)
		}
		var f [3]string
		for j, name := range []string{"kid", "alg", "public_key"} {
			v, ok := m[name]
			if !ok {
				return bad("key %d needs exactly kid, alg and public_key", i)
			}
			if f[j], err = stringValue(v, name); err != nil {
				return bad("key %d: %v", i, err)
			}
		}
		kid, alg, pub := f[0], f[1], f[2]
		if !kidRE.MatchString(kid) {
			return bad("key %d: kid isn't 1-128 of [A-Za-z0-9_:-]", i)
		}
		// Strict still skips CR and LF; the spec's base64url has none.
		key, err := b64.DecodeString(pub)
		if err != nil || strings.ContainsAny(pub, "\r\n") {
			return bad("key %d: public_key isn't canonical base64url without padding", i)
		}
		ks = append(ks, PublicKey{KID: kid, Alg: alg, Key: key})
	}
	return ks, nil
}
