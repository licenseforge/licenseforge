package licensefile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// ParseKeySet reads a trusted key set in the license format's JSON form: an
// array of {"kid", "alg", "public_key"} with public_key in base64url without
// padding (as the LicenseForge dashboard shows it). As the spec says, an
// unknown alg, a duplicate kid or a key of the wrong length load as given and
// surface in Verify (ErrUnsupportedAlg, ErrInvalidKeySet). What can't be
// represented, or would silently load an empty key, is ErrInvalidKeySet here:
// malformed JSON, unknown or missing fields, a kid outside the spec's
// pattern, non-canonical base64url, an empty set.
func ParseKeySet(data []byte) (KeySet, error) {
	bad := func(format string, a ...any) (KeySet, error) {
		return nil, fmt.Errorf("%w: "+format, append([]any{ErrInvalidKeySet}, a...)...)
	}
	var raw []struct {
		KID       *string `json:"kid"`
		Alg       *string `json:"alg"`
		PublicKey *string `json:"public_key"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
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
	for i, k := range raw {
		switch {
		case k.KID == nil || k.Alg == nil || k.PublicKey == nil:
			return bad("key %d needs kid, alg and public_key", i)
		case !kidRE.MatchString(*k.KID):
			return bad("key %d: kid %q isn't 1-128 of [A-Za-z0-9_:-]", i, *k.KID)
		case *k.Alg == "":
			return bad("key %d: empty alg", i)
		}
		key, err := b64.DecodeString(*k.PublicKey)
		if err != nil || len(key) == 0 {
			return bad("key %q: public_key must be non-empty base64url without padding", *k.KID)
		}
		ks = append(ks, PublicKey{KID: *k.KID, Alg: *k.Alg, Key: key})
	}
	return ks, nil
}
