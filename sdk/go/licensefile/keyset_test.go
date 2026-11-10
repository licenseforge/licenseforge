package licensefile

import (
	"errors"
	"testing"
)

const vecKey = "K1dYPb52fJP3YCWAkHCq-Yto_8Ix32Cj3226U4PqI6k" // spec/vectors/lf1.json test:2026-11

func TestParseKeySet(t *testing.T) {
	ks, err := ParseKeySet([]byte(`[{"kid":"sk_a","alg":"ed25519","public_key":"` + vecKey + `"},{"kid":"sk_b","alg":"ml-dsa-65","public_key":"AAAA"}]`))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := b64.DecodeString(vecKey)
	if len(ks) != 2 || ks[0].KID != "sk_a" || ks[0].Alg != AlgEd25519 || string(ks[0].Key) != string(want) || ks[1].Alg != "ml-dsa-65" || len(ks[1].Key) != 3 {
		t.Fatalf("got %+v", ks)
	}
}

// What the spec leaves to Verify loads as given: an unknown alg, a duplicate
// kid, a key of the wrong length (unsupported_alg / invalid_key_set there).
func TestParseKeySetLoadsAsGiven(t *testing.T) {
	ks, err := ParseKeySet([]byte(`[{"kid":"d","alg":"ed25519","public_key":"AAAA"},{"kid":"d","alg":"ed25519","public_key":"AAAA"},{"kid":"x","alg":"rsa","public_key":"AAAA"},` +
		`{"kid":"e","alg":"","public_key":"AAAA"},{"kid":"z","alg":"ed25519","public_key":""}]`))
	if err != nil || len(ks) != 5 || len(ks[4].Key) != 0 {
		t.Fatalf("got %d keys, %v", len(ks), err)
	}
}

// What can't be represented, or would silently load an empty key, is refused.
func TestParseKeySetRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"not json":           `{`,
		"not an array":       `{"kid":"a","alg":"ed25519","public_key":"AAAA"}`,
		"empty":              `[]`,
		"null":               `null`,
		"trailing data":      `[{"kid":"a","alg":"ed25519","public_key":"AAAA"}] []`,
		"typo in field":      `[{"kid":"a","alg":"ed25519","publicKey":"AAAA"}]`,
		"unknown field":      `[{"kid":"a","alg":"ed25519","public_key":"AAAA","use":"sig"}]`,
		"missing key":        `[{"kid":"a","alg":"ed25519"}]`,
		"missing kid":        `[{"alg":"ed25519","public_key":"AAAA"}]`,
		"missing alg":        `[{"kid":"a","public_key":"AAAA"}]`,
		"padded":             `[{"kid":"a","alg":"ed25519","public_key":"AAA="}]`,
		"standard alphabet":  `[{"kid":"a","alg":"ed25519","public_key":"AA+/"}]`,
		"non-canonical bits": `[{"kid":"a","alg":"ed25519","public_key":"AB"}]`,
		"bad kid":            `[{"kid":"a.b","alg":"ed25519","public_key":"AAAA"}]`,
		// One file, one reading: exact-case fields, none repeated (encoding/json
		// alone folds case, even the Kelvin sign, and keeps the last duplicate).
		"upper-case fields":   `[{"KID":"a","ALG":"ed25519","Public_Key":"AAAA"}]`,
		"kelvin sign":         "[{\"\u212aid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]",
		"repeated key":        `[{"kid":"a","alg":"ed25519","public_key":"AAAA","public_key":"` + vecKey + `"}]`,
		"case-variant repeat": `[{"kid":"a","alg":"ed25519","public_key":"AAAA","PUBLIC_KEY":"` + vecKey + `"}]`,
		"repeated kid":        `[{"kid":"a","kid":"b","alg":"ed25519","public_key":"AAAA"}]`,
		"null field":          `[{"kid":"a","alg":null,"public_key":"AAAA"}]`,
		"number field":        `[{"kid":"a","alg":1,"public_key":"AAAA"}]`,
		"null entry":          `[null]`,
		"newline in key":      `[{"kid":"a","alg":"ed25519","public_key":"AA\nAA"}]`,
		"CR in key":           `[{"kid":"a","alg":"ed25519","public_key":"AA\rAA"}]`,
		"long non-canonical":  `[{"kid":"a","alg":"ed25519","public_key":"` + vecKey[:len(vecKey)-1] + `l"}]`,
		"long padded":         `[{"kid":"a","alg":"ed25519","public_key":"` + vecKey + `="}]`,
		"lone surrogate":      `[{"kid":"a","alg":"\ud800","public_key":"AAAA"}]`,
		"invalid UTF-8":       "[{\"kid\":\"a\",\"alg\":\"ed\xff\",\"public_key\":\"AAAA\"}]",
		"BOM":                 "\ufeff[{\"kid\":\"a\",\"alg\":\"ed25519\",\"public_key\":\"AAAA\"}]",
	} {
		if _, err := ParseKeySet([]byte(in)); !errors.Is(err, ErrInvalidKeySet) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
