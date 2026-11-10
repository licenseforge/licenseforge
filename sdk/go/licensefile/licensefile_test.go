package licensefile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/fips140"
	"encoding/json"
	"errors"
	"flag"
	"math/big"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate spec/vectors/lf1.json")

const vectorsPath = "../../../spec/vectors/lf1.json"

// Fixed test-only seed so vectors are reproducible (Ed25519 signing is deterministic).
var testSeed = []byte("licenseforge-test-vector-seed-01")

type vectorKey struct {
	KID       string `json:"kid"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"`
}

type vectorCase struct {
	Name    string `json:"name"`
	License string `json:"license"`
	Expect  string `json:"expect"`
	KID     string `json:"kid,omitempty"`
	Payload string `json:"payload,omitempty"`
}

type vectorFile struct {
	Format      string       `json:"format"`
	Note        string       `json:"note"`
	Conventions []string     `json:"conventions"`
	TestSeed    string       `json:"test_seed"`
	Keys        []vectorKey  `json:"keys"`
	Cases       []vectorCase `json:"cases"`
}

func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(testSeed)
	pub := b64.EncodeToString(priv.Public().(ed25519.PublicKey))
	payload := `{"v":1,"lid":"lic_test","product":"acme-db","exp":"2027-01-01T00:00:00Z"}`

	sign := func(kid, p string) string {
		armored, err := Sign(kid, priv, []byte(p))
		if err != nil {
			t.Fatal(err)
		}
		tok, _ := unarmor(armored)
		return tok
	}
	tok := sign("test:2026-11", payload)
	parts := strings.Split(tok, ".")
	join := func(p ...string) string { return strings.Join(p, ".") }

	// Wrapped at 64 columns with CRLF line endings.
	var wrapped strings.Builder
	wrapped.WriteString(beginArmor + "\r\n")
	for i := 0; i < len(tok); i += 64 {
		wrapped.WriteString(tok[i:min(i+64, len(tok))] + "\r\n")
	}
	wrapped.WriteString(endArmor + "\r\n")

	// Non-canonical signature: set a trailing bit that must be zero.
	sigEnc := []byte(parts[3])
	last := strings.IndexByte(b64Alphabet, sigEnc[len(sigEnc)-1])
	sigEnc[len(sigEnc)-1] = b64Alphabet[last|1]

	shortSig := b64.EncodeToString(make([]byte, 63))
	otherPayload := b64.EncodeToString([]byte(strings.Replace(payload, "acme-db", "acme-xx", 1)))

	// Non-canonical payload encoding (payload length is not a multiple of 3, so trailing bits exist).
	if len(payload)%3 == 0 {
		t.Fatal("payload length must not be a multiple of 3")
	}
	payEnc := []byte(parts[2])
	payEnc[len(payEnc)-1] = b64Alphabet[strings.IndexByte(b64Alphabet, payEnc[len(payEnc)-1])|1]

	// Malleated signature: S' = S + L encodes the same group element but is non-canonical.
	sig, _ := b64.DecodeString(parts[3])
	sBig := new(big.Int).SetBytes(reverse(sig[32:]))
	order, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	sBig.Add(sBig, order)
	malleated := append(append([]byte{}, sig[:32]...), reverse(sBig.FillBytes(make([]byte, 32)))...)

	// Unknown kid combined with a second fault, to pin error precedence.
	missingTok := sign("test:missing", payload)
	mp := strings.Split(missingTok, ".")
	rp := strings.Split(sign("test:rsa", payload), ".")

	// Size limit counts bytes: pad with spaces to exactly MaxSize bytes (valid),
	// and to MaxSize+1 bytes with a leading 3-byte BOM (malformed; a counter of
	// characters instead of bytes would wrongly accept it).
	atLimit := tok + strings.Repeat(" ", MaxSize-len(tok))
	overLimitBOM := "\uFEFF" + tok + strings.Repeat(" ", MaxSize+1-3-len(tok))

	return vectorFile{
		Format: "lf1",
		Note:   "Conformance vectors for the lf1 license format (spec/license-format.md). Keys are TEST ONLY. Every SDK must produce the expected result for every case.",
		Conventions: []string{
			"public_key is base64url without padding (RFC 4648 section 5).",
			"test_seed is the raw ASCII bytes used as the 32-byte Ed25519 seed; signing the valid payload under kid test:2026-11 reproduces the valid licenses exactly.",
			"Keys are loaded as given; an unknown alg or a bad key must not fail at load time but surface during Verify (unsupported_alg / invalid_key_set).",
			"expect is the error class of the first failing step in the spec's verify algorithm, or valid.",
		},
		TestSeed: string(testSeed),
		Keys: []vectorKey{
			{KID: "test:2026-11", Alg: AlgEd25519, PublicKey: pub},
			{KID: "test:other", Alg: AlgEd25519, PublicKey: pub},
			{KID: "test:rsa", Alg: "rsa-pss-sha256", PublicKey: pub},
			{KID: "test:dup", Alg: AlgEd25519, PublicKey: pub},
			{KID: "test:dup", Alg: AlgEd25519, PublicKey: pub},
			{KID: "test:short", Alg: AlgEd25519, PublicKey: b64.EncodeToString(priv.Public().(ed25519.PublicKey)[:31])},
		},
		Cases: []vectorCase{
			{Name: "valid_armored", License: beginArmor + "\n" + tok + "\n" + endArmor + "\n", Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "valid_bare", License: tok, Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "valid_wrapped_crlf", License: wrapped.String(), Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "valid_bare_trailing_lf", License: tok + "\n", Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "valid_bom_prefix", License: "\uFEFF" + beginArmor + "\n" + tok + "\n" + endArmor + "\n", Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "valid_armor_single_line", License: beginArmor + tok + endArmor, Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "bad_signature_noncanonical_s", License: join(parts[0], parts[1], parts[2], b64.EncodeToString(malleated)), Expect: "bad_signature"},
			{Name: "unknown_key_with_short_signature", License: join(mp[0], mp[1], mp[2], shortSig), Expect: "unknown_key"},
			{Name: "unsupported_alg_with_short_signature", License: join(rp[0], rp[1], rp[2], shortSig), Expect: "unsupported_alg"},
			{Name: "malformed_wins_over_unknown_key", License: join(mp[0], mp[1], mp[2], mp[3]+"=="), Expect: "malformed"},
			{Name: "invalid_key_set_duplicate_kid", License: sign("test:dup", payload), Expect: "invalid_key_set"},
			{Name: "invalid_key_set_short_key", License: sign("test:short", payload), Expect: "invalid_key_set"},
			{Name: "bad_signature_payload_tampered", License: join(parts[0], parts[1], otherPayload, parts[3]), Expect: "bad_signature"},
			{Name: "bad_signature_kid_swapped", License: join(parts[0], "test:other", parts[2], parts[3]), Expect: "bad_signature"},
			{Name: "unknown_key", License: sign("test:missing", payload), Expect: "unknown_key"},
			{Name: "unsupported_alg", License: sign("test:rsa", payload), Expect: "unsupported_alg"},
			{Name: "malformed_version", License: join("lf2", parts[1], parts[2], parts[3]), Expect: "malformed"},
			{Name: "malformed_missing_part", License: join(parts[0], parts[1], parts[2]), Expect: "malformed"},
			{Name: "malformed_extra_part", License: join(tok, "x"), Expect: "malformed"},
			{Name: "malformed_padded_base64", License: join(parts[0], parts[1], parts[2], parts[3]+"=="), Expect: "malformed"},
			{Name: "malformed_noncanonical_base64", License: join(parts[0], parts[1], parts[2], string(sigEnc)), Expect: "malformed"},
			{Name: "malformed_noncanonical_payload_base64", License: join(parts[0], parts[1], string(payEnc), parts[3]), Expect: "malformed"},
			{Name: "malformed_empty_payload", License: join(parts[0], parts[1], "", parts[3]), Expect: "malformed"},
			{Name: "malformed_nbsp_inside", License: tok[:10] + "\u00a0" + tok[10:], Expect: "malformed"},
			{Name: "malformed_bom_inside", License: tok[:10] + "\uFEFF" + tok[10:], Expect: "malformed"},
			{Name: "malformed_u2028_inside", License: tok[:10] + "\u2028" + tok[10:], Expect: "malformed"},
			{Name: "valid_at_size_limit", License: atLimit, Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "malformed_over_size_limit_bytes", License: overLimitBOM, Expect: "malformed"},
			{Name: "malformed_empty_armor", License: beginArmor + "\n" + endArmor + "\n", Expect: "malformed"},
			{Name: "malformed_invalid_kid", License: join(parts[0], "bad/kid", parts[2], parts[3]), Expect: "malformed"},
			{Name: "malformed_signature_length", License: join(parts[0], parts[1], parts[2], shortSig), Expect: "malformed"},
			{Name: "malformed_missing_end_armor", License: beginArmor + "\n" + tok + "\n", Expect: "malformed"},
			{Name: "malformed_empty", License: "", Expect: "malformed"},
		},
	}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func errClass(err error) string {
	for class, target := range map[string]error{
		"malformed": ErrMalformed, "unknown_key": ErrUnknownKey,
		"unsupported_alg": ErrUnsupportedAlg, "bad_signature": ErrBadSignature,
		"invalid_key_set": ErrInvalidKeySet,
	} {
		if errors.Is(err, target) {
			return class
		}
	}
	if err == nil {
		return "valid"
	}
	return "unexpected: " + err.Error()
}

// TestVectors runs the shared conformance vectors exactly as other SDKs do,
// and fails if the file is out of date with the generator.
func TestVectors(t *testing.T) {
	want, err := json.MarshalIndent(buildVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if *update {
		if err := os.WriteFile(vectorsPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Skip only when the module is tested outside the repository (no repo root);
	// inside the repo a missing vector file is a failure.
	if _, err := os.Stat("../../../go.mod"); errors.Is(err, os.ErrNotExist) {
		t.Skip("not inside the licenseforge repository; conformance vectors unavailable")
	}
	got, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("spec/vectors/lf1.json is stale; run: go test ./licensefile -update")
	}

	var vf vectorFile
	if err := json.Unmarshal(got, &vf); err != nil {
		t.Fatal(err)
	}
	// The vectors' key list loads through ParseKeySet, as a build would load
	// the dashboard's: unknown algs, duplicates and short keys included.
	var set struct {
		Keys json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(got, &set); err != nil {
		t.Fatal(err)
	}
	keys, err := ParseKeySet(set.Keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range vf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			payload, kid, err := Verify(c.License, keys)
			if got := errClass(err); got != c.Expect {
				t.Fatalf("got %s, want %s", got, c.Expect)
			}
			if c.Expect == "valid" && (string(payload) != c.Payload || kid != c.KID) {
				t.Fatalf("got payload %q kid %q, want %q %q", payload, kid, c.Payload, c.KID)
			}
		})
	}
}

func TestVerifyRejectsOversizedInput(t *testing.T) {
	if _, _, err := Verify(strings.Repeat("a", MaxSize+1), nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestSignRejectsInvalidKID(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed)
	if _, err := Sign("bad.kid", priv, []byte("{}")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

func TestSignLimits(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed)
	if _, err := Sign("k", priv, nil); !errors.Is(err, ErrMalformed) {
		t.Errorf("empty payload: got %v, want ErrMalformed", err)
	}
	if _, err := Sign("k", priv, make([]byte, 49<<10)); !errors.Is(err, ErrMalformed) {
		t.Errorf("oversized payload: got %v, want ErrMalformed", err)
	}
}

// TestFIPSModeWhenRequested guards the CI FIPS job: if the build asked for the
// FIPS 140-3 module, it must actually be active.
func TestFIPSModeWhenRequested(t *testing.T) {
	if v := os.Getenv("GOFIPS140"); v != "" && v != "off" && !fips140.Enabled() {
		t.Fatalf("GOFIPS140=%s but FIPS 140-3 mode is not enabled", v)
	}
}
