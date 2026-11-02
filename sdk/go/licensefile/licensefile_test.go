package licensefile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
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
	Format   string       `json:"format"`
	Note     string       `json:"note"`
	TestSeed string       `json:"test_seed"`
	Keys     []vectorKey  `json:"keys"`
	Cases    []vectorCase `json:"cases"`
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

	return vectorFile{
		Format:   "lf1",
		Note:     "Conformance vectors for the lf1 license format. Keys are TEST ONLY. Every SDK must produce the expected result for every case.",
		TestSeed: string(testSeed),
		Keys: []vectorKey{
			{KID: "test:2026-11", Alg: AlgEd25519, PublicKey: pub},
			{KID: "test:other", Alg: AlgEd25519, PublicKey: pub},
			{KID: "test:rsa", Alg: "rsa-pss-sha256", PublicKey: pub},
		},
		Cases: []vectorCase{
			{Name: "valid_armored", License: beginArmor + "\n" + tok + "\n" + endArmor + "\n", Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "valid_bare", License: tok, Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "valid_wrapped_crlf", License: wrapped.String(), Expect: "valid", KID: "test:2026-11", Payload: payload},
			{Name: "bad_signature_payload_tampered", License: join(parts[0], parts[1], otherPayload, parts[3]), Expect: "bad_signature"},
			{Name: "bad_signature_kid_swapped", License: join(parts[0], "test:other", parts[2], parts[3]), Expect: "bad_signature"},
			{Name: "unknown_key", License: sign("test:missing", payload), Expect: "unknown_key"},
			{Name: "unsupported_alg", License: sign("test:rsa", payload), Expect: "unsupported_alg"},
			{Name: "malformed_version", License: join("lf2", parts[1], parts[2], parts[3]), Expect: "malformed"},
			{Name: "malformed_missing_part", License: join(parts[0], parts[1], parts[2]), Expect: "malformed"},
			{Name: "malformed_extra_part", License: join(tok, "x"), Expect: "malformed"},
			{Name: "malformed_padded_base64", License: join(parts[0], parts[1], parts[2], parts[3]+"=="), Expect: "malformed"},
			{Name: "malformed_noncanonical_base64", License: join(parts[0], parts[1], parts[2], string(sigEnc)), Expect: "malformed"},
			{Name: "malformed_invalid_kid", License: join(parts[0], "bad/kid", parts[2], parts[3]), Expect: "malformed"},
			{Name: "malformed_signature_length", License: join(parts[0], parts[1], parts[2], shortSig), Expect: "malformed"},
			{Name: "malformed_missing_end_armor", License: beginArmor + "\n" + tok + "\n", Expect: "malformed"},
			{Name: "malformed_empty", License: "", Expect: "malformed"},
		},
	}
}

const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func errClass(err error) string {
	for class, target := range map[string]error{
		"malformed": ErrMalformed, "unknown_key": ErrUnknownKey,
		"unsupported_alg": ErrUnsupportedAlg, "bad_signature": ErrBadSignature,
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
	got, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors (run go test -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("spec/vectors/lf1.json is stale; run: go test ./licensefile -update")
	}

	var vf vectorFile
	if err := json.Unmarshal(got, &vf); err != nil {
		t.Fatal(err)
	}
	var keys KeySet
	for _, k := range vf.Keys {
		raw, err := b64.DecodeString(k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, PublicKey{KID: k.KID, Alg: k.Alg, Key: raw})
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
