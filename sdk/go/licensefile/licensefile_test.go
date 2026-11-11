package licensefile

import (
	"bytes"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

	// A chosen R with S = k·a mod L, k = SHA-512(R || A || M) mod L: what the
	// key's holder can make. With R = identity, Go's cofactorless check
	// accepts it and OpenSSL refuses; the spec refuses every weak R.
	expanded := sha512.Sum512(testSeed)
	expanded[0] &= 248
	expanded[31] &= 127
	expanded[31] |= 64
	scalar := new(big.Int).SetBytes(reverse(expanded[:32]))
	chosenR := func(rHex string) string {
		r := weakKey(rHex)
		h := sha512.New()
		h.Write(r)
		h.Write(priv.Public().(ed25519.PublicKey))
		h.Write([]byte(join(parts[0], parts[1], parts[2])))
		k := new(big.Int).SetBytes(reverse(h.Sum(nil)))
		s := k.Mul(k.Mod(k, order), scalar)
		s.Mod(s, order)
		return join(parts[0], parts[1], parts[2], b64.EncodeToString(append(r, reverse(s.FillBytes(make([]byte, 32)))...)))
	}

	// A mixed-order key A' = A + T8 passes the weak-key rule. With R = T8 and a
	// payload ground so that k ≡ 7 (mod 8), S = k·a verifies cofactorless
	// (Go, SunEC) while OpenSSL refuses: only refusing every small-order R,
	// not just the identity, makes the SDKs agree.
	t8 := weakKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	mixedKey := edEncode(edAdd(edDecode(priv.Public().(ed25519.PublicKey)), edDecode(t8)))
	var mixedOrderR string
	for n := 0; ; n++ {
		p := b64.EncodeToString([]byte(fmt.Sprintf(`{"v":1,"lid":"lic_test","product":"acme-db","n":%d}`, n)))
		msg := join("lf1", "test:mixed-order", p)
		h := sha512.New()
		h.Write(t8)
		h.Write(mixedKey)
		h.Write([]byte(msg))
		k := new(big.Int).SetBytes(reverse(h.Sum(nil)))
		k.Mod(k, order)
		if new(big.Int).Mod(k, big.NewInt(8)).Int64() != 7 {
			continue
		}
		s := k.Mul(k, scalar)
		s.Mod(s, order)
		mixedOrderR = join(msg, b64.EncodeToString(append(append([]byte{}, t8...), reverse(s.FillBytes(make([]byte, 32)))...)))
		break
	}

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
			// Weak keys (spec): small-order points and non-canonical encodings.
			{KID: "test:weak-identity", Alg: AlgEd25519, PublicKey: b64.EncodeToString(weakKey("0100000000000000000000000000000000000000000000000000000000000000"))},
			{KID: "test:weak-negative-zero", Alg: AlgEd25519, PublicKey: b64.EncodeToString(weakKey("0100000000000000000000000000000000000000000000000000000000000080"))},
			{KID: "test:weak-noncanonical-small", Alg: AlgEd25519, PublicKey: b64.EncodeToString(weakKey("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))},
			{KID: "test:weak-noncanonical-large", Alg: AlgEd25519, PublicKey: b64.EncodeToString(weakKey("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))},
			{KID: "test:mixed-order", Alg: AlgEd25519, PublicKey: b64.EncodeToString(mixedKey)},
			{KID: "test:weak-order-8", Alg: AlgEd25519, PublicKey: b64.EncodeToString(weakKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))},
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
			// With the identity as public key, R = identity and S = 0 verifies for
			// any message in cofactorless Ed25519 (crypto/ed25519): a forgery the
			// key set must refuse before the signature check.
			{Name: "invalid_key_set_small_order_forgery", License: join("lf1", "test:weak-identity", parts[2], b64.EncodeToString(append(weakKey("0100000000000000000000000000000000000000000000000000000000000000"), make([]byte, 32)...))), Expect: "invalid_key_set"},
			{Name: "invalid_key_set_negative_zero_key", License: join("lf1", "test:weak-negative-zero", parts[2], parts[3]), Expect: "invalid_key_set"},
			{Name: "invalid_key_set_noncanonical_small_key", License: join("lf1", "test:weak-noncanonical-small", parts[2], parts[3]), Expect: "invalid_key_set"},
			{Name: "invalid_key_set_noncanonical_large_key", License: join("lf1", "test:weak-noncanonical-large", parts[2], parts[3]), Expect: "invalid_key_set"},
			{Name: "invalid_key_set_order_8_key", License: join("lf1", "test:weak-order-8", parts[2], parts[3]), Expect: "invalid_key_set"},
			{Name: "invalid_key_set_weak_key_before_signature_length", License: join("lf1", "test:weak-identity", parts[2], shortSig), Expect: "invalid_key_set"},
			{Name: "bad_signature_small_order_r", License: chosenR("0100000000000000000000000000000000000000000000000000000000000000"), Expect: "bad_signature"},
			{Name: "bad_signature_order_8_r", License: chosenR("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), Expect: "bad_signature"},
			{Name: "bad_signature_negative_zero_r", License: chosenR("0100000000000000000000000000000000000000000000000000000000000080"), Expect: "bad_signature"},
			{Name: "bad_signature_order_8_r_mixed_order_key", License: mixedOrderR, Expect: "bad_signature"},
			{Name: "bad_signature_noncanonical_r", License: chosenR("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), Expect: "bad_signature"},
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

// Minimal edwards25519 arithmetic for the vector generator (affine
// coordinates, math/big): -x² + y² = 1 + d·x²·y² over p = 2^255 - 19.
var (
	edP    = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD    = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), edP)), edP)
	edSqrt = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP) // sqrt(-1)
)

type edPoint struct{ x, y *big.Int }

func edDecode(b []byte) edPoint {
	e := reverse(b)
	sign := e[0] >> 7
	e[0] &= 0x7f
	y := new(big.Int).SetBytes(e)
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	v := new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1))
	x2 := new(big.Int).Mod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, edP)), edP)
	x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(edP, big.NewInt(3)), 3), edP)
	if new(big.Int).Mod(new(big.Int).Mul(x, x), edP).Cmp(x2) != 0 {
		x.Mod(x.Mul(x, edSqrt), edP)
	}
	if new(big.Int).Mod(new(big.Int).Mul(x, x), edP).Cmp(x2) != 0 {
		panic("not a point")
	}
	if uint(x.Bit(0)) != uint(sign) {
		x.Sub(edP, x)
	}
	return edPoint{x, y}
}

func edAdd(a, b edPoint) edPoint {
	xy := new(big.Int).Mul(new(big.Int).Mul(a.x, b.x), new(big.Int).Mul(a.y, b.y))
	dxy := new(big.Int).Mod(xy.Mul(xy, edD), edP)
	xn := new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x))
	yn := new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x))
	x := new(big.Int).Mul(xn, new(big.Int).ModInverse(new(big.Int).Add(big.NewInt(1), dxy), edP))
	y := new(big.Int).Mul(yn, new(big.Int).ModInverse(new(big.Int).Sub(big.NewInt(1), dxy), edP))
	return edPoint{x.Mod(x, edP), y.Mod(y, edP)}
}

func edEncode(p edPoint) []byte {
	b := p.y.FillBytes(make([]byte, 32))
	b[0] |= byte(p.x.Bit(0)) << 7
	return reverse(b)
}

func weakKey(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		panic(h)
	}
	return b
}

// Every weak encoding is refused, and ordinary keys aren't (spec: weak keys).
func TestWeakEd25519(t *testing.T) {
	var weak [][]byte
	for _, h := range smallOrder {
		weak = append(weak, weakKey(h))
	}
	// y = p+k for k = 0..18 (every value at or above p), with either sign bit.
	for k := range 19 {
		b := bytes.Repeat([]byte{0xff}, 32)
		b[0], b[31] = byte(0xed+k), 0x7f
		weak = append(weak, b, append(append([]byte{}, b[:31]...), 0xff))
	}
	// Negative zero: x = 0 (y = 1 or y = p-1) with the sign bit set.
	weak = append(weak, weakKey("0100000000000000000000000000000000000000000000000000000000000080"),
		weakKey("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
	for _, k := range weak {
		if !weakEd25519(k) {
			t.Errorf("%x: not refused", k)
		}
	}
	strong := [][]byte{ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey),
		weakKey("eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p-3: a full-order point
		weakKey("0300000000000000000000000000000000000000000000000000000000000000")} // y = 3: a full-order point
	for i := range 64 {
		seed := bytes.Repeat([]byte{byte(i)}, 32)
		strong = append(strong, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	for _, k := range strong {
		if weakEd25519(k) {
			t.Errorf("%x: refused", k)
		}
	}
}
