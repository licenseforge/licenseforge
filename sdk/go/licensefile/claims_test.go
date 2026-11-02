package licensefile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const claimVectorsPath = "../../../spec/vectors/lf1-claims.json"

type claimOptions struct {
	Now            string `json:"now"`
	Product        string `json:"product"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	BuildDate      string `json:"build_date,omitempty"`
	ClockTolerance string `json:"clock_tolerance,omitempty"`
}

type claimCase struct {
	Name    string       `json:"name"`
	Payload string       `json:"payload"`
	Options claimOptions `json:"options"`
	Expect  string       `json:"expect"`
}

type claimVectorFile struct {
	Format      string      `json:"format"`
	Note        string      `json:"note"`
	Conventions []string    `json:"conventions"`
	Cases       []claimCase `json:"cases"`
}

// payload builds a claims JSON object from a base plus overrides; a nil value removes the field.
func payload(t *testing.T, overrides map[string]any) string {
	t.Helper()
	m := map[string]any{
		"v": 1, "lid": "lic_test", "product": "acme-db",
		"iat": "2026-11-01T00:00:00Z", "exp": "2026-12-01T00:00:00Z", "grace": "P7D",
		"bind": map[string]any{"type": "machine", "fp": "sha256:abc"},
	}
	for k, v := range overrides {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func buildClaimVectors(t *testing.T) claimVectorFile {
	t.Helper()
	opts := func(now string, mod ...func(*claimOptions)) claimOptions {
		o := claimOptions{Now: now, Product: "acme-db", Fingerprint: "sha256:abc"}
		for _, f := range mod {
			f(&o)
		}
		return o
	}
	mid := "2026-11-15T00:00:00Z"
	p := func(o map[string]any) string { return payload(t, o) }
	c := func(name, pl string, o claimOptions, expect string) claimCase {
		return claimCase{Name: name, Payload: pl, Options: o, Expect: expect}
	}
	return claimVectorFile{
		Format: "lf1-claims",
		Note:   "Claim-check vectors for lf1 (spec/license-format.md, Claim checks). Payloads are already signature-verified; only claim parsing and checks are tested.",
		Conventions: []string{
			"payload is the exact JSON text of the verified payload.",
			"options.now, options.build_date use the spec timestamp format; options.clock_tolerance uses the spec duration format; absent means the 24h default, PT0S means strict.",
			"Some payloads are not produced by a map serializer (duplicate or case-variant keys, number forms); they are written as raw JSON text on purpose.",
			"expect is valid, grace, or the class of the first failing claim check.",
		},
		Cases: []claimCase{
			c("valid_basic", p(nil), opts(mid), "valid"),
			c("valid_perpetual", p(map[string]any{"exp": nil}), opts("2099-01-01T00:00:00Z"), "valid"),
			c("valid_at_exp", p(nil), opts("2026-12-01T00:00:00Z"), "valid"),
			c("grace_after_exp", p(nil), opts("2026-12-01T00:00:01Z"), "grace"),
			c("grace_at_grace_end", p(nil), opts("2026-12-08T00:00:00Z"), "grace"),
			c("expired_after_grace", p(nil), opts("2026-12-08T00:00:01Z"), "expired"),
			c("expired_without_grace", p(map[string]any{"grace": nil}), opts("2026-12-01T00:00:01Z"), "expired"),
			c("grace_combined_duration", p(map[string]any{"grace": "P1DT2H3M4S"}), opts("2026-12-02T02:03:04Z"), "grace"),
			c("expired_combined_duration", p(map[string]any{"grace": "P1DT2H3M4S"}), opts("2026-12-02T02:03:05Z"), "expired"),
			c("wrong_product", p(nil), opts(mid, func(o *claimOptions) { o.Product = "other" }), "wrong_product"),
			c("wrong_product_wins_over_expired", p(nil), opts("2027-06-01T00:00:00Z", func(o *claimOptions) { o.Product = "other" }), "wrong_product"),
			c("binding_mismatch", p(nil), opts(mid, func(o *claimOptions) { o.Fingerprint = "sha256:xyz" }), "binding_mismatch"),
			c("binding_cluster_match", p(map[string]any{"bind": map[string]any{"type": "cluster", "fp": "sha256:k8s"}}), opts(mid, func(o *claimOptions) { o.Fingerprint = "sha256:k8s" }), "valid"),
			c("binding_none_ignores_fingerprint", p(map[string]any{"bind": map[string]any{"type": "none"}}), opts(mid, func(o *claimOptions) { o.Fingerprint = "anything" }), "valid"),
			c("binding_absent_is_none", p(map[string]any{"bind": nil}), opts(mid, func(o *claimOptions) { o.Fingerprint = "" }), "valid"),
			c("clock_skew", p(map[string]any{"iat": "2026-11-16T00:00:01Z"}), opts(mid), "clock_skew"),
			c("iat_future_within_tolerance", p(map[string]any{"iat": "2026-11-16T00:00:00Z"}), opts(mid), "valid"),
			c("clock_skew_custom_tolerance", p(map[string]any{"iat": "2026-11-15T02:00:00Z"}), opts(mid, func(o *claimOptions) { o.ClockTolerance = "PT1H" }), "clock_skew"),
			c("not_yet_valid", p(map[string]any{"nbf": "2026-11-15T00:00:01Z"}), opts(mid), "not_yet_valid"),
			c("valid_at_nbf", p(map[string]any{"nbf": mid}), opts(mid), "valid"),
			c("offline_exceeded", p(map[string]any{"max_offline": "P3D", "iat": "2026-11-11T23:59:59Z"}), opts(mid), "offline_exceeded"),
			c("offline_at_limit", p(map[string]any{"max_offline": "P3D", "iat": "2026-11-12T00:00:00Z"}), opts(mid), "valid"),
			c("updates_expired", p(map[string]any{"updates_until": "2026-06-01T00:00:00Z"}), opts(mid, func(o *claimOptions) { o.BuildDate = "2026-07-01T00:00:00Z" }), "updates_expired"),
			c("updates_covered", p(map[string]any{"updates_until": "2026-06-01T00:00:00Z"}), opts(mid, func(o *claimOptions) { o.BuildDate = "2026-06-01T00:00:00Z" }), "valid"),
			c("updates_unchecked_without_build_date", p(map[string]any{"updates_until": "2026-06-01T00:00:00Z"}), opts(mid), "valid"),
			c("updates_expired_wins_over_grace", p(map[string]any{"updates_until": "2026-06-01T00:00:00Z"}), opts("2026-12-02T00:00:00Z", func(o *claimOptions) { o.BuildDate = "2026-07-01T00:00:00Z" }), "updates_expired"),
			c("unsupported_version", `{"v":2}`, opts(mid), "unsupported_version"),
			c("unknown_fields_ignored", p(map[string]any{"future_claim": map[string]any{"x": 1}}), opts(mid), "valid"),
			c("malformed_not_object", `[]`, opts(mid), "malformed"),
			c("malformed_missing_v", p(map[string]any{"v": nil}), opts(mid), "malformed"),
			c("malformed_v_string", p(map[string]any{"v": "1"}), opts(mid), "malformed"),
			c("malformed_missing_lid", p(map[string]any{"lid": nil}), opts(mid), "malformed"),
			c("malformed_missing_product", p(map[string]any{"product": nil}), opts(mid), "malformed"),
			c("malformed_missing_iat", p(map[string]any{"iat": nil}), opts(mid), "malformed"),
			c("malformed_time_offset", p(map[string]any{"exp": "2026-12-01T00:00:00+00:00"}), opts(mid), "malformed"),
			c("malformed_time_fraction", p(map[string]any{"exp": "2026-12-01T00:00:00.000Z"}), opts(mid), "malformed"),
			c("malformed_time_invalid_date", p(map[string]any{"exp": "2026-02-30T00:00:00Z"}), opts(mid), "malformed"),
			c("malformed_duration_years", p(map[string]any{"grace": "P1Y"}), opts(mid), "malformed"),
			c("malformed_duration_weeks", p(map[string]any{"grace": "P1W"}), opts(mid), "malformed"),
			c("malformed_duration_empty", p(map[string]any{"grace": "P"}), opts(mid), "malformed"),
			c("malformed_duration_dangling_t", p(map[string]any{"grace": "P1DT"}), opts(mid), "malformed"),
			c("malformed_duration_negative", p(map[string]any{"grace": "-P1D"}), opts(mid), "malformed"),
			c("malformed_bind_unknown_type", p(map[string]any{"bind": map[string]any{"type": "dongle", "fp": "x"}}), opts(mid), "malformed"),
			c("malformed_bind_machine_without_fp", p(map[string]any{"bind": map[string]any{"type": "machine"}}), opts(mid), "malformed"),
			// Presence vs zero values.
			c("offline_exceeded_zero_max_offline", p(map[string]any{"max_offline": "PT0S"}), opts(mid), "offline_exceeded"),
			c("valid_zero_max_offline_at_iat", p(map[string]any{"max_offline": "P0D", "iat": mid}), opts(mid), "valid"),
			c("expired_epoch_exp", p(map[string]any{"exp": "1970-01-01T00:00:00Z", "grace": nil}), opts(mid), "expired"),
			c("clock_skew_strict_tolerance", p(map[string]any{"iat": "2026-11-15T00:00:01Z"}), opts(mid, func(o *claimOptions) { o.ClockTolerance = "PT0S" }), "clock_skew"),
			c("valid_strict_tolerance_at_now", p(map[string]any{"iat": mid}), opts(mid, func(o *claimOptions) { o.ClockTolerance = "PT0S" }), "valid"),
			// Duration range.
			c("grace_max_duration", p(map[string]any{"grace": "P36500D"}), opts("2100-01-01T00:00:00Z"), "grace"),
			c("malformed_duration_over_max", p(map[string]any{"grace": "P36500DT1S"}), opts(mid), "malformed"),
			c("malformed_duration_six_digit_days_over_max", p(map[string]any{"grace": "P999999D"}), opts(mid), "malformed"),
			c("malformed_duration_seven_digits", p(map[string]any{"grace": "PT1000000S"}), opts(mid), "malformed"),
			c("malformed_duration_lowercase", p(map[string]any{"grace": "p1d"}), opts(mid), "malformed"),
			// Null and types.
			c("malformed_exp_null", p(map[string]any{"exp": json.RawMessage("null")}), opts(mid), "malformed"),
			c("malformed_v_null", p(map[string]any{"v": json.RawMessage("null")}), opts(mid), "malformed"),
			c("malformed_bind_null", p(map[string]any{"bind": json.RawMessage("null")}), opts(mid), "malformed"),
			c("malformed_plan_number", p(map[string]any{"plan": 7}), opts(mid), "malformed"),
			c("malformed_empty_lid", p(map[string]any{"lid": ""}), opts(mid), "malformed"),
			c("malformed_empty_product", p(map[string]any{"product": ""}), opts(mid), "malformed"),
			c("malformed_features_not_array", p(map[string]any{"entitlements": map[string]any{"features": "sso"}}), opts(mid), "malformed"),
			// Integer forms and version precedence.
			c("malformed_v_float", `{"v":1.0,"lid":"l","product":"acme-db","iat":"2026-11-01T00:00:00Z"}`, opts(mid), "malformed"),
			c("malformed_v_exponent", `{"v":1e0,"lid":"l","product":"acme-db","iat":"2026-11-01T00:00:00Z"}`, opts(mid), "malformed"),
			c("unsupported_version_huge", `{"v":99999999999999999999}`, opts(mid), "unsupported_version"),
			c("unsupported_version_with_changed_fields", `{"v":2,"bind":"x","iat":5}`, opts(mid), "unsupported_version"),
			// Keys: exact case, no duplicates.
			c("case_variant_key_ignored", `{"v":1,"lid":"l","product":"acme-db","iat":"2026-11-01T00:00:00Z","EXP":"2026-11-02T00:00:00Z"}`, opts(mid), "valid"),
			c("malformed_duplicate_key", `{"v":1,"lid":"l","product":"acme-db","iat":"2026-11-01T00:00:00Z","exp":"2027-01-01T00:00:00Z","exp":"2026-11-02T00:00:00Z"}`, opts(mid), "malformed"),
			c("malformed_duplicate_nested_key", `{"v":1,"lid":"l","product":"acme-db","iat":"2026-11-01T00:00:00Z","bind":{"type":"machine","fp":"sha256:abc","fp":"sha256:xyz"}}`, opts(mid), "malformed"),
			c("malformed_trailing_data", `{"v":1,"lid":"l","product":"acme-db","iat":"2026-11-01T00:00:00Z"} {}`, opts(mid), "malformed"),
			// Binding edge cases.
			c("malformed_bind_empty_type", p(map[string]any{"bind": map[string]any{"type": "", "fp": "sha256:abc"}}), opts(mid), "malformed"),
			c("malformed_bind_fp_without_type", p(map[string]any{"bind": map[string]any{"fp": "sha256:abc"}}), opts(mid), "malformed"),
			c("binding_mismatch_empty_local_fingerprint", p(nil), opts(mid, func(o *claimOptions) { o.Fingerprint = "" }), "binding_mismatch"),
			// Limits.
			c("valid_limit_max_safe_integer", p(map[string]any{"entitlements": map[string]any{"limits": map[string]any{"users": json.RawMessage("9007199254740991")}}}), opts(mid), "valid"),
			c("malformed_limit_over_safe_integer", p(map[string]any{"entitlements": map[string]any{"limits": map[string]any{"users": json.RawMessage("9007199254740992")}}}), opts(mid), "malformed"),
			c("malformed_limit_negative", p(map[string]any{"entitlements": map[string]any{"limits": map[string]any{"users": -5}}}), opts(mid), "malformed"),
			c("malformed_limit_float", p(map[string]any{"entitlements": map[string]any{"limits": map[string]any{"users": json.RawMessage("1.0")}}}), opts(mid), "malformed"),
			// Timestamp edge cases.
			c("malformed_time_hour_24", p(map[string]any{"exp": "2026-12-01T24:00:00Z"}), opts(mid), "malformed"),
			c("malformed_time_leap_second", p(map[string]any{"exp": "2026-12-31T23:59:60Z"}), opts(mid), "malformed"),
			c("malformed_time_lowercase_z", p(map[string]any{"exp": "2026-12-01T00:00:00z"}), opts(mid), "malformed"),
			c("malformed_time_lowercase_t", p(map[string]any{"exp": "2026-12-01t00:00:00Z"}), opts(mid), "malformed"),
			c("malformed_time_extended_year", p(map[string]any{"exp": "+002026-12-01T00:00:00Z"}), opts(mid), "malformed"),
			c("malformed_time_before_1970", p(map[string]any{"exp": "1969-12-31T23:59:59Z"}), opts(mid), "malformed"),
		},
	}
}

func claimClass(st Status, err error) string {
	if err == nil {
		return string(st)
	}
	for class, target := range map[string]error{
		"malformed": ErrMalformed, "unsupported_version": ErrUnsupportedVersion,
		"wrong_product": ErrWrongProduct, "binding_mismatch": ErrBindingMismatch,
		"clock_skew": ErrClockSkew, "not_yet_valid": ErrNotYetValid,
		"offline_exceeded": ErrOfflineExceeded, "expired": ErrExpired,
		"updates_expired": ErrUpdatesExpired,
	} {
		if errors.Is(err, target) {
			return class
		}
	}
	return "unexpected: " + err.Error()
}

func TestClaimVectors(t *testing.T) {
	want, err := json.MarshalIndent(buildClaimVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	if *update {
		if err := os.WriteFile(claimVectorsPath, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat("../../../go.mod"); errors.Is(err, os.ErrNotExist) {
		t.Skip("not inside the licenseforge repository; conformance vectors unavailable")
	}
	got, err := os.ReadFile(claimVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("spec/vectors/lf1-claims.json is stale; run: go test ./licensefile -update")
	}

	var vf claimVectorFile
	if err := json.Unmarshal(got, &vf); err != nil {
		t.Fatal(err)
	}
	mustTime := func(s string) time.Time {
		if s == "" {
			return time.Time{}
		}
		tm, err := parseTime(s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	for _, c := range vf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			o := CheckOptions{Now: mustTime(c.Options.Now), Product: c.Options.Product, Fingerprint: c.Options.Fingerprint, BuildDate: mustTime(c.Options.BuildDate)}
			if c.Options.ClockTolerance != "" {
				tol, err := parseDuration(c.Options.ClockTolerance)
				if err != nil {
					t.Fatal(err)
				}
				o.ClockTolerance = &tol
			}
			var st Status
			claims, err := ParseClaims([]byte(c.Payload))
			if err == nil {
				st, err = claims.Check(o)
			}
			if got := claimClass(st, err); got != c.Expect {
				t.Fatalf("got %s, want %s", got, c.Expect)
			}
		})
	}
}

func TestParseClaimsFields(t *testing.T) {
	c, err := ParseClaims([]byte(`{"v":1,"lid":"l","product":"p","iat":"2026-11-01T00:00:00Z",
		"customer":{"id":"cus_1"},"entitlements":{"features":["sso"],"limits":{"users":50,"nodes":-1}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.CustomerID != "cus_1" || c.Binding.Type != "none" || !strings.Contains(strings.Join(c.Entitlements.Features, ","), "sso") ||
		c.Entitlements.Limits["users"] != 50 || c.Entitlements.Limits["nodes"] != -1 || c.Expires != nil || c.MaxOffline != nil {
		t.Fatalf("unexpected claims: %+v", c)
	}
}

func TestOpen(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(testSeed)
	keys := KeySet{{KID: "k", Alg: AlgEd25519, Key: priv.Public().(ed25519.PublicKey)}}
	lic, err := Sign("k", priv, []byte(payload(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	c, st, err := Open(lic, keys, CheckOptions{Now: now, Product: "acme-db", Fingerprint: "sha256:abc"})
	if err != nil || st != StatusValid || c.LicenseID != "lic_test" {
		t.Fatalf("Open = %v, %q, %v", c, st, err)
	}
	if _, _, err := Open(lic, keys, CheckOptions{Now: now.AddDate(1, 0, 0), Product: "acme-db", Fingerprint: "sha256:abc"}); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: got %v", err)
	}
	if _, _, err := Open(strings.Replace(lic, "lf1.k.", "lf1.x.", 1), keys, CheckOptions{Now: now}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: got %v", err)
	}
}
