package licensefile

import (
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Every payload the parser accepts survives ParseClaims → Encode → ParseClaims
// unchanged, so Encode covers the whole claim set.
func TestEncodeRoundTripsVectors(t *testing.T) {
	n := 0
	for _, c := range buildClaimVectors(t).Cases {
		want, err := ParseClaims([]byte(c.Payload))
		if err != nil {
			continue // malformed and unsupported-version cases
		}
		out, err := Encode(*want)
		if err != nil {
			t.Errorf("%s: Encode: %v", c.Name, err)
			continue
		}
		got, err := ParseClaims(out)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: round trip: %v\n got %+v\nwant %+v", c.Name, err, got, want)
		}
		n++
	}
	if n < 20 {
		t.Fatalf("only %d vectors round-tripped", n)
	}
}

func ptr[T any](v T) *T { return &v }

// The exact bytes are pinned: field order, no HTML escaping, durations.
func TestEncodeExact(t *testing.T) {
	cet := time.FixedZone("CET", 3600) // every time is written as UTC
	at := func(m time.Month, d, h int) *time.Time { return ptr(time.Date(2026, m, d, h, 0, 0, 0, cet)) }
	out, err := Encode(Claims{
		LicenseID: "lic_1", Tenant: "tnt_1", Product: "acme-db", Plan: "pro",
		CustomerID: "cus_1", CustomerName: "Contoso", IssuedAt: *at(11, 2, 10),
		NotBefore: at(11, 2, 11), Expires: at(12, 2, 10), RefreshAfter: at(11, 3, 10), UpdatesUntil: at(12, 31, 1),
		Grace:      7*24*time.Hour + 90*time.Minute,
		MaxOffline: ptr(time.Duration(0)),
		Binding:    Binding{Type: BindMachine, Fingerprint: "sha256:<&>"},
		Entitlements: Entitlements{
			Features: []string{"sso"},
			Limits:   map[string]int64{"users": 10, "nodes": Unlimited},
		},
	})
	want := `{"v":1,"lid":"lic_1","tenant":"tnt_1","product":"acme-db","plan":"pro","customer":{"id":"cus_1","name":"Contoso"},` +
		`"iat":"2026-11-02T09:00:00Z","nbf":"2026-11-02T10:00:00Z","exp":"2026-12-02T09:00:00Z","grace":"P7DT1H30M","max_offline":"PT0S",` +
		`"refresh_after":"2026-11-03T09:00:00Z","updates_until":"2026-12-31T00:00:00Z",` +
		`"bind":{"type":"machine","fp":"sha256:<&>"},"entitlements":{"features":["sso"],"limits":{"nodes":-1,"users":10}}}`
	if err != nil || string(out) != want {
		t.Errorf("Encode = %s, %v\nwant %s", out, err, want)
	}
}

// Absent and zero-valued optional claims are left out.
func TestEncodeMinimal(t *testing.T) {
	out, err := Encode(Claims{LicenseID: "lic_1", Product: "p", IssuedAt: time.Unix(1_800_000_000, 0),
		Binding: Binding{Type: BindNone}, Entitlements: Entitlements{Features: []string{}, Limits: map[string]int64{}}})
	if want := `{"v":1,"lid":"lic_1","product":"p","iat":"2027-01-15T08:00:00Z"}`; err != nil || string(out) != want {
		t.Errorf("Encode = %s, %v, want %s", out, err, want)
	}
}

func TestEncodeRejects(t *testing.T) {
	ok := Claims{LicenseID: "lic_1", Product: "p", IssuedAt: time.Unix(1_800_000_000, 0)}
	if _, err := Encode(ok); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(*Claims){
		"no lid":             func(c *Claims) { c.LicenseID = "" },
		"no product":         func(c *Claims) { c.Product = "" },
		"no iat":             func(c *Claims) { c.IssuedAt = time.Time{} },
		"sub-second iat":     func(c *Claims) { c.IssuedAt = c.IssuedAt.Add(time.Millisecond) },
		"sub-second exp":     func(c *Claims) { c.Expires = ptr(c.IssuedAt.Add(time.Nanosecond)) },
		"before 1970":        func(c *Claims) { c.NotBefore = ptr(time.Unix(-1, 0)) },
		"sub-second grace":   func(c *Claims) { c.Grace = 1500 * time.Millisecond },
		"negative grace":     func(c *Claims) { c.Grace = -time.Second },
		"max offline > 100y": func(c *Claims) { c.MaxOffline = ptr(36501 * 24 * time.Hour) },
		"machine without fp": func(c *Claims) { c.Tenant = "t"; c.Binding = Binding{Type: BindMachine} },
		"machine, no tenant": func(c *Claims) { c.Binding = Binding{Type: BindMachine, Fingerprint: "f"} },
		"none with fp":       func(c *Claims) { c.Binding = Binding{Type: BindNone, Fingerprint: "f"} },
		"fp without type":    func(c *Claims) { c.Binding = Binding{Fingerprint: "f"} },
		"unknown binding":    func(c *Claims) { c.Binding = Binding{Type: "galaxy", Fingerprint: "f"} },
		"limit below -1":     func(c *Claims) { c.Entitlements.Limits = map[string]int64{"n": -2} },
		"limit above 2^53-1": func(c *Claims) { c.Entitlements.Limits = map[string]int64{"n": 1 << 53} },
		"invalid UTF-8":      func(c *Claims) { c.Plan = "\xff" },
		"NUL in product":     func(c *Claims) { c.Product = "a\x00b" },
	} {
		c := ok
		f(&c)
		if _, err := Encode(c); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Encode = %v, want ErrMalformed", name, err)
		}
	}
}

// Encode's output signs and opens like any other license.
func TestEncodeSignOpen(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	iat := time.Unix(1_800_000_000, 0)
	payload, err := Encode(Claims{LicenseID: "lic_1", Tenant: "t", Product: "p", IssuedAt: iat,
		Binding: Binding{Type: BindCluster, Fingerprint: "sha256:x"}})
	if err != nil {
		t.Fatal(err)
	}
	lic, err := Sign("k1", priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	keys := KeySet{{KID: "k1", Alg: AlgEd25519, Key: pub}}
	c, status, err := Open(lic, keys, CheckOptions{Now: iat, Product: "p", Fingerprint: "sha256:x"})
	if err != nil || status != StatusValid || !strings.HasPrefix(c.LicenseID, "lic_") {
		t.Errorf("Open = %v %v %v", c, status, err)
	}
}
