package offline

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
	"licenseforge.io/licenseforge/sdk/go/fingerprint"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

const (
	tenant  = "tnt_01jcz5b2y3c4d5e6f7g8h9j0k1"
	machine = "sha256:81fe9b1a2812e068c320c4264f01b6d4d186a83cc0008fe954fd5d1b6e3f3684"
	other   = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

var priv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32))

type memStore struct {
	mu sync.Mutex
	b  []byte
}

func (m *memStore) Update(fn func([]byte) ([]byte, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := fn(m.b)
	if err == nil && next != nil {
		m.b = next
	}
	return err
}

type env struct {
	c     *Client
	store *memStore
	now   time.Time
}

func newEnv(t *testing.T, guard *clock.Guard) *env {
	t.Helper()
	e := &env{store: &memStore{}, now: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	c, err := New(Config{TenantID: tenant, Product: "acme-db", LicenseKey: "LF-ABCDE-FGHIJ",
		Keys:        licensefile.KeySet{{KID: "k1", Alg: licensefile.AlgEd25519, Key: priv.Public().(ed25519.PublicKey)}},
		Fingerprint: fingerprint.Result{Fingerprint: machine, Source: fingerprint.SourceMachineID, Binding: "machine"},
		Hostname:    "air-1", Store: e.store, Clock: guard})
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return e.now }
	c.rand = bytes.NewReader(bytes.Repeat([]byte{7}, 64))
	e.c = c
	return e
}

// file signs a license for edit(defaults: this tenant, product and machine,
// issued an hour before now, valid a day).
func (e *env) file(t *testing.T, edit func(*licensefile.Claims)) string {
	t.Helper()
	iat := e.now.Add(-time.Hour)
	exp := iat.Add(24 * time.Hour)
	c := licensefile.Claims{LicenseID: "lic_a", Tenant: tenant, Product: "acme-db", Plan: "pro", IssuedAt: iat, Expires: &exp,
		Binding: licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: machine}}
	if edit != nil {
		edit(&c)
	}
	payload, err := licensefile.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	f, err := licensefile.Sign("k1", priv, payload)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRequest(t *testing.T) {
	e := newEnv(t, nil)
	s, err := e.c.Request()
	if err != nil {
		t.Fatal(err)
	}
	r, err := licensefile.ParseRequest(s)
	if err != nil || r.Tenant != tenant || r.Product != "acme-db" || r.Key != "LF-ABCDE-FGHIJ" || r.Binding.Fingerprint != machine ||
		r.Binding.Type != licensefile.BindMachine || r.FPSource != "machine-id" || r.Hostname != "air-1" || r.SDKVersion == "" || !r.Created.Equal(e.now) {
		t.Errorf("request %+v, %v", r, err)
	}
}

func TestInstallAndDeactivate(t *testing.T) {
	e := newEnv(t, nil)
	if _, _, err := e.c.Current(); !errors.Is(err, ErrNoLicense) {
		t.Errorf("nothing installed: %v", err)
	}
	f := e.file(t, nil)
	if c, st, err := e.c.Install(f); err != nil || st != licensefile.StatusValid || c.LicenseID != "lic_a" {
		t.Fatalf("Install = %v %v", st, err)
	}
	// Another client on the same store (another process) sees it.
	e2 := newEnv(t, nil)
	e2.c.cfg.Store = e.store
	if _, st, err := e2.c.Current(); err != nil || st != licensefile.StatusValid {
		t.Errorf("Current from the store = %v %v", st, err)
	}
	receipt, err := e.c.Deactivate()
	if err != nil {
		t.Fatal(err)
	}
	h, _ := licensefile.FileSHA256(f)
	r, err := licensefile.ParseReceipt(receipt)
	if err != nil || r.Tenant != tenant || r.LicenseID != "lic_a" || r.Fingerprint != machine || r.FileSHA256 != h {
		t.Errorf("receipt %+v, %v", r, err)
	}
	if _, _, err := e.c.Current(); !errors.Is(err, ErrNoLicense) {
		t.Errorf("after Deactivate: %v", err)
	}
	if _, err := e.c.Deactivate(); !errors.Is(err, ErrNoLicense) {
		t.Errorf("Deactivate twice: %v", err)
	}
	// The returned file, or an older one, can't come back; a newer one can.
	if _, _, err := e.c.Install(f); !errors.Is(err, ErrReturned) {
		t.Errorf("returned file installed again: %v", err)
	}
	if _, _, err := e.c.Install(e.file(t, func(c *licensefile.Claims) { c.IssuedAt = c.IssuedAt.Add(-time.Minute) })); !errors.Is(err, ErrReturned) {
		t.Errorf("older file installed: %v", err)
	}
	if _, _, err := e.c.Install(e.file(t, func(c *licensefile.Claims) { c.IssuedAt = c.IssuedAt.Add(time.Minute) })); err != nil {
		t.Errorf("newer file: %v", err)
	}
	// Another license's file isn't affected by lic_a's return.
	if _, _, err := e.c.Install(e.file(t, func(c *licensefile.Claims) { c.LicenseID = "lic_b" })); err != nil {
		t.Errorf("another license: %v", err)
	}
}

func TestInstallRefusals(t *testing.T) {
	e := newEnv(t, nil)
	for name, c := range map[string]struct {
		edit func(*licensefile.Claims)
		want error
	}{
		"other machine": {func(c *licensefile.Claims) { c.Binding.Fingerprint = other }, ErrBadFile},
		"other tenant":  {func(c *licensefile.Claims) { c.Tenant = "tnt_01jcz5b2y3c4d5e6f7g8h9j0k2" }, ErrBadFile},
		"other product": {func(c *licensefile.Claims) { c.Product = "other" }, ErrBadFile},
		"unbound":       {func(c *licensefile.Claims) { c.Binding = licensefile.Binding{Type: licensefile.BindNone} }, ErrBadFile},
		"expired": {func(c *licensefile.Claims) {
			c.IssuedAt = e.now.Add(-48 * time.Hour)
			x := e.now.Add(-time.Hour)
			c.Expires = &x
		}, licensefile.ErrExpired},
	} {
		if _, _, err := e.c.Install(e.file(t, c.edit)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	if _, _, err := e.c.Install("not a license"); !errors.Is(err, ErrBadFile) {
		t.Errorf("garbage: %v", err)
	}
	if e.store.b != nil {
		t.Errorf("a refused file was stored: %s", e.store.b)
	}
}

// The clock guard: installing raises its mark to the file's iat, and a
// clock turned back past the tolerance stops the license.
func TestClock(t *testing.T) {
	cs := &memStore{}
	zero := time.Duration(0)
	g, err := clock.New(cs, "LF-ABCDE-FGHIJ", clock.Options{Tolerance: &zero})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, g)
	if _, _, err := e.c.Install(e.file(t, nil)); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(-2 * time.Hour) // before the file's iat
	if _, _, err := e.c.Current(); !errors.Is(err, clock.ErrRollback) {
		t.Errorf("clock turned back: %v", err)
	}
}
