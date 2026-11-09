package offline

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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
	mu       sync.Mutex
	b        []byte
	failSave bool
}

func (m *memStore) Update(fn func([]byte) ([]byte, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := fn(m.b)
	if err != nil || next == nil {
		return err
	}
	if m.failSave {
		return errors.New("read-only file system")
	}
	m.b = next
	return nil
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
	e2.now = e2.now.Add(24 * time.Hour) // past exp: the installed file stops working
	if _, _, err := e2.c.Current(); !errors.Is(err, licensefile.ErrExpired) {
		t.Errorf("expired: %v", err)
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
	// Another license's file waits until lic_a is deactivated (its seat
	// needs a receipt), and isn't affected by lic_a's return.
	b := e.file(t, func(c *licensefile.Claims) { c.LicenseID = "lic_b" })
	if _, _, err := e.c.Install(b); !errors.Is(err, ErrOtherLicense) {
		t.Errorf("another license over lic_a: %v", err)
	}
	if _, err := e.c.Deactivate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.c.Install(b); err != nil {
		t.Errorf("another license: %v", err)
	}
	// Deactivate saves before it answers: on a failed write, no receipt and
	// the file stays installed.
	e.store.failSave = true
	if r, err := e.c.Deactivate(); err == nil || r != "" {
		t.Errorf("failed save: %q, %v", r, err)
	}
	e.store.failSave = false
	if c, _, err := e.c.Current(); err != nil || c.LicenseID != "lic_b" {
		t.Errorf("after a failed deactivate: %v", err)
	}
	// An expired file can still be returned.
	e.now = e.now.Add(48 * time.Hour)
	if _, err := e.c.Deactivate(); err != nil {
		t.Errorf("expired file: %v", err)
	}
}

// A renewal isn't rolled back by installing an older file of the same
// license (a stale mount, a secret store rolled back); the same file again
// changes nothing.
func TestInstallOlderFile(t *testing.T) {
	e := newEnv(t, nil)
	old := e.file(t, nil)
	renewed := e.file(t, func(c *licensefile.Claims) { c.IssuedAt = c.IssuedAt.Add(time.Minute) })
	if _, _, err := e.c.Install(renewed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.c.Install(old); !errors.Is(err, ErrOlderFile) {
		t.Errorf("older file over the renewal: %v", err)
	}
	if c, _, err := e.c.Current(); err != nil || !c.IssuedAt.Equal(e.now.Add(-time.Hour+time.Minute).Truncate(time.Second)) {
		t.Errorf("after: %v, %v", c, err)
	}
	if _, _, err := e.c.Install(renewed); err != nil {
		t.Errorf("same file again: %v", err)
	}
	// An installed file that no longer verifies here (the fingerprint
	// changed) doesn't block a file for this machine, older or not.
	e.c.cfg.Fingerprint.Fingerprint = other
	moved := e.file(t, func(c *licensefile.Claims) { c.Binding.Fingerprint = other })
	if _, _, err := e.c.Install(moved); err != nil {
		t.Errorf("after a fingerprint change: %v", err)
	}
}

func TestStatesAndOptions(t *testing.T) {
	e := newEnv(t, nil)
	// In grace: the term ended ten minutes ago, grace an hour.
	if _, st, err := e.c.Install(e.file(t, func(c *licensefile.Claims) {
		x := e.now.Add(-10 * time.Minute)
		c.Expires, c.Grace = &x, time.Hour
	})); err != nil || st != licensefile.StatusGrace {
		t.Errorf("grace: %v %v", st, err)
	}
	// BuildDate reaches updates_until.
	e.c.cfg.BuildDate = e.now
	if _, _, err := e.c.Current(); err != nil {
		t.Errorf("no updates_until: %v", err)
	}
	e.c.cfg.BuildDate = time.Time{}
	if _, _, err := e.c.Install(e.file(t, func(c *licensefile.Claims) {
		u := e.now.Add(-24 * time.Hour)
		c.IssuedAt, c.UpdatesUntil = c.IssuedAt.Add(time.Second), &u
	})); err != nil {
		t.Fatal(err)
	}
	e.c.cfg.BuildDate = e.now
	if _, _, err := e.c.Current(); !errors.Is(err, licensefile.ErrUpdatesExpired) {
		t.Errorf("build after updates_until: %v", err)
	}
	// A cluster-bound file under a machine configuration, same fingerprint.
	if _, _, err := e.c.Install(e.file(t, func(c *licensefile.Claims) { c.Binding.Type = licensefile.BindCluster })); !errors.Is(err, ErrBadFile) {
		t.Errorf("cluster file: %v", err)
	}
	// Requests carry fresh random nonces.
	e.c.rand = rand.Reader
	r1, _ := e.c.Request()
	r2, _ := e.c.Request()
	p1, err1 := licensefile.ParseRequest(r1)
	p2, err2 := licensefile.ParseRequest(r2)
	if err1 != nil || err2 != nil || len(p1.Nonce) != 16 || bytes.Equal(p1.Nonce, p2.Nonce) {
		t.Errorf("nonces %x %x", p1.Nonce, p2.Nonce)
	}
}

// State: corrupt counts as none and is repaired by Install; another
// kind's state (the clock guard's, a shared store) fails loudly.
func TestState(t *testing.T) {
	e := newEnv(t, nil)
	for _, corrupt := range []string{"{not json", "null", "{}", "[]", `{"offline":1,"file":5}`} {
		e.store.b = []byte(corrupt)
		if _, _, err := e.c.Current(); !errors.Is(err, ErrNoLicense) {
			t.Errorf("corrupt %q: %v", corrupt, err)
		}
	}
	if _, _, err := e.c.Install(e.file(t, nil)); err != nil {
		t.Errorf("Install over corrupt state: %v", err)
	}
	g, err := clock.New(e.store, "LF-ABCDE-FGHIJ", clock.Options{}) // the mistake: one store for both
	if err != nil {
		t.Fatal(err)
	}
	e.c.cfg.Clock = g
	_, _, err = e.c.Current() // the guard writes its mark over the offline state...
	if _, _, err2 := e.c.Current(); !errors.Is(err, ErrForeignState) && !errors.Is(err2, ErrForeignState) {
		t.Errorf("shared store: %v, %v", err, err2) // ...which the next read notices
	}
}

// A guard that can't be raised to a file's future iat: Install refuses
// what Current would.
func TestInstallFutureFileUnheldGuard(t *testing.T) {
	cs := &memStore{}
	g, err := clock.New(cs, "LF-ABCDE-FGHIJ", clock.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, g)
	strict := time.Duration(0)
	e.c.cfg.ClockTolerance = &strict
	cs.failSave = true
	if _, _, err := e.c.Install(e.file(t, func(c *licensefile.Claims) { c.IssuedAt = e.now.Add(time.Hour) })); !errors.Is(err, clock.ErrNotPersisted) {
		t.Errorf("Install with an unwritable guard: %v", err)
	}
	if e.store.b != nil {
		t.Error("the file was stored")
	}
	// A vendor clock a few minutes fast needs no raise (the claim checks'
	// default tolerance): installed even with an unwritable guard.
	e.c.cfg.ClockTolerance = nil
	if _, _, err := e.c.Install(e.file(t, func(c *licensefile.Claims) { c.IssuedAt = e.now.Add(5 * time.Minute) })); err != nil {
		t.Errorf("five minutes fast: %v", err)
	}
}

// A file refused for an iat too far ahead leaves the guard, and the
// installed file, as they were.
func TestRefusedFutureFile(t *testing.T) {
	g, err := clock.New(&memStore{}, "LF-ABCDE-FGHIJ", clock.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, g)
	if _, _, err := e.c.Install(e.file(t, nil)); err != nil { // 23h left
		t.Fatal(err)
	}
	if _, _, err := e.c.Install(e.file(t, func(c *licensefile.Claims) {
		c.IssuedAt = e.now.Add(100 * time.Hour)
		x := c.IssuedAt.Add(time.Hour)
		c.Expires = &x
	})); err == nil {
		t.Fatal("a file 100h ahead was installed")
	}
	if _, st, err := e.c.Current(); err != nil || st != licensefile.StatusValid {
		t.Errorf("installed file after the refusal: %v %v", st, err)
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
	wrongKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	payload, _ := licensefile.Encode(licensefile.Claims{LicenseID: "lic_a", Tenant: tenant, Product: "acme-db", IssuedAt: e.now,
		Binding: licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: machine}})
	forged, err := licensefile.Sign("k1", wrongKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.c.Install(forged); !errors.Is(err, ErrBadFile) {
		t.Errorf("another key: %v", err)
	}
	if _, _, err := e.c.Install("not a license"); !errors.Is(err, ErrBadFile) {
		t.Errorf("garbage: %v", err)
	}
	if e.store.b != nil {
		t.Errorf("a refused file was stored: %s", e.store.b)
	}
}

// A machine whose clock is behind the file's iat (within the guard's
// tolerance) runs it: installing raises the guard to the iat.
func TestInstallRaisesTheClock(t *testing.T) {
	g, err := clock.New(&memStore{}, "LF-ABCDE-FGHIJ", clock.Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, g)
	strict := time.Duration(0)
	e.c.cfg.ClockTolerance = &strict                                                  // only the guard can make the iat reachable
	f := e.file(t, func(c *licensefile.Claims) { c.IssuedAt = e.now.Add(time.Hour) }) // the vendor's clock: an hour ahead
	if _, st, err := e.c.Install(f); err != nil || st != licensefile.StatusValid {
		t.Errorf("Install = %v %v", st, err)
	}
	if _, st, err := e.c.Current(); err != nil || st != licensefile.StatusValid { // through the raised guard
		t.Errorf("Current = %v %v", st, err)
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
