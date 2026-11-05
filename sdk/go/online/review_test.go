package online

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
	"licenseforge.io/licenseforge/sdk/go/fingerprint"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// With max_offline 0, refresh_after is the iat: Run must not spin.
func TestRunNeverSpins(t *testing.T) {
	f := newFake(t)
	f.claims = func(c *licensefile.Claims) {
		zero := time.Duration(0)
		c.MaxOffline = &zero
		c.RefreshAfter = &c.IssuedAt
	}
	c, sleeps := f.client(t, f.iat, nil)
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	f.respond = func(string, int, http.ResponseWriter) bool {
		if n++; n == 5 {
			cancel()
		}
		return false
	}
	if err := c.Run(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(*sleeps) < 5 || (*sleeps)[0] != 0 {
		t.Fatalf("sleeps %v", *sleeps)
	}
	for i, d := range (*sleeps)[1:] {
		if d < MinRefreshInterval {
			t.Errorf("sleep %d after a success: %v", i+1, d)
		}
	}
}

// A cached lease that doesn't pass Current is refreshed at once, not at
// refresh_after.
func TestRunRefreshesInvalidAtOnce(t *testing.T) {
	f := newFake(t)
	f.claims = func(c *licensefile.Claims) { u := c.IssuedAt.Add(-time.Hour); c.UpdatesUntil = &u }
	c, sleeps := f.client(t, f.iat, func(cfg *Config) { cfg.BuildDate = f.iat })
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Current(); !errors.Is(err, licensefile.ErrUpdatesExpired) { // BuildDate reaches the claim checks
		t.Fatalf("Current = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f.respond = func(string, int, http.ResponseWriter) bool { cancel(); return false }
	_ = c.Run(ctx, nil)
	if len(*sleeps) == 0 || (*sleeps)[0] != 0 {
		t.Errorf("sleeps %v, want an immediate refresh", *sleeps)
	}
}

func TestDeactivateLostResponse(t *testing.T) {
	f := newFake(t)
	store := &memStore{}
	c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = store })
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Not activated on the first attempt: an error, the lease stays.
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 404, "not_activated"); return true }
	if err := c.Deactivate(context.Background()); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("first attempt: %v", err)
	}
	if _, _, err := c.Current(); err != nil {
		t.Errorf("lease dropped: %v", err)
	}
	// The first answer is lost (503), the retry finds it done: success.
	before := len(f.reqs)
	f.respond = func(_ string, n int, w http.ResponseWriter) bool {
		if n == before+1 {
			problem(w, 503, "")
		} else {
			problem(w, 404, "not_activated")
		}
		return true
	}
	if err := c.Deactivate(context.Background()); err != nil {
		t.Fatalf("after a lost answer: %v", err)
	}
	if _, _, err := c.Current(); !errors.Is(err, ErrNoLease) || store.saved == nil || *store.saved != "" {
		t.Errorf("lease kept: %v %v", err, store.saved)
	}
}

func TestTransport(t *testing.T) {
	f := newFake(t)
	cfg := Config{TenantID: tenant, Product: product, LicenseKey: key, Keys: f.keys(), Fingerprint: fp}
	for url, ok := range map[string]bool{
		"http://api.vendor.example": false, "http://10.0.0.1": false, "ftp://x": false,
		"https://api.vendor.example": true, "http://localhost:8080": true, "http://127.0.0.1": true, "http://[::1]:9": true,
	} {
		cfg.BaseURL = url
		if _, err := New(cfg); (err == nil) != ok {
			t.Errorf("%s: %v", url, err)
		}
	}
	// Redirects aren't followed: the key would go with them.
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool {
		w.Header().Set("Location", f.srv.URL+"/elsewhere")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return true
	}
	c, _ := f.client(t, f.iat, nil)
	if _, err := c.Activate(context.Background()); err == nil {
		t.Error("redirect followed")
	}
	if len(f.reqs) != 1 {
		t.Errorf("%d requests", len(f.reqs))
	}
}

func TestUnboundLeasesRefused(t *testing.T) {
	f := newFake(t)
	for name, mod := range map[string]func(*licensefile.Claims){
		"no binding":    func(c *licensefile.Claims) { c.Binding = licensefile.Binding{Type: licensefile.BindNone} },
		"other binding": func(c *licensefile.Claims) { c.Binding.Type = licensefile.BindCluster },
	} {
		f.claims = mod
		c, _ := f.client(t, f.iat, nil)
		if _, err := c.Activate(context.Background()); !errors.Is(err, ErrBadLease) {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg := Config{BaseURL: f.srv.URL, TenantID: tenant, Product: product, LicenseKey: key, Keys: f.keys(),
		Fingerprint: fingerprint.Result{Fingerprint: fp.Fingerprint, Source: fp.Source}}
	if _, err := New(cfg); err == nil {
		t.Error("fingerprint without a binding accepted")
	}
}

type failStore struct{ loadErr, saveErr error }

func (s failStore) Load() (string, error) { return "", s.loadErr }
func (s failStore) Save(string) error     { return s.saveErr }

type failClock struct{}

func (failClock) Update(fn func([]byte) ([]byte, error)) error {
	_, _ = fn(nil)
	return errors.New("read-only")
}

func TestWarnings(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t, f.iat, nil)
	if w := c.Warnings(); len(w) != 1 || !strings.Contains(w[0].Error(), "memory only") {
		t.Errorf("memory-only: %v", w)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Errorf("not forgotten: %v", w)
	}
	c, _ = f.client(t, f.iat, func(cfg *Config) { cfg.Store = failStore{loadErr: errors.New("disk")} })
	if w := c.Warnings(); len(w) != 1 || !strings.Contains(w[0].Error(), "disk") {
		t.Errorf("load error: %v", w)
	}
	bad := "lf1.nope"
	c, _ = f.client(t, f.iat, func(cfg *Config) { cfg.Store = &memStore{saved: &bad} })
	if w := c.Warnings(); len(w) != 1 || !errors.Is(w[0], ErrBadLease) {
		t.Errorf("bad stored lease: %v", w)
	}
	// Clock and store failures come with the lease, and Run reports them.
	g, _ := clock.New(failClock{}, key, clock.Options{})
	c, _ = f.client(t, f.iat, func(cfg *Config) { cfg.Clock = g; cfg.Store = failStore{saveErr: errors.New("full")} })
	l, err := c.Activate(context.Background())
	if l == nil || err == nil || !strings.Contains(err.Error(), "clock not reset") || !strings.Contains(err.Error(), "full") {
		t.Fatalf("activate: %v %v", l, err)
	}
	if _, _, err := c.Current(); err != nil && !errors.Is(err, clock.ErrUnreadable) {
		t.Errorf("lease not in use: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runs := 0
	f.respond = func(string, int, http.ResponseWriter) bool {
		if runs++; runs == 2 {
			cancel()
		}
		return false
	}
	var reported []error
	_ = c.Run(ctx, func(err error) { reported = append(reported, err) })
	if len(reported) == 0 || !strings.Contains(reported[0].Error(), "full") {
		t.Errorf("Run reported %v", reported)
	}
}

func TestForgetAndFarFutureIat(t *testing.T) {
	f := newFake(t)
	store := &memStore{}
	real := f.iat
	f.claims = func(c *licensefile.Claims) { // a server clock ten years ahead
		c.IssuedAt = c.IssuedAt.AddDate(10, 0, 0)
		e, r := c.IssuedAt.Add(time.Hour), c.IssuedAt.Add(30*time.Minute)
		c.Expires, c.RefreshAfter = &e, &r
	}
	c, _ := f.client(t, real, func(cfg *Config) { cfg.Store = store })
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.claims = nil // fixed: correct leases now look older
	if _, err := c.Refresh(context.Background()); !errors.Is(err, ErrBadLease) {
		t.Fatalf("refresh = %v", err)
	}
	if err := c.Forget(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Current(); !errors.Is(err, ErrNoLease) || *store.saved != "" {
		t.Errorf("after Forget: %v %q", err, *store.saved)
	}
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Errorf("refresh after Forget: %v", err)
	}
	if r := f.reqs[len(f.reqs)-1]; r.op != "refresh" {
		t.Errorf("Forget talked to the server: %+v", f.reqs)
	}
}

// Claims handed out are copies: changing them doesn't change the cache.
func TestClaimsAreCopies(t *testing.T) {
	f := newFake(t)
	f.claims = func(c *licensefile.Claims) {
		c.Entitlements = licensefile.Entitlements{Features: []string{"sso"}, Limits: map[string]int64{"seats": 5}}
	}
	c, _ := f.client(t, f.iat, nil)
	l, err := c.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	l.Claims.Entitlements.Features[0] = "x"
	l.Claims.Entitlements.Limits["seats"] = 999
	got, _, _ := c.Current()
	got.Product = "y"
	again, _, _ := c.Current()
	if !slices.Equal(again.Entitlements.Features, []string{"sso"}) || again.Entitlements.Limits["seats"] != 5 || again.Product != product {
		t.Errorf("cache changed: %+v", again)
	}
}

// A lease loaded from the store raises the clock guard to its iat.
func TestStoredLeaseObservesClock(t *testing.T) {
	f := newFake(t)
	f.iat = time.Now().UTC().Truncate(time.Second)
	file := f.lease(nil)
	g, _ := clock.New(&clockStore{}, key, clock.Options{})
	c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = &memStore{saved: &file}; cfg.Clock = g })
	if now, err := g.Now(f.iat.Add(-time.Hour)); err != nil || !now.Equal(f.iat) { // before any Current
		t.Errorf("guard %v %v", now, err)
	}
	if _, _, err := c.Current(); err != nil {
		t.Fatalf("stored lease: %v", err)
	}
}

// Commits don't race (go test -race).
func TestConcurrentCommits(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = &lockedStore{} })
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { _, _ = c.Refresh(context.Background()) })
		wg.Go(func() { _ = c.Forget() })
		wg.Go(func() { _, _, _ = c.Current() })
	}
	wg.Wait()
}

type lockedStore struct {
	mu sync.Mutex
	s  string
}

func (l *lockedStore) Load() (string, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.s, nil }
func (l *lockedStore) Save(s string) error   { l.mu.Lock(); defer l.mu.Unlock(); l.s = s; return nil }
