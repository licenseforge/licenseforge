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
	// Clock and store failures are warnings: the lease is in use, and Run
	// reports them.
	g, _ := clock.New(failClock{}, key, clock.Options{})
	c, _ = f.client(t, f.iat, func(cfg *Config) { cfg.Clock = g; cfg.Store = failStore{saveErr: errors.New("full")} })
	if l, err := c.Activate(context.Background()); l == nil || err != nil {
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
	var reported []string
	_ = c.Run(ctx, func(err error) { reported = append(reported, err.Error()) })
	all := strings.Join(reported, "\n")
	if !strings.Contains(all, "clock not reset") || !strings.Contains(all, "full") {
		t.Errorf("Run reported %v", reported)
	}
	// Warnings from New reach Run's onErr too.
	bad2 := "lf1.nope"
	c, _ = f.client(t, f.iat, func(cfg *Config) { cfg.Store = &memStore{saved: &bad2} })
	c.mu.Lock()
	c.claims = &licensefile.Claims{} // something to keep fresh, so Run starts
	c.mu.Unlock()
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	reported = nil
	_ = c.Run(ctx2, func(err error) { reported = append(reported, err.Error()) })
	if len(reported) == 0 || !strings.Contains(reported[0], "stored lease not used") {
		t.Errorf("New warnings not reported: %v", reported)
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
	exp := *l.Claims.Expires
	*l.Claims.Expires = exp.Add(1000 * time.Hour)
	*l.Claims.MaxOffline = time.Nanosecond
	got, _, _ := c.Current()
	got.Product = "y"
	*got.Expires = exp.Add(2000 * time.Hour)
	again, _, _ := c.Current()
	if !slices.Equal(again.Entitlements.Features, []string{"sso"}) || again.Entitlements.Limits["seats"] != 5 || again.Product != product || !again.Expires.Equal(exp) || *again.MaxOffline != 2*time.Hour {
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

// Not activated on the first attempt is success too: the seat is free.
func TestDeactivateNotActivated(t *testing.T) {
	f := newFake(t)
	store := &memStore{}
	c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = store })
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 404, "not_activated"); return true }
	if err := c.Deactivate(context.Background()); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, _, err := c.Current(); !errors.Is(err, ErrNoLease) || *store.saved != "" {
		t.Errorf("lease kept: %v", err)
	}
	// Other refusals stay errors, and the lease stays.
	if _, err := (func() (*Lease, error) { f.respond = nil; return c.Activate(context.Background()) })(); err != nil {
		t.Fatal(err)
	}
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 401, "unauthenticated"); return true }
	if err := c.Deactivate(context.Background()); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("deactivate: %v", err)
	}
	if _, _, err := c.Current(); err != nil {
		t.Errorf("lease dropped: %v", err)
	}
}

// A simulated day where Current keeps failing for a reason no refresh fixes
// (the build is newer than updates_until): Run refreshes on the lease's
// schedule, not every minute.
func TestRunBoundedWhenRefreshCantHelp(t *testing.T) {
	for _, skew := range []time.Duration{0, 45 * time.Minute, -2 * time.Hour} {
		t.Run(skew.String(), func(t *testing.T) { runBounded(t, skew) })
	}
}

// runBounded runs Run for a simulated day with the local clock skew ahead
// of the server.
func runBounded(t *testing.T, skew time.Duration) {
	f := newFake(t)
	var mu sync.Mutex
	sim := f.iat // server time
	f.claims = func(c *licensefile.Claims) {
		mu.Lock()
		now := sim.Truncate(time.Second)
		mu.Unlock()
		u := f.iat.Add(-time.Hour) // before the build all day
		e, r := now.Add(time.Hour), now.Add(30*time.Minute)
		c.IssuedAt, c.UpdatesUntil, c.Expires, c.RefreshAfter = now, &u, &e, &r
	}
	c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.BuildDate = f.iat })
	c.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return sim.Add(skew) }
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		sim = sim.Add(d)
		over := sim.Sub(f.iat) > 24*time.Hour
		mu.Unlock()
		if over {
			cancel()
		}
		return ctx.Err()
	}
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = c.Run(ctx, nil)
	if n := len(f.reqs); n > 60 { // every 30 minutes: 48 a day
		t.Errorf("%d requests in a simulated day", n)
	}
}

// Without refresh_after, Run waits half the time to exp (at most backoffMax).
func TestRunWithoutRefreshAfter(t *testing.T) {
	f := newFake(t)
	f.claims = func(c *licensefile.Claims) { c.RefreshAfter = nil }
	c, sleeps := f.client(t, f.iat, nil)
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = c.Run(ctx, nil)
	if len(*sleeps) != 1 || (*sleeps)[0] != backoffMax { // exp in 1h: half is 30m, capped at 5m
		t.Errorf("sleeps %v", *sleeps)
	}
}

// Jitter is up to a tenth of the wait, after refresh_after (ADR-0034: not
// before), also when refresh_after is half the lifetime.
func TestRunJitter(t *testing.T) {
	for _, tc := range []struct {
		exp, want time.Duration
	}{{2 * time.Hour, 33 * time.Minute}, {time.Hour, 33 * time.Minute}} {
		f := newFake(t)
		f.claims = func(c *licensefile.Claims) { e := c.IssuedAt.Add(tc.exp); c.Expires = &e }
		c, sleeps := f.client(t, f.iat, nil)
		if _, err := c.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		c.rand = func(n int64) int64 { return n - 1 }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = c.Run(ctx, nil)
		if (*sleeps)[0] != tc.want {
			t.Errorf("exp %v: sleeps %v, want %v", tc.exp, *sleeps, tc.want)
		}
	}
}

// The commit lock: a slow store save and a second, newer lease end with the
// store holding the cached (newest) lease; Forget waits for a save too.
func TestCommitLock(t *testing.T) {
	f := newFake(t)
	var mu sync.Mutex
	issued := 0
	f.claims = func(c *licensefile.Claims) {
		mu.Lock()
		issued++
		n := issued
		mu.Unlock()
		c.IssuedAt = c.IssuedAt.Add(time.Duration(n) * time.Second)
	}
	store := &blockingStore{block: make(chan struct{}), entered: make(chan struct{})}
	c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = store })
	done := make(chan *Lease)
	go func() { l, _ := c.Refresh(context.Background()); done <- l }()
	<-store.entered // the first lease is saving, the commit held
	newer := make(chan *Lease)
	go func() { l, _ := c.Refresh(context.Background()); newer <- l }()
	time.Sleep(50 * time.Millisecond) // the second one gets its lease and waits to commit
	close(store.block)
	first, second := <-done, <-newer
	if first == nil || second == nil || !second.Claims.IssuedAt.After(first.Claims.IssuedAt) {
		t.Fatalf("leases %v %v", first, second)
	}
	c.mu.Lock()
	cached := c.lease
	c.mu.Unlock()
	if store.value() != cached || cached != second.File {
		t.Errorf("store and cache disagree, or the older lease won")
	}

	// Forget waits for a save in progress, so the lease doesn't come back.
	store2 := &blockingStore{block: make(chan struct{}), entered: make(chan struct{})}
	c2, _ := f.client(t, f.iat.Add(time.Hour), func(cfg *Config) { cfg.Store = store2 })
	go func() { l, _ := c2.Refresh(context.Background()); done <- l }()
	<-store2.entered
	forgot := make(chan error)
	go func() { forgot <- c2.Forget() }()
	time.Sleep(50 * time.Millisecond)
	close(store2.block)
	<-done
	if err := <-forgot; err != nil {
		t.Fatal(err)
	}
	if store2.value() != "" {
		t.Error("Forget overtaken by a save: the lease is back in the store")
	}
	if _, _, err := c2.Current(); !errors.Is(err, ErrNoLease) {
		t.Errorf("Current after Forget: %v", err)
	}
}

// blockingStore blocks the first Save until block closes.
type blockingStore struct {
	mu      sync.Mutex
	s       string
	saves   int
	block   chan struct{}
	entered chan struct{}
}

func (b *blockingStore) Load() (string, error) { return "", nil }
func (b *blockingStore) Save(s string) error {
	b.mu.Lock()
	b.saves++
	first := b.saves == 1
	b.mu.Unlock()
	if first {
		close(b.entered)
		<-b.block
	}
	b.mu.Lock()
	b.s = s
	b.mu.Unlock()
	return nil
}
func (b *blockingStore) value() string { b.mu.Lock(); defer b.mu.Unlock(); return b.s }

// A refresh in flight when Forget runs doesn't bring the lease back.
func TestForgetSupersedesInFlight(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t, f.iat, nil)
	inside, release := make(chan struct{}), make(chan struct{})
	f.respond = func(string, int, http.ResponseWriter) bool {
		close(inside)
		<-release
		return false
	}
	got := make(chan error)
	go func() { _, err := c.Refresh(context.Background()); got <- err }()
	<-inside
	if err := c.Forget(); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-got; !errors.Is(err, ErrSuperseded) {
		t.Errorf("refresh = %v", err)
	}
	if _, _, err := c.Current(); !errors.Is(err, ErrNoLease) {
		t.Errorf("lease came back: %v", err)
	}
}

// Run forgets the lease when the server says this machine is no longer
// licensed (revoked, or the seat moved).
func TestRunForgetsOnRevocation(t *testing.T) {
	for _, tc := range []struct {
		code   string
		status int
		forget bool
	}{
		{"license_revoked", 403, true}, {"not_activated", 404, true},
		{"license_revoked", 404, false}, {"not_activated", 403, false}, // the code with an unexpected status
	} {
		f := newFake(t)
		store := &memStore{}
		c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = store })
		if _, err := c.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, tc.status, tc.code); return true }
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // a regression fails, doesn't hang
		err := c.Run(ctx, nil)
		cancel()
		if err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s %d: Run = %v", tc.code, tc.status, err)
		}
		_, _, cur := c.Current()
		if forgot := errors.Is(cur, ErrNoLease) && *store.saved == ""; forgot != tc.forget {
			t.Errorf("%s %d: forgot %v", tc.code, tc.status, forgot)
		}
	}
}

// A spoofed or garbled answer isn't an API refusal: its code is ignored
// unless it is a problem+json with a 4xx status.
func TestCodesOnlyFromProblems(t *testing.T) {
	f := newFake(t)
	for name, respond := range map[string]func(string, int, http.ResponseWriter) bool{
		"plain JSON": func(_ string, _ int, w http.ResponseWriter) bool {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"code":"license_revoked"}`))
			return true
		},
		"5xx problem": func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 503, "license_revoked"); return true },
	} {
		f.respond = respond
		c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.MaxAttempts = 1 })
		_, err := c.Activate(context.Background())
		if err == nil || errors.Is(err, ErrRevoked) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A 5xx problem's code is still reported (a tenant without a signing
	// key), as a server error.
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 503, "no_signing_key"); return true }
	c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.MaxAttempts = 1 })
	_, err := c.Activate(context.Background())
	var ae *APIError
	if !errors.Is(err, ErrServer) || !errors.As(err, &ae) || ae.Code != "no_signing_key" || !strings.Contains(err.Error(), "no_signing_key") {
		t.Errorf("503 no_signing_key: %v", err)
	}
}

// A refusal of an older refresh doesn't drop a lease an Activate committed
// meanwhile.
func TestRunKeepsNewerLease(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t, f.iat, nil)
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	f.respond = func(op string, _ int, w http.ResponseWriter) bool {
		if op != "refresh" {
			return false
		}
		once.Do(func() { // the app re-activates while this refresh is answered
			f.respond = nil
			if _, err := c.Activate(context.Background()); err != nil {
				t.Error(err)
			}
		})
		problem(w, 404, "not_activated")
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Run(ctx, nil); !errors.Is(err, ErrNotActivated) {
		t.Fatalf("Run = %v", err)
	}
	if _, _, err := c.Current(); err != nil {
		t.Errorf("newer lease dropped: %v", err)
	}
}

// ClockTolerance reaches the claim checks.
func TestClockTolerance(t *testing.T) {
	f := newFake(t)
	tol := 72 * time.Hour
	local := f.iat.Add(-48 * time.Hour) // the server is two days ahead; the lease's offset is ignored here
	for name, cfgTol := range map[string]*time.Duration{"default": nil, "configured": &tol} {
		c, _ := f.client(t, local, func(cfg *Config) { cfg.ClockTolerance = cfgTol })
		if _, err := c.Activate(context.Background()); err != nil {
			t.Fatal(err)
		}
		c.mu.Lock()
		c.offset = 0 // check against the local clock alone
		c.mu.Unlock()
		_, _, err := c.Current()
		if (name == "default") != errors.Is(err, licensefile.ErrClockSkew) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A persistent outage: Run makes one request per pass, so a day costs a few
// hundred requests, not thousands.
func TestRunOutageBounded(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t, f.iat, nil)
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 503, ""); return true }
	var mu sync.Mutex
	sim := f.iat
	c.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return sim }
	ctx, cancel := context.WithCancel(context.Background())
	c.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		sim = sim.Add(d)
		over := sim.Sub(f.iat) > 24*time.Hour
		mu.Unlock()
		if over {
			cancel()
		}
		return ctx.Err()
	}
	before := len(f.reqs)
	_ = c.Run(ctx, nil)
	if n := len(f.reqs) - before; n > 300 { // backoff capped at 5 minutes: 288 a day
		t.Errorf("%d requests in a simulated day of outage", n)
	}
}

// Without refresh_after and exp under 10 minutes away, Run waits half of it.
func TestRunHalfOfShortExp(t *testing.T) {
	f := newFake(t)
	f.claims = func(c *licensefile.Claims) { e := c.IssuedAt.Add(4 * time.Minute); c.Expires, c.RefreshAfter = &e, nil }
	c, sleeps := f.client(t, f.iat, nil)
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = c.Run(ctx, nil)
	if len(*sleeps) != 1 || (*sleeps)[0] != 2*time.Minute {
		t.Errorf("sleeps %v", *sleeps)
	}
}

// A simulated day of an hour-long lease (refresh_after at 30 minutes) with
// the local clock skew(elapsed) ahead of the server: Run keeps the lease
// passing Current at every wake when a refresh can (a fast clock lapses it
// locally before refresh_after), without refreshing more than it must.
func TestRunSimulatedDay(t *testing.T) {
	for _, tc := range []struct {
		name     string
		skew     func(elapsed time.Duration) time.Duration
		min, max int                                        // requests a day
		gaps     int                                        // wakes where Current may fail
		lease    func(c *licensefile.Claims, now time.Time) // nil: the hour-long lease
		first    time.Duration                              // the first wait, when set
	}{
		{"0", func(time.Duration) time.Duration { return 0 }, 45, 52, 0, nil, 0},
		{"+45m", func(time.Duration) time.Duration { return 45 * time.Minute }, 90, 115, 0, nil, 0},
		{"+3h", func(time.Duration) time.Duration { return 3 * time.Hour }, 45, 52, 100, nil, 0}, // every lease lapses at once
		{"slow", func(time.Duration) time.Duration { return -2 * time.Hour }, 45, 52, 0, nil, 0},
		{"drifting to +45m", func(e time.Duration) time.Duration { return e * 45 / (24 * 60) }, 48, 115, 0, nil, 0},
		{"jumping to +45m", func(e time.Duration) time.Duration { // the jump lapses the lease held then
			if e > 12*time.Hour {
				return 45 * time.Minute
			}
			return 0
		}, 70, 90, 1, nil, 0},
		// A week-long lease with max_offline 1d (refresh_after at 12h): the
		// first point Current fails at is iat+max_offline, 11h ahead by a
		// 13h-fast clock; the margin stops at 2 minutes.
		{name: "week lease, +13h", skew: func(time.Duration) time.Duration { return 13 * time.Hour }, min: 3, max: 4,
			lease: func(c *licensefile.Claims, now time.Time) {
				e, r, o := now.Add(7*24*time.Hour), now.Add(12*time.Hour), 24*time.Hour
				c.Expires, c.RefreshAfter, c.MaxOffline = &e, &r, &o
			}, first: 11*time.Hour - failMargin},
		// Grace counts: Current fails only at exp+grace, 45m ahead by a
		// 45m-fast clock, so refresh_after (30m) stands.
		{name: "grace, +45m", skew: func(time.Duration) time.Duration { return 45 * time.Minute }, min: 45, max: 52,
			lease: func(c *licensefile.Claims, _ time.Time) { c.Grace = 30 * time.Minute }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, gaps, sleeps := simulateDay(t, tc.skew, tc.lease)
			t.Logf("%d requests, %d gaps", n, gaps)
			if tc.first != 0 && (len(sleeps) == 0 || sleeps[0] != tc.first) {
				t.Errorf("first wait %v, want %v", sleeps[:min(len(sleeps), 1)], tc.first)
			}
			if n < tc.min || n > tc.max {
				t.Errorf("%d requests, want %d..%d", n, tc.min, tc.max)
			}
			if gaps > tc.gaps {
				t.Errorf("Current failed at %d wakes", gaps)
			}
		})
	}
}

func simulateDay(t *testing.T, skew func(time.Duration) time.Duration, lease func(*licensefile.Claims, time.Time)) (requests, gaps int, sleeps []time.Duration) {
	f := newFake(t)
	var mu sync.Mutex
	sim := f.iat // server time
	f.claims = func(c *licensefile.Claims) {
		mu.Lock()
		now := sim.Truncate(time.Second)
		mu.Unlock()
		e, r := now.Add(time.Hour), now.Add(30*time.Minute)
		c.IssuedAt, c.Expires, c.RefreshAfter = now, &e, &r
		if lease != nil {
			lease(c, now)
		}
	}
	c, _ := f.client(t, f.iat, nil)
	c.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return sim.Add(skew(sim.Sub(f.iat))) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		sim = sim.Add(d)
		over := sim.Sub(f.iat) > 24*time.Hour
		mu.Unlock()
		sleeps = append(sleeps, d)
		if over {
			cancel()
		} else if _, _, err := c.Current(); err != nil {
			gaps++
		}
		return ctx.Err()
	}
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = c.Run(ctx, nil)
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs), gaps, sleeps
}

// A refresh_after past exp or iat+max_offline doesn't sleep through them:
// Run wakes at half the time left.
func TestRunWaitCapped(t *testing.T) {
	for _, tc := range []struct {
		name            string
		exp, maxOffline time.Duration
	}{{"exp", time.Hour, 4 * time.Hour}, {"max_offline", 4 * time.Hour, time.Hour}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			f.claims = func(c *licensefile.Claims) {
				e, r, o := c.IssuedAt.Add(tc.exp), c.IssuedAt.Add(3*time.Hour), tc.maxOffline
				c.Expires, c.RefreshAfter, c.MaxOffline = &e, &r, &o
			}
			c, sleeps := f.client(t, f.iat, nil)
			if _, err := c.Activate(context.Background()); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_ = c.Run(ctx, nil)
			if len(*sleeps) != 1 || (*sleeps)[0] != 30*time.Minute {
				t.Errorf("sleeps %v", *sleeps)
			}
		})
	}
}

// Only Forget supersedes an in-flight call: a lease another call commits
// meanwhile doesn't make a refresh fail (the iat comparison keeps the
// newest).
func TestRefreshNotSupersededByCommit(t *testing.T) {
	f := newFake(t)
	c, _ := f.client(t, f.iat, nil)
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	f.respond = func(op string, _ int, _ http.ResponseWriter) bool {
		once.Do(func() {
			f.respond = nil
			if _, err := c.Activate(context.Background()); err != nil {
				t.Error(err)
			}
		})
		return false
	}
	if _, err := c.Refresh(context.Background()); err != nil {
		t.Errorf("Refresh = %v", err)
	}
}
