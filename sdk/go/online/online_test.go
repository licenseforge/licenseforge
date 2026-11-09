package online

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
	"licenseforge.io/licenseforge/sdk/go/fingerprint"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

const (
	tenant  = "tnt_aaaaaaaaaaaaaaaaaaaaaaaaab"
	product = "acme-db"
	key     = "LF-AAAAA-BBBBB-CCCCC-DDDDD-EEEEEE"
)

var fp = fingerprint.Result{Fingerprint: "sha256:" + strings.Repeat("ab", 32), Source: fingerprint.SourceMachineID, Binding: "machine"}

// fake emulates the activation API. Requests are recorded; respond decides
// each answer (nil: a fresh lease).
type fake struct {
	t       *testing.T
	priv    ed25519.PrivateKey
	kid     string
	iat     time.Time // server time
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []recorded
	respond func(op string, n int, w http.ResponseWriter) bool // true: answered
	claims  func(*licensefile.Claims)                          // changes the lease's claims
}

type recorded struct {
	op, auth, idem string
	body           map[string]string
}

func newFake(t *testing.T) *fake {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{t: t, priv: priv, kid: "k1", iat: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) keys() licensefile.KeySet {
	return licensefile.KeySet{{KID: f.kid, Alg: licensefile.AlgEd25519, Key: f.priv.Public().(ed25519.PublicKey)}}
}

func (f *fake) lease(mod func(*licensefile.Claims)) string {
	exp, refresh := f.iat.Add(time.Hour), f.iat.Add(30*time.Minute)
	off := 2 * time.Hour
	c := licensefile.Claims{LicenseID: "lic_x", Tenant: tenant, Product: product, Plan: "pro", IssuedAt: f.iat,
		Expires: &exp, RefreshAfter: &refresh, MaxOffline: &off,
		Binding: licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: fp.Fingerprint}}
	if mod != nil {
		mod(&c)
	}
	payload, err := licensefile.Encode(c)
	if err != nil {
		f.t.Fatal(err)
	}
	file, err := licensefile.Sign(f.kid, f.priv, payload)
	if err != nil {
		f.t.Fatal(err)
	}
	return file
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	op := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	var body map[string]string
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	if want := "/api/v1/activation/tenants/" + tenant + "/" + op; r.URL.Path != want || r.Method != http.MethodPost {
		f.t.Errorf("request %s %s", r.Method, r.URL.Path)
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, recorded{op: op, auth: r.Header.Get("Authorization"), idem: r.Header.Get("Idempotency-Key"), body: body})
	n := len(f.reqs)
	respond, mod := f.respond, f.claims
	f.mu.Unlock()
	if respond != nil && respond(op, n, w) {
		return
	}
	if op == "deactivate" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"lease": f.lease(mod), "activation_id": "act_x"})
}

func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "code": code, "request_id": "req1"})
}

// client returns a client of f whose local clock is local and whose sleeps
// are recorded, not slept.
func (f *fake) client(t *testing.T, local time.Time, mod func(*Config)) (*Client, *[]time.Duration) {
	t.Helper()
	cfg := Config{BaseURL: f.srv.URL, TenantID: tenant, Product: product, LicenseKey: key, Keys: f.keys(), Fingerprint: fp, AppVersion: "1.0"}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var sleeps []time.Duration
	c.now = func() time.Time { return local }
	c.sleep = func(ctx context.Context, d time.Duration) error { sleeps = append(sleeps, d); return ctx.Err() }
	c.rand = func(int64) int64 { return 0 }
	return c, &sleeps
}

func TestActivate(t *testing.T) {
	f := newFake(t)
	local := f.iat.Add(-90 * time.Minute) // local clock 90 minutes behind the server
	c, _ := f.client(t, local, nil)
	l, err := c.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if l.ActivationID != "act_x" || l.Claims.LicenseID != "lic_x" {
		t.Errorf("lease %+v", l)
	}
	r := f.reqs[0]
	if r.op != "activate" || r.auth != "License "+key || r.idem == "" || r.body["fingerprint"] != fp.Fingerprint || r.body["fp_source"] != "machine-id" ||
		r.body["app_version"] != "1.0" || r.body["sdk_version"] != SDKVersion {
		t.Errorf("request %+v", r)
	}
	if c.ServerOffset() != 90*time.Minute {
		t.Errorf("offset %v", c.ServerOffset())
	}
	// Checked at max(local, server-adjusted): the server's time, so the lease
	// expires by server time, not 90 minutes late.
	claims, st, err := c.Current()
	if err != nil || st != licensefile.StatusValid || claims.LicenseID != "lic_x" {
		t.Errorf("Current = %v %v", st, err)
	}
	c.now = func() time.Time { return local.Add(61 * time.Minute) } // server time 13:01: past exp (13:00)
	if _, _, err := c.Current(); !errors.Is(err, licensefile.ErrExpired) {
		t.Errorf("Current after exp = %v", err)
	}
}

func TestBadLeasesAreNotUsed(t *testing.T) {
	f := newFake(t)
	other := newFake(t)
	for name, tc := range map[string]struct {
		claims  func(*licensefile.Claims)
		respond func(op string, n int, w http.ResponseWriter) bool
	}{
		"another product":     {claims: func(c *licensefile.Claims) { c.Product = "other" }},
		"another machine":     {claims: func(c *licensefile.Claims) { c.Binding.Fingerprint = "sha256:" + strings.Repeat("cd", 32) }},
		"another tenant":      {claims: func(c *licensefile.Claims) { c.Tenant = "tnt_other" }},
		"expired at its iat":  {claims: func(c *licensefile.Claims) { e := c.IssuedAt.Add(-time.Minute); c.Expires = &e }},
		"not yet valid":       {claims: func(c *licensefile.Claims) { nbf := c.IssuedAt.Add(time.Hour); c.NotBefore = &nbf }},
		"unknown signing key": {respond: lease(other.lease(nil))},
		"tampered":            {respond: lease(strings.Replace(f.lease(nil), "lf1.k1.", "lf1.k1.A", 1))},
		"not a lease":         {respond: lease("hello")},
		"not JSON":            {respond: func(_ string, _ int, w http.ResponseWriter) bool { _, _ = w.Write([]byte("{")); return true }},
	} {
		t.Run(name, func(t *testing.T) {
			f.claims, f.respond = tc.claims, tc.respond
			store := &memStore{}
			c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = store })
			if _, err := c.Activate(context.Background()); !errors.Is(err, ErrBadLease) {
				t.Fatalf("err = %v", err)
			}
			if _, _, err := c.Current(); !errors.Is(err, ErrNoLease) {
				t.Errorf("Current = %v", err)
			}
			if store.saved != nil {
				t.Errorf("stored %q", *store.saved)
			}
		})
	}
	// An older lease than the one held (a replay) is refused too.
	f.claims, f.respond = nil, nil
	c0, _ := f.client(t, f.iat, nil)
	if _, err := c0.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.claims = func(c *licensefile.Claims) { c.IssuedAt = c.IssuedAt.Add(-time.Minute) }
	if _, err := c0.Refresh(context.Background()); !errors.Is(err, ErrBadLease) {
		t.Errorf("older lease: %v", err)
	}
	// A bad refresh keeps the last good lease.
	f.claims, f.respond = nil, nil
	c, _ := f.client(t, f.iat, nil)
	good, err := c.Activate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.respond = lease(other.lease(nil))
	if _, err := c.Refresh(context.Background()); !errors.Is(err, ErrBadLease) {
		t.Fatalf("refresh = %v", err)
	}
	if claims, _, err := c.Current(); err != nil || claims.IssuedAt != good.Claims.IssuedAt || c.lease != good.File {
		t.Errorf("Current = %v %v", claims, err)
	}
}

func lease(file string) func(string, int, http.ResponseWriter) bool {
	return func(_ string, _ int, w http.ResponseWriter) bool {
		_ = json.NewEncoder(w).Encode(map[string]string{"lease": file, "activation_id": "act_x"})
		return true
	}
}

type memStore struct{ saved *string }

func (m *memStore) Load() (string, error) {
	if m.saved == nil {
		return "", nil
	}
	return *m.saved, nil
}
func (m *memStore) Save(s string) error { m.saved = &s; return nil }

func TestStore(t *testing.T) {
	f := newFake(t)
	store := &memStore{}
	c, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = store })
	l, err := c.Activate(context.Background())
	if err != nil || store.saved == nil || *store.saved != l.File {
		t.Fatalf("saved %v, %v", store.saved, err)
	}
	// A new client starts from the stored lease, re-verified.
	c2, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = store })
	c2.now = func() time.Time { return f.iat }
	if _, _, err := c2.Current(); err != nil {
		t.Errorf("from store: %v", err)
	}
	// Leases that don't verify are ignored: tampered, or for another key set.
	for name, s := range map[string]string{"tampered": l.File[:len(l.File)-4] + "AAAA", "foreign": newFake(t).lease(nil)} {
		bad := s
		c3, _ := f.client(t, f.iat, func(cfg *Config) { cfg.Store = &memStore{saved: &bad} })
		if _, _, err := c3.Current(); !errors.Is(err, ErrNoLease) {
			t.Errorf("%s stored lease used: %v", name, err)
		}
	}
	// Deactivate frees the seat and drops the lease, stored too.
	if err := c.Deactivate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Current(); !errors.Is(err, ErrNoLease) || *store.saved != "" {
		t.Errorf("after deactivate: %v, stored %q", err, *store.saved)
	}
	if r := f.reqs[len(f.reqs)-1]; r.op != "deactivate" || r.body["fingerprint"] != fp.Fingerprint || len(r.body) != 1 {
		t.Errorf("deactivate request %+v", r)
	}
}

func TestRetries(t *testing.T) {
	f := newFake(t)
	f.respond = func(_ string, n int, w http.ResponseWriter) bool {
		switch n {
		case 1:
			w.Header().Set("Retry-After", "7")
			problem(w, 503, "")
			return true
		case 2:
			w.Header().Set("Retry-After", f.iat.Add(40*time.Second).Format(http.TimeFormat))
			problem(w, 429, "rate_limited")
			return true
		case 3:
			problem(w, 409, "idempotency_in_progress")
			return true
		}
		return false
	}
	c, sleeps := f.client(t, f.iat, nil)
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.reqs) != 4 || f.reqs[0].idem == "" || f.reqs[1].idem != f.reqs[0].idem || f.reqs[3].idem != f.reqs[0].idem {
		t.Errorf("requests %+v", f.reqs)
	}
	// Retry-After in seconds, as an HTTP date, then backoff (3rd attempt: 4s, jitter 0 → 2s).
	if want := []time.Duration{7 * time.Second, 40 * time.Second, 2 * time.Second}; !equal(*sleeps, want) {
		t.Errorf("sleeps %v, want %v", *sleeps, want)
	}
	// A new Activate is a new request: another key.
	f.respond = nil
	if _, err := c.Activate(context.Background()); err != nil || f.reqs[4].idem == f.reqs[0].idem {
		t.Errorf("second activate: %v %q", err, f.reqs[4].idem)
	}
	// Refresh carries none.
	if _, err := c.Refresh(context.Background()); err != nil || f.reqs[5].idem != "" {
		t.Errorf("refresh: %v %q", err, f.reqs[5].idem)
	}

	// Give up after MaxAttempts; a huge Retry-After is capped.
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool {
		w.Header().Set("Retry-After", "999999")
		problem(w, 503, "")
		return true
	}
	c, sleeps = f.client(t, f.iat, func(cfg *Config) { cfg.MaxAttempts = 3 })
	before := len(f.reqs)
	_, err := c.Activate(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || !errors.Is(err, ErrServer) || ae.Status != 503 || len(f.reqs)-before != 3 || !equal(*sleeps, []time.Duration{maxRetryAfter, maxRetryAfter}) {
		t.Errorf("err %v, %d requests, sleeps %v", err, len(f.reqs)-before, *sleeps)
	}
}

func equal(a, b []time.Duration) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestErrorCodes(t *testing.T) {
	f := newFake(t)
	for code, want := range map[string]error{
		"unauthenticated": ErrUnauthenticated, "invalid_request": ErrInvalidRequest, "license_suspended": ErrSuspended,
		"license_revoked": ErrRevoked, "license_expired": ErrExpired, "activation_limit_reached": ErrActivationLimit,
		"rehost_limit_reached": ErrRehostLimit, "binding_mismatch": ErrBindingMismatch, "not_activated": ErrNotActivated,
		"offline_seat": ErrOfflineSeat, "idempotency_key_reused": ErrIdempotencyReused,
	} {
		f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 403, code); return true }
		c, sleeps := f.client(t, f.iat, nil)
		before := len(f.reqs)
		_, err := c.Activate(context.Background())
		var ae *APIError
		if !errors.Is(err, want) || !errors.As(err, &ae) || ae.Code != code || ae.RequestID != "req1" {
			t.Errorf("%s: %v", code, err)
		}
		if len(f.reqs)-before != 1 || len(*sleeps) != 0 { // refusals aren't retried
			t.Errorf("%s retried", code)
		}
	}
}

func TestRun(t *testing.T) {
	f := newFake(t)
	c, sleeps := f.client(t, f.iat.Add(-10*time.Minute), nil) // local 10 minutes behind
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	refreshes := 0
	f.respond = func(op string, n int, w http.ResponseWriter) bool {
		refreshes++
		switch refreshes {
		case 2:
			w.Header().Set("Retry-After", "120")
			problem(w, 503, "")
			return true
		case 4:
			cancel()
		}
		return false
	}
	c.cfg.MaxAttempts = 1
	if err := c.Run(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v", err)
	}
	// From refresh_after on (30 min after iat, by server time); after the
	// 503, not before its Retry-After; then refresh_after again.
	if len(*sleeps) < 3 || (*sleeps)[0] != 30*time.Minute || (*sleeps)[1] != 30*time.Minute || (*sleeps)[2] < 120*time.Second {
		t.Errorf("sleeps %v", *sleeps)
	}
	// An offline seat stops Run too; the lease stays until it ends.
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 409, "offline_seat"); return true }
	if err := c.Run(context.Background(), nil); !errors.Is(err, ErrOfflineSeat) {
		t.Errorf("Run on an offline seat = %v", err)
	}
	if _, _, err := c.Current(); err != nil {
		t.Errorf("lease forgotten on offline_seat: %v", err)
	}
	// Revoked stops Run with the error.
	f.respond = func(_ string, _ int, w http.ResponseWriter) bool { problem(w, 403, "license_revoked"); return true }
	var reported error
	if err := c.Run(context.Background(), func(err error) { reported = err }); !errors.Is(err, ErrRevoked) || !errors.Is(reported, ErrRevoked) {
		t.Errorf("Run = %v, reported %v", err, reported)
	}
}

// Each verified lease resets the clock guard to its iat (ADR-0018), never to
// the HTTP Date header.
func TestClockReset(t *testing.T) {
	f := newFake(t)
	st := &clockStore{}
	g, err := clock.New(st, key, clock.Options{})
	if err != nil {
		t.Fatal(err)
	}
	// A mark far ahead (a clock once set forward): the lease's iat lowers it.
	if err := g.Observe(f.iat.Add(48*time.Hour), f.iat.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	local := f.iat.Add(-3 * time.Hour) // the local clock is behind the server
	c, _ := f.client(t, local, func(cfg *Config) { cfg.Clock = g })
	if _, err := c.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The mark is the lease's iat, not the local time.
	if now, err := g.Now(local); err != nil || !now.Equal(f.iat) {
		t.Errorf("guard after activate: %v %v", now, err)
	}
	if _, st, err := c.Current(); err != nil || st != licensefile.StatusValid {
		t.Errorf("Current: %v %v", st, err)
	}
	// Current goes through the guard: a clock more than the tolerance behind
	// its mark is a rollback.
	if err := g.Reset(f.iat.Add(48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Current(); !errors.Is(err, clock.ErrRollback) {
		t.Errorf("Current behind the mark: %v", err)
	}
}

type clockStore struct{ b []byte }

func (s *clockStore) Update(fn func([]byte) ([]byte, error)) error {
	nb, err := fn(s.b)
	if err == nil && nb != nil {
		s.b = nb
	}
	return err
}

func TestNewValidates(t *testing.T) {
	f := newFake(t)
	for name, mod := range map[string]func(*Config){
		"no URL":         func(c *Config) { c.BaseURL = "" },
		"not http":       func(c *Config) { c.BaseURL = "ftp://x" },
		"no tenant":      func(c *Config) { c.TenantID = "" },
		"no key":         func(c *Config) { c.LicenseKey = "" },
		"no trusted key": func(c *Config) { c.Keys = nil },
		"no fingerprint": func(c *Config) { c.Fingerprint = fingerprint.Result{} },
	} {
		cfg := Config{BaseURL: f.srv.URL, TenantID: tenant, Product: product, LicenseKey: key, Keys: f.keys(), Fingerprint: fp}
		mod(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
