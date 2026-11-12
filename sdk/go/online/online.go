// Package online is the SDK's client for the activation API (ADR-0004,
// ADR-0034): activate this machine with a license key, keep its signed lease
// fresh, deactivate it.
//
// Every lease the server returns is verified with licensefile (signature
// against the vendor's embedded keys, claims, product, tenant and this
// machine's fingerprint) before it is used or cached; anything else is
// discarded. A cached lease keeps the app running through server outages
// until max_offline or exp (+ grace) runs out.
//
//	c, err := online.New(online.Config{BaseURL: "https://api.vendor.example", TenantID: "tnt_…",
//		Product: "acme-db", LicenseKey: key, Keys: trustedKeys, Fingerprint: fp})
//	lease, err := c.Activate(ctx)       // once per machine
//	go c.Run(ctx, func(err error) {})  // refreshes from refresh_after on
//	claims, status, err := c.Current() // for each license check
//
// Time (ADR-0018): each verified lease's iat is server time. The client
// keeps the offset to the local clock and checks with max(local,
// local+offset); with Config.Clock it also resets the clock guard's
// high-water mark to the iat. The HTTP Date header is never trusted.
package online

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
	"licenseforge.io/licenseforge/sdk/go/fingerprint"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// Errors for the API's stable problem codes. An *APIError wraps one of them
// (errors.Is works) and carries the details.
var (
	ErrUnauthenticated   = errors.New("online: invalid license key")
	ErrInvalidRequest    = errors.New("online: invalid request")
	ErrSuspended         = errors.New("online: license suspended")
	ErrRevoked           = errors.New("online: license revoked")
	ErrExpired           = errors.New("online: license expired")
	ErrActivationLimit   = errors.New("online: every seat is taken; deactivate a machine first")
	ErrRehostLimit       = errors.New("online: the license's machines have moved as often as it allows")
	ErrBindingMismatch   = errors.New("online: the fingerprint doesn't bind what the license requires")
	ErrNotActivated      = errors.New("online: this machine isn't activated")
	ErrOfflineSeat       = errors.New("online: this machine's seat is offline; return it with a deactivation receipt")
	ErrRateLimited       = errors.New("online: rate limited")
	ErrIdempotencyReused = errors.New("online: idempotency key reused")
	ErrInProgress        = errors.New("online: a request with this idempotency key is in progress")
	ErrServer            = errors.New("online: server error")
	// ErrBadLease means the server's answer didn't verify: a wrong or
	// unknown signing key, another product, tenant or machine, or a
	// malformed lease. It is never cached.
	ErrBadLease = errors.New("online: lease doesn't verify")
	// ErrNoLease means there is no verified lease yet (activate first).
	ErrNoLease = errors.New("online: no lease")
	// ErrSuperseded means Forget or Deactivate ran while the call was in
	// flight: its lease isn't used.
	ErrSuperseded = errors.New("online: the lease was forgotten while the call ran")
)

var codes = map[string]error{
	"unauthenticated": ErrUnauthenticated, "invalid_request": ErrInvalidRequest,
	"license_suspended": ErrSuspended, "license_revoked": ErrRevoked, "license_expired": ErrExpired,
	"activation_limit_reached": ErrActivationLimit, "rehost_limit_reached": ErrRehostLimit,
	"binding_mismatch": ErrBindingMismatch, "not_activated": ErrNotActivated, "offline_seat": ErrOfflineSeat, "rate_limited": ErrRateLimited,
	"idempotency_key_reused": ErrIdempotencyReused, "idempotency_in_progress": ErrInProgress,
}

// APIError is a refusal from the server (RFC 9457 problem).
type APIError struct {
	Status     int
	Code       string
	Detail     string
	RequestID  string
	RetryAfter time.Duration // from Retry-After, if sent
	kind       error
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%v (%d %s, request %s)", e.kind, e.Status, e.Code, e.RequestID)
}

func (e *APIError) Unwrap() error { return e.kind }

// Store keeps the verified lease across restarts (a file, a Kubernetes
// ConfigMap or Secret, ADR-0004). Leases are re-verified when loaded.
type Store interface {
	Load() (string, error)   // "" if none
	Save(lease string) error // "" means delete the stored lease
	// Implementations must not call back into the Client: Save runs while
	// the Client holds its commit lock.
}

// Config configures a Client. Everything but HTTPClient, Store, Clock and
// the versions is required.
type Config struct {
	BaseURL     string // e.g. https://api.vendor.example (the server's API host)
	TenantID    string // tnt_…, the license's tenant claim
	Product     string // the product slug the app expects (the product claim)
	LicenseKey  string
	Keys        licensefile.KeySet // trusted signing keys embedded in the build
	Fingerprint fingerprint.Result // fingerprint.Compute(ctx, TenantID, Product, …)
	Hostname    string
	AppVersion  string
	// HTTPClient: nil means a client with a 30s timeout that follows no
	// redirects. A custom client should refuse redirects too
	// (CheckRedirect returning http.ErrUseLastResponse): the license key is
	// in a header.
	HTTPClient *http.Client
	Store      Store        // nil: memory only (a warning: nothing survives a restart)
	Clock      *clock.Guard // optional: reset to each lease's iat (ADR-0018)
	// ClockTolerance and BuildDate are passed to the claim checks in
	// Current: how far iat may be ahead (nil: the default), and the app's
	// build date for updates_until (zero: not checked).
	ClockTolerance *time.Duration
	BuildDate      time.Time
	// MaxAttempts per call for retryable failures (network, 429, 5xx,
	// in progress). 0: 4.
	MaxAttempts int
}

// SDKVersion is sent with activations and refreshes.
const SDKVersion = "go/0.1.0"

// Client talks to the activation API for one license on one machine. It is
// safe for concurrent use.
type Client struct {
	cfg  Config
	base *url.URL

	commit   sync.Mutex // one lease change at a time: compare, set, clock reset, store
	mu       sync.Mutex // guards the fields below
	lease    string
	claims   *licensefile.Claims
	offset   time.Duration // server time minus local time, from the last lease
	gen      uint64        // bumped by Forget: in-flight calls from before don't commit
	ver      uint64        // bumped by every commit and Forget: forgetIf keeps a newer lease
	warnings []error       // non-fatal problems not yet reported (Warnings, Run)

	now   func() time.Time
	sleep func(context.Context, time.Duration) error
	rand  func(n int64) int64
}

// New checks cfg and loads a cached lease from cfg.Store if one verifies.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	switch {
	case err != nil || u.Host == "" || !secureBase(u):
		return nil, errors.New("online: BaseURL must be an https URL (http only for loopback hosts): the license key travels with each request")
	case cfg.TenantID == "" || cfg.Product == "" || cfg.LicenseKey == "" || len(cfg.Keys) == 0 || cfg.Fingerprint.Fingerprint == "":
		return nil, errors.New("online: TenantID, Product, LicenseKey, Keys and Fingerprint are required")
	case cfg.Fingerprint.Binding != string(licensefile.BindMachine) && cfg.Fingerprint.Binding != string(licensefile.BindCluster):
		return nil, errors.New("online: Fingerprint.Binding must be machine or cluster")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 4
	}
	c := &Client{cfg: cfg, base: u, now: time.Now, sleep: sleepCtx, rand: cryptoRand}
	if cfg.Store == nil {
		c.warn(errors.New("online: no Store: the lease lives in memory only and is lost on restart (ADR-0018)"))
		return c, nil
	}
	s, err := cfg.Store.Load()
	switch {
	case err != nil:
		c.warn(fmt.Errorf("online: loading the stored lease: %w", err))
	case s != "":
		// Verified like a fresh one; Current checks it against the time on
		// every use. Anything that doesn't verify is not used.
		claims, err := c.verifyFresh(s)
		if err != nil {
			c.warn(fmt.Errorf("online: stored lease not used: %w", err))
			break
		}
		c.lease, c.claims = s, claims
		if cfg.Clock != nil {
			// A cache starting empty must not let an old lease pass for
			// new: its iat is a genuine time the clock has reached.
			if err := cfg.Clock.Observe(claims.IssuedAt, c.now()); err != nil {
				c.warn(fmt.Errorf("online: clock: %w", err))
			}
		}
	}
	return c, nil
}

// secureBase: https, or http to a loopback host (tests, a local agent).
func secureBase(u *url.URL) bool {
	return u.Scheme == "https" || u.Scheme == "http" && loopback(u.Hostname())
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) warn(err error) {
	c.mu.Lock()
	c.warnings = append(c.warnings, err)
	c.mu.Unlock()
}

// Warnings returns, and forgets, the non-fatal problems since the last
// call: a memory-only store, a stored lease that couldn't be loaded or
// didn't verify, a clock guard or store that couldn't be written. Run
// reports them to its onErr too.
func (c *Client) Warnings() []error {
	c.mu.Lock()
	defer c.mu.Unlock()
	w := c.warnings
	c.warnings = nil
	return w
}

// Lease is a verified lease.
type Lease struct {
	File         string
	Claims       *licensefile.Claims
	ActivationID string
}

type leaseResponse struct {
	Lease        string `json:"lease"`
	ActivationID string `json:"activation_id"`
}

// Activate activates this machine and returns the verified lease. Retries
// reuse one Idempotency-Key, so a retry never takes a second seat.
func (c *Client) Activate(ctx context.Context) (*Lease, error) {
	l, _, err := c.leaseCall(ctx, "activate", rand.Text(), c.cfg.MaxAttempts)
	return l, err
}

// Refresh gets a new lease for this machine (also the SDK's validate).
// ErrNotActivated means the activation is gone (deactivated or reset):
// activate again.
func (c *Client) Refresh(ctx context.Context) (*Lease, error) {
	l, _, err := c.leaseCall(ctx, "refresh", "", c.cfg.MaxAttempts)
	return l, err
}

// Deactivate frees this machine's seat and drops the cached lease. A
// machine the server already has as not activated (deactivated before, or
// the first attempt's answer was lost) is success too.
func (c *Client) Deactivate(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"fingerprint": c.cfg.Fingerprint.Fingerprint})
	if _, err := c.call(ctx, "deactivate", body, "", http.StatusNoContent, c.cfg.MaxAttempts); err != nil && !errors.Is(err, ErrNotActivated) {
		return err
	}
	return c.Forget()
}

// Forget drops the cached and stored lease without contacting the server.
// It is the way out of a lease that can't be replaced: one issued with a
// far-future iat by a server whose clock was wrong makes every correct
// later lease look older (a replay) and be refused. Forget, then Refresh
// (or Activate).
func (c *Client) Forget() error { return c.forget(nil) }

// forgetIf forgets only if no lease was committed or forgotten since
// version ver: a refusal of an older call mustn't drop a lease an
// Activate committed meanwhile.
func (c *Client) forgetIf(ver uint64) error { return c.forget(&ver) }

func (c *Client) forget(ifVer *uint64) error {
	c.commit.Lock()
	defer c.commit.Unlock()
	c.mu.Lock()
	if ifVer != nil && c.ver != *ifVer {
		c.mu.Unlock()
		return nil
	}
	c.lease, c.claims, c.offset = "", nil, 0
	c.gen++
	c.ver++
	c.mu.Unlock()
	if c.cfg.Store != nil {
		return c.cfg.Store.Save("")
	}
	return nil
}

// leaseCall makes the call (up to attempts) and commits its lease. It
// returns the version the call started from (for forgetIf). Only a Forget
// meanwhile supersedes the call: concurrent refreshes don't, and the iat
// comparison keeps the newest of them.
func (c *Client) leaseCall(ctx context.Context, op, idemKey string, attempts int) (*Lease, uint64, error) {
	body, _ := json.Marshal(map[string]string{
		"fingerprint": c.cfg.Fingerprint.Fingerprint, "fp_source": string(c.cfg.Fingerprint.Source),
		"hostname": c.cfg.Hostname, "app_version": c.cfg.AppVersion, "sdk_version": SDKVersion,
	})
	c.mu.Lock()
	gen, ver := c.gen, c.ver
	c.mu.Unlock()
	raw, err := c.call(ctx, op, body, idemKey, http.StatusOK, attempts)
	if err != nil {
		return nil, ver, err
	}
	var r leaseResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, ver, fmt.Errorf("%w: %w", ErrBadLease, err)
	}
	local := c.now()
	claims, err := c.verifyFresh(r.Lease)
	if err != nil {
		return nil, ver, err
	}
	// One commit at a time, so the comparison, the cache, the clock and the
	// store all end with the same lease.
	c.commit.Lock()
	defer c.commit.Unlock()
	c.mu.Lock()
	if c.gen != gen { // forgotten (or deactivated) meanwhile: don't bring it back
		c.mu.Unlock()
		return nil, ver, ErrSuperseded
	}
	if c.claims != nil && claims.IssuedAt.Before(c.claims.IssuedAt) {
		// An older lease than the one held: a replay, which could otherwise
		// wind the clock guard back (ADR-0018).
		c.mu.Unlock()
		return nil, ver, fmt.Errorf("%w: issued before the current lease", ErrBadLease)
	}
	c.lease, c.claims, c.offset = r.Lease, claims, claims.IssuedAt.Sub(local)
	c.ver++
	c.mu.Unlock()
	// The lease is in use from here on; the clock and store failing doesn't
	// change that, so they are warnings (Warnings, Run's onErr).
	if c.cfg.Clock != nil {
		if err := c.cfg.Clock.Reset(claims.IssuedAt); err != nil { // an authenticated server time
			c.warn(fmt.Errorf("online: clock not reset: %w", err))
		}
	}
	if c.cfg.Store != nil {
		if err := c.cfg.Store.Save(r.Lease); err != nil {
			c.warn(fmt.Errorf("online: lease not stored: %w", err))
		}
	}
	return &Lease{File: r.Lease, Claims: cloneClaims(claims), ActivationID: r.ActivationID}, ver, nil
}

// verifyFresh checks a lease: the signature against the trusted keys, the
// claims as of the lease's own iat (server time; the local clock may be
// off), the product, this machine's fingerprint and the tenant.
func (c *Client) verifyFresh(lease string) (*licensefile.Claims, error) {
	payload, _, err := licensefile.Verify(lease, c.cfg.Keys)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadLease, err)
	}
	claims, err := licensefile.ParseClaims(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadLease, err)
	}
	if _, err := claims.Check(licensefile.CheckOptions{Now: claims.IssuedAt, Product: c.cfg.Product, Fingerprint: c.cfg.Fingerprint.Fingerprint}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadLease, err)
	}
	if claims.Tenant != c.cfg.TenantID {
		return nil, fmt.Errorf("%w: lease for tenant %q", ErrBadLease, claims.Tenant)
	}
	// An online lease always binds this machine or cluster: an unbound one
	// would run anywhere.
	if string(claims.Binding.Type) != c.cfg.Fingerprint.Binding {
		return nil, fmt.Errorf("%w: lease binds %q, not %q", ErrBadLease, claims.Binding.Type, c.cfg.Fingerprint.Binding)
	}
	return claims, nil
}

// cloneClaims copies c, entitlements included, so callers can't change the
// cached lease.
func cloneClaims(c *licensefile.Claims) *licensefile.Claims {
	if c == nil {
		return nil
	}
	cp := *c
	cp.Entitlements.Features = slices.Clone(c.Entitlements.Features)
	cp.Entitlements.Limits = maps.Clone(c.Entitlements.Limits)
	cp.NotBefore, cp.Expires, cp.RefreshAfter, cp.UpdatesUntil = clonePtr(c.NotBefore), clonePtr(c.Expires), clonePtr(c.RefreshAfter), clonePtr(c.UpdatesUntil)
	cp.MaxOffline = clonePtr(c.MaxOffline)
	return &cp
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func (c *Client) checkOptions() licensefile.CheckOptions {
	local := c.now()
	c.mu.Lock()
	offset := c.offset
	c.mu.Unlock()
	now := local
	if adj := local.Add(offset); adj.After(now) { // ADR-0018: max(local, server-adjusted)
		now = adj
	}
	return licensefile.CheckOptions{Now: now, Product: c.cfg.Product, Fingerprint: c.cfg.Fingerprint.Fingerprint,
		ClockTolerance: c.cfg.ClockTolerance, BuildDate: c.cfg.BuildDate}
}

// Current checks the cached lease now and returns its claims and status
// (valid, or grace: usable with a warning). Any error means: don't run as
// licensed. With Config.Clock, the time also passes the rollback check.
func (c *Client) Current() (*licensefile.Claims, licensefile.Status, error) {
	c.mu.Lock()
	claims := c.claims
	c.mu.Unlock()
	if claims == nil {
		return nil, "", ErrNoLease
	}
	claims = cloneClaims(claims)
	o, err := c.currentOptions()
	if err != nil {
		return claims, "", err
	}
	st, err := claims.Check(o)
	return claims, st, err
}

// currentOptions are the check options Current uses: with Config.Clock,
// the time has passed the rollback check.
func (c *Client) currentOptions() (licensefile.CheckOptions, error) {
	o := c.checkOptions()
	if c.cfg.Clock != nil {
		t, err := c.cfg.Clock.Now(o.Now)
		if err != nil && !errors.Is(err, clock.ErrNotPersisted) {
			return o, err
		}
		o.Now = t
	}
	return o, nil
}

// ServerOffset is server time minus local time from the last lease (whole
// seconds: iat is).
func (c *Client) ServerOffset() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offset
}

// MinRefreshInterval is the least Run waits after a successful refresh,
// whatever refresh_after says: with max_offline 0 refresh_after is the
// lease's iat (ADR-0034), and the app refreshes before each check itself.
const MinRefreshInterval = time.Minute

// failMargin caps how long before the lease would fail Current Run wakes.
const failMargin = 2 * time.Minute

// wakeBounds bound how long Run waits with a lease that passes Current (0:
// no bound). half is half the time left to exp and to iat+max_offline
// (server time), so a refresh_after past them can't sleep through them.
// beforeFail is a margin (10% of what is left, at most failMargin) before
// Current would start failing by its own clock, which runs ahead of server
// time when the local clock is fast: refresh_after alone would let the
// lease lapse locally.
func (c *Client) wakeBounds(cl *licensefile.Claims, now time.Time) (half, beforeFail time.Duration) {
	bound := func(b *time.Duration, d time.Duration) {
		if d > 0 && (*b == 0 || d < *b) {
			*b = d
		}
	}
	var fail *time.Time
	if cl.MaxOffline != nil {
		off := cl.IssuedAt.Add(*cl.MaxOffline)
		bound(&half, off.Sub(now)/2)
		fail = &off
	}
	if cl.Expires != nil {
		bound(&half, cl.Expires.Sub(now)/2)
		if e := cl.Expires.Add(cl.Grace); fail == nil || e.Before(*fail) {
			fail = &e
		}
	}
	if o, err := c.currentOptions(); err == nil && fail != nil {
		left := fail.Sub(o.Now)
		bound(&beforeFail, left-min(left/10, failMargin))
	}
	return half, beforeFail
}

// Run refreshes the lease until ctx ends: from refresh_after on (without
// one, at half the time to exp, at most backoffMax), and on its first pass
// at once if the cached lease doesn't pass Current (a skewed clock after a
// restart); never sooner than MinRefreshInterval after a success, always
// with jitter. Times are scheduled in server time (the local clock plus the
// offset from the last lease), as refresh_after and exp are; but while the
// lease passes Current, Run wakes no later than wakeBounds allow: before
// the lease would fail by Current's clock (a fast local clock), and at half
// the time left to exp and to iat+max_offline. A lease that fails Current right after a refresh
// gets the server's schedule alone (refreshing can't fix it). Each pass is
// one request: failures are retried by the next pass, with exponential
// backoff and jitter, not sooner than the server's Retry-After. Every
// failure and warning goes to onErr.
//
// Run returns on ctx's end; with ErrNoLease when there is no lease to keep
// fresh; or with a refusal retrying can't fix, which the app must act on:
// ErrNotActivated (the seat was freed: Activate again), ErrRevoked,
// ErrUnauthenticated or ErrBindingMismatch (stop running as licensed), or
// ErrOfflineSeat (the machine was activated offline since: use its offline
// file). On
// ErrRevoked (403) and ErrNotActivated (404) from the API it forgets the
// lease first, unless a newer one was committed meanwhile: the server has
// said this machine is no longer licensed, so Current fails from then on.
func (c *Client) Run(ctx context.Context, onErr func(error)) error {
	report := func(err error) {
		if onErr != nil && err != nil {
			onErr(err)
		}
	}
	failures, retry, refreshed := 0, time.Duration(0), false
	for {
		for _, w := range c.Warnings() {
			report(w)
		}
		c.mu.Lock()
		claims := c.claims
		c.mu.Unlock()
		if claims == nil {
			return ErrNoLease
		}
		var wait time.Duration
		now := c.now().Add(c.ServerOffset()) // refresh_after and exp are server times
		_, _, invalid := c.Current()
		switch {
		case failures > 0:
			wait = max(c.backoff(failures), retry) // never sooner than the server asked
		case invalid != nil && !refreshed:
			wait = 0 // a fresh lease may fix it; once refreshed, it can't (e.g. updates_until)
		case claims.RefreshAfter != nil:
			wait = claims.RefreshAfter.Sub(now)
		case claims.Expires != nil:
			wait = min(backoffMax, claims.Expires.Sub(now)/2)
		default:
			wait = backoffMax
		}
		var half, beforeFail time.Duration
		if failures == 0 && invalid == nil {
			half, beforeFail = c.wakeBounds(claims, now)
		}
		if half > 0 {
			wait = min(wait, half)
		}
		wait = max(wait, 0)
		wait += time.Duration(c.rand(int64(wait/10) + 1)) // spread fleets out
		if beforeFail > 0 && wait > beforeFail {
			wait = beforeFail - time.Duration(c.rand(int64(beforeFail/10)+1)) // early, still spread
		}
		if refreshed && failures == 0 {
			wait = max(wait, MinRefreshInterval)
		}
		if err := c.sleep(ctx, wait); err != nil {
			return err
		}
		_, ver, err := c.leaseCall(ctx, "refresh", "", 1) // one attempt: this loop retries
		if err == nil {
			failures, retry, refreshed = 0, 0, true
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		report(err)
		var ae *APIError
		isAPI := errors.As(err, &ae)
		if isAPI && (ae.Status == http.StatusForbidden && errors.Is(err, ErrRevoked) || ae.Status == http.StatusNotFound && errors.Is(err, ErrNotActivated)) {
			if ferr := c.forgetIf(ver); ferr != nil {
				report(ferr)
			}
			return err
		}
		if errors.Is(err, ErrRevoked) || errors.Is(err, ErrNotActivated) {
			return err // claimed with an unexpected status: stop, but keep the lease
		}
		if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrBindingMismatch) || errors.Is(err, ErrOfflineSeat) {
			return err // the lease is kept until it ends
		}
		failures, retry = failures+1, 0
		if isAPI {
			retry = ae.RetryAfter
		}
	}
}

const (
	backoffBase = time.Second
	backoffMax  = 5 * time.Minute
)

// backoff is the wait after n consecutive failures: exponential with
// jitter in its upper half, until it reaches backoffMax, which is never
// shortened (a long outage costs one request per backoffMax).
func (c *Client) backoff(n int) time.Duration {
	d := backoffBase << min(n-1, 20)
	if d >= backoffMax {
		return backoffMax
	}
	return d/2 + time.Duration(c.rand(int64(d/2)+1))
}

// call POSTs body to op and returns the response body when the status is
// want. Network errors, 429, 5xx and idempotency_in_progress are retried up
// to MaxAttempts, waiting Retry-After when the server sends it.
func (c *Client) call(ctx context.Context, op string, body []byte, idemKey string, want, attempts int) ([]byte, error) {
	u := c.base.JoinPath("api/v1/activation/tenants", c.cfg.TenantID, op).String()
	for attempt := 1; ; attempt++ {
		raw, retryAfter, err := c.once(ctx, u, body, idemKey, want)
		if err == nil || !retryable(err) || attempt >= attempts || ctx.Err() != nil {
			return raw, err
		}
		wait := c.backoff(attempt)
		if retryAfter > 0 {
			wait = retryAfter
		}
		if serr := c.sleep(ctx, wait); serr != nil {
			return nil, errors.Join(err, serr)
		}
	}
}

func retryable(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return true // network errors
	}
	return ae.Status == http.StatusTooManyRequests || ae.Status >= 500 || errors.Is(err, ErrInProgress)
}

func (c *Client) once(ctx context.Context, u string, body []byte, idemKey string, want int) ([]byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "License "+c.cfg.LicenseKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "licenseforge-sdk-"+SDKVersion)
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode == want {
		return raw, 0, nil
	}
	var p struct {
		Code      string `json:"code"`
		Detail    string `json:"detail"`
		RequestID string `json:"request_id"`
	}
	ae := &APIError{Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header.Get("Retry-After"), c.now())}
	// The stable codes count only in a problem answer with a 4xx status: a
	// proxy's error page or a garbled 5xx must not read as "revoked". A 5xx
	// problem's code and detail (e.g. no_signing_key) are kept to report,
	// but it stays ErrServer.
	if mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mt == "application/problem+json" &&
		resp.StatusCode >= 400 && json.Unmarshal(raw, &p) == nil {
		ae.Code, ae.Detail, ae.RequestID = p.Code, p.Detail, p.RequestID
		if resp.StatusCode < 500 {
			ae.kind = codes[p.Code]
		}
	}
	switch {
	case ae.kind != nil:
	case resp.StatusCode >= 500:
		ae.kind = ErrServer
	case resp.StatusCode == http.StatusTooManyRequests:
		ae.kind = ErrRateLimited
	default:
		ae.kind = fmt.Errorf("online: unexpected status %d", resp.StatusCode)
	}
	return nil, ae.RetryAfter, ae
}

// maxRetryAfter caps a server's Retry-After, so a bad header can't stall
// the client for days.
const maxRetryAfter = 10 * time.Minute

// retryAfter parses Retry-After: delay-seconds or an HTTP date (RFC 9110).
func retryAfter(h string, now time.Time) time.Duration {
	if h == "" {
		return 0
	}
	var d time.Duration
	if s, err := strconv.Atoi(h); err == nil && s >= 0 {
		d = time.Duration(s) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = t.Sub(now)
	}
	return max(0, min(d, maxRetryAfter))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func cryptoRand(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}
