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
	"math/big"
	"net/http"
	"net/url"
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
)

var codes = map[string]error{
	"unauthenticated": ErrUnauthenticated, "invalid_request": ErrInvalidRequest,
	"license_suspended": ErrSuspended, "license_revoked": ErrRevoked, "license_expired": ErrExpired,
	"activation_limit_reached": ErrActivationLimit, "rehost_limit_reached": ErrRehostLimit,
	"binding_mismatch": ErrBindingMismatch, "not_activated": ErrNotActivated, "rate_limited": ErrRateLimited,
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
	Load() (string, error) // "" if none
	Save(lease string) error
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
	HTTPClient  *http.Client // nil: a client with a 30s timeout
	Store       Store        // nil: memory only
	Clock       *clock.Guard // optional: reset to each lease's iat (ADR-0018)
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

	mu     sync.Mutex
	lease  string
	claims *licensefile.Claims
	offset time.Duration // server time minus local time, from the last lease

	now   func() time.Time
	sleep func(context.Context, time.Duration) error
	rand  func(n int64) int64
}

// New checks cfg and loads a cached lease from cfg.Store if one verifies.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	switch {
	case err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "":
		return nil, errors.New("online: BaseURL must be an http(s) URL")
	case cfg.TenantID == "" || cfg.Product == "" || cfg.LicenseKey == "" || len(cfg.Keys) == 0 || cfg.Fingerprint.Fingerprint == "":
		return nil, errors.New("online: TenantID, Product, LicenseKey, Keys and Fingerprint are required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 4
	}
	c := &Client{cfg: cfg, base: u, now: time.Now, sleep: sleepCtx, rand: cryptoRand}
	if cfg.Store != nil {
		if s, err := cfg.Store.Load(); err == nil && s != "" {
			// Verified like a fresh one; Current checks it against the time
			// on every use. Anything that doesn't verify is ignored.
			if claims, err := c.verifyFresh(s); err == nil {
				c.lease, c.claims = s, claims
			}
		}
	}
	return c, nil
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
	return c.leaseCall(ctx, "activate", rand.Text())
}

// Refresh gets a new lease for this machine (also the SDK's validate).
// ErrNotActivated means the activation is gone (deactivated or reset):
// activate again.
func (c *Client) Refresh(ctx context.Context) (*Lease, error) {
	return c.leaseCall(ctx, "refresh", "")
}

// Deactivate frees this machine's seat and drops the cached lease.
func (c *Client) Deactivate(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"fingerprint": c.cfg.Fingerprint.Fingerprint})
	if _, err := c.call(ctx, "deactivate", body, "", http.StatusNoContent); err != nil {
		return err
	}
	c.mu.Lock()
	c.lease, c.claims = "", nil
	c.mu.Unlock()
	if c.cfg.Store != nil {
		return c.cfg.Store.Save("")
	}
	return nil
}

func (c *Client) leaseCall(ctx context.Context, op, idemKey string) (*Lease, error) {
	body, _ := json.Marshal(map[string]string{
		"fingerprint": c.cfg.Fingerprint.Fingerprint, "fp_source": string(c.cfg.Fingerprint.Source),
		"hostname": c.cfg.Hostname, "app_version": c.cfg.AppVersion, "sdk_version": SDKVersion,
	})
	raw, err := c.call(ctx, op, body, idemKey, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var r leaseResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadLease, err)
	}
	local := c.now()
	claims, err := c.verifyFresh(r.Lease)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.claims != nil && claims.IssuedAt.Before(c.claims.IssuedAt) {
		// An older lease than the one held: a replay, which could otherwise
		// wind the clock guard back (ADR-0018).
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: issued before the current lease", ErrBadLease)
	}
	c.lease, c.claims, c.offset = r.Lease, claims, claims.IssuedAt.Sub(local)
	c.mu.Unlock()
	if c.cfg.Clock != nil {
		_ = c.cfg.Clock.Reset(claims.IssuedAt) // an authenticated server time; a write failure isn't the lease's
	}
	if c.cfg.Store != nil {
		if err := c.cfg.Store.Save(r.Lease); err != nil {
			return &Lease{File: r.Lease, Claims: claims, ActivationID: r.ActivationID}, fmt.Errorf("online: lease not stored: %w", err)
		}
	}
	return &Lease{File: r.Lease, Claims: claims, ActivationID: r.ActivationID}, nil
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
	return claims, nil
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
	return licensefile.CheckOptions{Now: now, Product: c.cfg.Product, Fingerprint: c.cfg.Fingerprint.Fingerprint}
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
	o := c.checkOptions()
	if c.cfg.Clock != nil {
		t, err := c.cfg.Clock.Now(o.Now)
		if err != nil && !errors.Is(err, clock.ErrNotPersisted) {
			return claims, "", err
		}
		o.Now = t
	}
	st, err := claims.Check(o)
	return claims, st, err
}

// ServerOffset is server time minus local time from the last lease (whole
// seconds: iat is).
func (c *Client) ServerOffset() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offset
}

// Run refreshes the lease from its refresh_after on until ctx ends, retrying
// failures with exponential backoff and jitter (and the server's
// Retry-After). It reports every failure to onErr and returns on ctx's end
// or a refusal retrying can't fix (revoked, invalid key, not activated,
// binding), with that error.
func (c *Client) Run(ctx context.Context, onErr func(error)) error {
	failures, retry := 0, time.Duration(0)
	for {
		c.mu.Lock()
		claims := c.claims
		c.mu.Unlock()
		wait := time.Duration(0)
		if claims == nil {
			return ErrNoLease
		}
		if claims.RefreshAfter != nil {
			wait = claims.RefreshAfter.Sub(c.checkOptions().Now)
		}
		if failures > 0 {
			wait = max(c.backoff(failures), retry) // never sooner than the server asked
		}
		if wait > 0 {
			wait += time.Duration(c.rand(int64(wait/10) + 1)) // spread fleets out
		}
		if err := c.sleep(ctx, wait); err != nil {
			return err
		}
		_, err := c.Refresh(ctx)
		switch {
		case err == nil:
			failures = 0
			continue
		case ctx.Err() != nil:
			return ctx.Err()
		}
		if onErr != nil {
			onErr(err)
		}
		if errors.Is(err, ErrRevoked) || errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrNotActivated) || errors.Is(err, ErrBindingMismatch) {
			return err
		}
		failures, retry = failures+1, 0
		var ae *APIError
		if errors.As(err, &ae) {
			retry = ae.RetryAfter
		}
	}
}

const (
	backoffBase = time.Second
	backoffMax  = 5 * time.Minute
)

// backoff is the wait after n consecutive failures: exponential, capped,
// with full jitter in its upper half.
func (c *Client) backoff(n int) time.Duration {
	d := backoffBase << min(n-1, 20)
	d = min(d, backoffMax)
	return d/2 + time.Duration(c.rand(int64(d/2)+1))
}

// call POSTs body to op and returns the response body when the status is
// want. Network errors, 429, 5xx and idempotency_in_progress are retried up
// to MaxAttempts, waiting Retry-After when the server sends it.
func (c *Client) call(ctx context.Context, op string, body []byte, idemKey string, want int) ([]byte, error) {
	u := c.base.JoinPath("api/v1/activation/tenants", c.cfg.TenantID, op).String()
	for attempt := 1; ; attempt++ {
		raw, retryAfter, err := c.once(ctx, u, body, idemKey, want)
		if err == nil || !retryable(err) || attempt >= c.cfg.MaxAttempts || ctx.Err() != nil {
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
		return !errors.Is(err, ErrBadLease) // network errors
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
	_ = json.Unmarshal(raw, &p)
	ae := &APIError{Status: resp.StatusCode, Code: p.Code, Detail: p.Detail, RequestID: p.RequestID,
		RetryAfter: retryAfter(resp.Header.Get("Retry-After"), c.now()), kind: codes[p.Code]}
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
