package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"licenseforge.io/licenseforge/internal/activations"
	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/idempotency"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
)

// The activation API (ADR-0004, ADR-0034) is what SDKs call: under
// Prefix + "/activation/tenants/{tenant}/…", authenticated by the license
// key (`Authorization: License <key>`), never by a token or session, so it
// bypasses authenticate. With an API host configured it is served there
// only (ADR-0023: the URL vendors embed in their builds).
const activationPrefix = Prefix + "/activation/"

// DefaultActivationRate is the requests per license key per minute, per
// replica, when Config.ActivationRate is 0.
const DefaultActivationRate = 60

type licenseKeyKey struct{}

// activation does what ServeHTTP's authenticate does for the management
// API: the host, the license key's form, its rate limit, then the body.
// The key itself is checked by internal/activations.
func (s *server) activation(w http.ResponseWriter, r *http.Request) {
	if s.APIHost != "" && !sameHost(r.Host, s.APIHost) {
		s.write(w, r, errNotFound)
		return
	}
	auth := r.Header.Values("Authorization")
	scheme, raw, _ := strings.Cut(strings.Join(auth, ""), " ")
	key, err := licensekey.Normalize(raw)
	if len(auth) != 1 || !strings.EqualFold(scheme, "License") || err != nil {
		s.write(w, r, errUnauthenticated)
		return
	}
	ok, retry, window := s.limiter.take(w, key)
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		s.write(w, r, &problem{status: http.StatusTooManyRequests, code: "rate_limited", detail: "Too many requests for this license key; retry after Retry-After seconds."})
		return
	}
	// From here on every way out releases the count unless the key
	// authenticated: oversized and aborted bodies too.
	mark := &keyMark{}
	defer func() {
		if !mark.ok {
			s.limiter.release(key, window)
		}
	}()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		s.badRequest(w, r, err)
		return
	}
	ctx := context.WithValue(context.WithValue(r.Context(), bodyKey{}, body), licenseKeyKey{}, key)
	r = r.WithContext(context.WithValue(ctx, keyMarkKey{}, mark))
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if _, pattern := s.mux.Handler(r); pattern == "" {
		s.unrouted(w, r)
		return
	}
	s.mux.ServeHTTP(w, r)
}

func activationRequest(ctx context.Context, tenant string, fp string, source apigen.ActivationRequestFpSource, hostname, app, sdk *string) activations.Request {
	key, _ := ctx.Value(licenseKeyKey{}).(string)
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	return activations.Request{TenantID: tenant, Key: key, Fingerprint: fp, Source: activation.FpSource(source),
		Hostname: deref(hostname), AppVersion: deref(app), SDKVersion: deref(sdk)}
}

func leaseView(l activations.Lease) apigen.Lease {
	return apigen.Lease{Lease: l.File, Kid: l.KID, ActivationId: l.ActivationID,
		IssuedAt: l.Claims.IssuedAt, ExpiresAt: *l.Claims.Expires, RefreshAfter: *l.Claims.RefreshAfter}
}

// keyMark records that the request's key authenticated: activation then
// keeps its rate-limit count. Every other request (unknown key, malformed
// body or fingerprint, unknown route) is released, so junk keys never
// occupy the limiter beyond their own request and can't fill it to push
// real keys past its bound (fail open).
type keyMark struct{ ok bool }

type keyMarkKey struct{}

// authenticated marks the key as known when err shows the service matched
// it to a license (success, or a refusal of that license), and returns err.
func authenticated(ctx context.Context, err error) error {
	m, _ := ctx.Value(keyMarkKey{}).(*keyMark)
	if m == nil {
		return err
	}
	for _, known := range []error{activations.ErrSuspended, activations.ErrRevoked, activations.ErrExpired, activations.ErrLimit,
		activations.ErrRehostLimit, activations.ErrBinding, activations.ErrNotActivated, activations.ErrOfflineSeat} {
		if errors.Is(err, known) {
			m.ok = true
		}
	}
	if err == nil {
		m.ok = true
	}
	return err
}

func (s *server) Activate(ctx context.Context, req apigen.ActivateRequestObject) (apigen.ActivateResponseObject, error) {
	b := req.Body
	ar := activationRequest(ctx, req.Tenant, b.Fingerprint, b.FpSource, b.Hostname, b.AppVersion, b.SdkVersion)
	if req.Params.IdempotencyKey == nil {
		l, err := s.Activations.Activate(ctx, ar)
		if err != nil {
			return nil, authenticated(ctx, err)
		}
		return apigen.Activate200JSONResponse(leaseView(l)), authenticated(ctx, nil)
	}
	// The license is the credential (ADR-0032: keys are scoped to the
	// credential); Identify finds it before Do's transaction.
	licenseID, err := s.Activations.Identify(ctx, ar)
	if err != nil {
		return nil, err
	}
	_ = authenticated(ctx, nil) // the key is a license's
	raw, _ := ctx.Value(bodyKey{}).([]byte)
	out, _, err := s.Idempotency.Do(ctx, idempotency.Request{TenantID: ar.TenantID, Credential: licenseID, Key: *req.Params.IdempotencyKey, Operation: "activate", Body: raw},
		func(ctx context.Context, tx *ent.Tx) error { return s.Activations.Recheck(ctx, tx, ar) },
		func(ctx context.Context, tx *ent.Tx) (idempotency.Outcome, error) {
			l, err := s.Activations.ActivateTx(ctx, tx, ar)
			if err != nil {
				p := mapErr(err)
				if p.status/100 != 4 {
					return idempotency.Outcome{}, err
				}
				ri, _ := ctx.Value(reqKey{}).(reqInfo)
				return idempotency.Outcome{Status: p.status, Body: p.body(ri.id)}, nil // stored and committed with its audit entry
			}
			body, err := json.Marshal(leaseView(l))
			return idempotency.Outcome{Status: http.StatusOK, Body: body}, err
		})
	if err != nil {
		return nil, err
	}
	if out.Status >= 400 { // a stored refusal: this request's request_id, as X-Request-Id
		var m map[string]any
		if json.Unmarshal(out.Body, &m) == nil {
			ri, _ := ctx.Value(reqKey{}).(reqInfo)
			m["request_id"] = ri.id
			if b, err := json.Marshal(m); err == nil {
				out.Body = append(b, '\n')
			}
		}
	}
	return stored(out), nil
}

func (s *server) RefreshLease(ctx context.Context, req apigen.RefreshLeaseRequestObject) (apigen.RefreshLeaseResponseObject, error) {
	b := req.Body
	l, err := s.Activations.Refresh(ctx, activationRequest(ctx, req.Tenant, b.Fingerprint, b.FpSource, b.Hostname, b.AppVersion, b.SdkVersion))
	if err != nil {
		return nil, authenticated(ctx, err)
	}
	return apigen.RefreshLease200JSONResponse(leaseView(l)), authenticated(ctx, nil)
}

func (s *server) Deactivate(ctx context.Context, req apigen.DeactivateRequestObject) (apigen.DeactivateResponseObject, error) {
	if err := s.Activations.Deactivate(ctx, activationRequest(ctx, req.Tenant, req.Body.Fingerprint, "", nil, nil, nil)); err != nil {
		return nil, authenticated(ctx, err)
	}
	return apigen.Deactivate204Response{}, authenticated(ctx, nil)
}

// stored writes an outcome as idempotency.Store.Do returned it: a fresh
// answer or a replay.
type stored idempotency.Outcome

func (o stored) VisitActivateResponse(w http.ResponseWriter) error {
	ct := "application/json"
	if o.Status >= 400 {
		ct = "application/problem+json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(o.Status)
	_, err := w.Write(o.Body)
	return err
}

// activationProblem maps the activation errors (nil for others; mapErr
// maps the idempotency errors). Codes are stable: SDKs switch on them.
func activationProblem(err error) *problem {
	for _, m := range []struct {
		err    error
		status int
		code   string
		detail string
	}{
		{activations.ErrUnauthenticated, http.StatusUnauthorized, "unauthenticated", "Missing or invalid license key."},
		{activations.ErrInvalid, http.StatusBadRequest, "invalid_request", "Malformed fingerprint, source, metadata, or offline activation request or receipt."},
		{activations.ErrSuspended, http.StatusForbidden, "license_suspended", "The license is suspended."},
		{activations.ErrRevoked, http.StatusForbidden, "license_revoked", "The license is revoked."},
		{activations.ErrExpired, http.StatusForbidden, "license_expired", "The license has expired."},
		{activations.ErrLimit, http.StatusConflict, "activation_limit_reached", "Every seat is taken; deactivate a machine first."},
		{activations.ErrRehostLimit, http.StatusConflict, "rehost_limit_reached", "The license's machines have moved as often as it allows."},
		{activations.ErrBinding, http.StatusUnprocessableEntity, "binding_mismatch", "The fingerprint doesn't bind what the license requires."},
		{activations.ErrNotActivated, http.StatusNotFound, "not_activated", "This machine isn't activated; activate it."},
		{activations.ErrOffline, http.StatusConflict, "offline_not_allowed", "The license's plan doesn't allow offline use."},
		{activations.ErrOnlineSeat, http.StatusConflict, "online_seat", "The machine is activated online; deactivate it there first."},
		{activations.ErrSuperseded, http.StatusConflict, "receipt_superseded", "The receipt is for an older file; the machine renewed since. Return the current file's receipt."},
		{activations.ErrOfflineSeat, http.StatusConflict, "offline_seat", "This machine's seat is offline; return it with a deactivation receipt."},
	} {
		if errors.Is(err, m.err) {
			return &problem{status: m.status, code: m.code, detail: m.detail, err: err}
		}
	}
	return nil
}

// keyLimiter is the per-license-key rate limit (ADR-0034): quota requests
// per key per fixed minute, counted in this process, so per replica (N
// replicas allow N × quota). Keys are held as SHA-256, never in plaintext,
// and forgotten when the minute ends. A request is counted before it
// reaches the service and released unless its key authenticated (keyMark),
// so only real keys stay tracked. At most maxKeys distinct keys are
// tracked per minute, so memory is bounded; past that (only reachable with
// that many real keys, or junk keys in flight at once) new keys pass
// untracked (fail open). Flooding is the job of the per-client-address
// limit (ADR-0032 step 0).
// ponytail: per replica and fixed windows; a shared limiter (Redis, the
// database) when per-cluster limits matter.
type keyLimiter struct {
	mu      sync.Mutex
	quota   int
	maxKeys int
	now     func() time.Time
	window  time.Time
	counts  map[[32]byte]int
}

const limiterWindow = time.Minute

func newKeyLimiter(quota int) *keyLimiter {
	if quota <= 0 {
		quota = DefaultActivationRate
	}
	return &keyLimiter{quota: quota, maxKeys: 100_000, now: time.Now, counts: map[[32]byte]int{}}
}

// take counts one request for key, sets the RateLimit headers and reports
// whether it is within the limit, and else the seconds until it resets. It
// returns the window it counted in, for release.
func (l *keyLimiter) take(w http.ResponseWriter, key string) (ok bool, retry int, window time.Time) {
	h := sha256.Sum256([]byte(key))
	l.mu.Lock()
	now := l.now()
	if w := now.Truncate(limiterWindow); !w.Equal(l.window) {
		l.window, l.counts = w, map[[32]byte]int{}
	}
	n, seen := l.counts[h]
	ok = n < l.quota
	remaining := 0
	switch {
	case !seen && len(l.counts) >= l.maxKeys: // untracked
		remaining = l.quota
	case ok:
		n++
		l.counts[h] = n
		remaining = l.quota - n
	}
	reset := max(1, int((l.window.Add(limiterWindow).Sub(now)+time.Second-1)/time.Second))
	window = l.window
	l.mu.Unlock()
	// Added, not set: the per-address limit's policy is on the response too.
	w.Header().Add("RateLimit-Policy", fmt.Sprintf(`"license-key";q=%d;w=%d`, l.quota, int(limiterWindow/time.Second)))
	w.Header().Add("RateLimit", fmt.Sprintf(`"license-key";r=%d;t=%d`, remaining, reset))
	return ok, reset, window
}

// release undoes take's count for key (an unknown key) in window,
// forgetting it when nothing is left. Once the window has moved on, the
// count is gone already and the new window's isn't touched.
func (l *keyLimiter) release(key string, window time.Time) {
	h := sha256.Sum256([]byte(key))
	l.mu.Lock()
	defer l.mu.Unlock()
	if !window.Equal(l.window) {
		return
	}
	switch n := l.counts[h]; {
	case n > 1:
		l.counts[h] = n - 1
	case n == 1:
		delete(l.counts, h)
	}
}
