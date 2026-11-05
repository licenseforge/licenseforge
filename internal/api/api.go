// Package api is the management REST API (ADR-0032). One outer handler
// wraps the whole router generated from api/openapi.yaml (apigen): it
// authenticates every request and resolves its tenant (steps 1–3 of the
// order of checks) before parameter binding, and renders every refusal,
// from any layer, as problem+json. Handlers do steps 4–6 and return errors
// that one mapper (fail) renders.
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"

	"licenseforge.io/licenseforge/internal/activations"
	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/apitoken"
	"licenseforge.io/licenseforge/internal/apitokens"
	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/catalog"
	"licenseforge.io/licenseforge/internal/customers"
	"licenseforge.io/licenseforge/internal/idempotency"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/invitations"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/members"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/tenants"
	"licenseforge.io/licenseforge/internal/weblogin"
)

// Prefix is where the API is mounted.
const Prefix = "/api/v1"

// maxBody bounds request bodies (413 above it).
const maxBody = 1 << 20

// unissuedTenant is well-formed but never issued (IDs are 128 random bits;
// this is all zeros): an unresolved tenant's token lookup runs under it, so
// it does the same work as a real one (ADR-0029, ADR-0032 step 2).
const unissuedTenant = "tnt_aaaaaaaaaaaaaaaaaaaaaaaaaa"

// Config is what the API needs from main.
type Config struct {
	Tokens   apitokens.Service
	Members  members.Service
	Licenses licenses.Service
	// The catalog (slice 1: products) and customers.
	Products  catalog.Products
	Customers customers.Service
	// Audit reads the tenant's audit log (audit:read).
	Audit audit.Log
	// Idempotency keeps Idempotency-Key outcomes (license issue, activate).
	Idempotency idempotency.Store
	// Tenants changes the tenant's own settings (MFA policy, ADR-0038).
	Tenants tenants.Service
	// Invitations: list, create, revoke, and accept (a user route).
	Invitations invitations.Service
	Identity    identity.Service
	Sessions    *weblogin.Sessions // nil: dashboard login is off, so sessions answer 401
	// APIHost, if set, accepts only API tokens; every other host only
	// sessions. Empty: both everywhere (one hostname).
	APIHost string
	Log     *slog.Logger
	// The activation API (activation.go).
	Activations    activations.Service
	ActivationRate int // requests per license key per minute, per replica; 0: DefaultActivationRate
}

type server struct {
	Config
	mux     *http.ServeMux
	limiter *keyLimiter
}

// New returns the API handler; mount it at Prefix + "/".
func New(c Config) http.Handler {
	s := &server{Config: c, mux: http.NewServeMux(), limiter: newKeyLimiter(c.ActivationRate)}
	s.routes(s.mux)
	return s
}

func (s *server) routes(m apigen.ServeMux) {
	strict := apigen.NewStrictHandlerWithOptions(s, []apigen.StrictMiddlewareFunc{strictInput},
		apigen.StrictHTTPServerOptions{RequestErrorHandlerFunc: s.badRequest, ResponseErrorHandlerFunc: s.fail})
	apigen.HandlerWithOptions(strict, apigen.StdHTTPServerOptions{BaseURL: Prefix, BaseRouter: m, ErrorHandlerFunc: s.badRequest})
}

type reqKey struct{}
type bodyKey struct{}

type reqInfo struct{ id, client string }

func (s *server) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ri := reqInfo{id: rand.Text(), client: clean(r.Header.Get("X-Request-Id"))}
	w := &tracked{ResponseWriter: rw}
	w.Header().Set("X-Request-Id", ri.id)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	r = r.WithContext(context.WithValue(r.Context(), reqKey{}, ri))
	if _, pattern := s.mux.Handler(r); pattern != "" { // before auth, so refusals get the route too
		metrics.SetRoute(r.Context(), pattern)
	}
	defer func() {
		if v := recover(); v != nil {
			if v == http.ErrAbortHandler { //nolint:errorlint // sentinel panic value
				panic(v)
			}
			p := &problem{status: http.StatusInternalServerError, code: "internal", err: fmt.Errorf("panic: %v\n%s", v, debug.Stack())}
			if w.started { // too late for a problem body: abort, so it can't pass for a success
				s.Log.ErrorContext(r.Context(), "api panic after the response started", "request_id", ri.id, "err", p.err)
				panic(http.ErrAbortHandler)
			}
			s.write(w, r, p)
		}
	}()
	if strings.HasPrefix(r.URL.Path, activationPrefix) { // decoded, as ServeMux matches it
		s.activation(w, r)
		return
	}
	p, prob := s.authenticate(w, r)
	if prob != nil {
		s.write(w, r, prob)
		return
	}
	// Read the body whole (bounded) so strictInput can decode it strictly.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		s.badRequest(w, r, err)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r = r.WithContext(context.WithValue(authz.WithPrincipal(r.Context(), p), bodyKey{}, body))
	if _, pattern := s.mux.Handler(r); pattern == "" {
		s.unrouted(w, r)
		return
	}
	s.mux.ServeHTTP(w, r)
}

// authenticate does steps 1–3: exactly one credential the host accepts, and
// the path's tenant.
func (s *server) authenticate(w http.ResponseWriter, r *http.Request) (authz.Principal, *problem) {
	auth := r.Header.Values("Authorization")
	_, err := r.Cookie(weblogin.SessionCookie)
	bearer, cookie := len(auth) > 0, err == nil
	apiHost := s.APIHost != "" && sameHost(r.Host, s.APIHost)
	switch {
	case bearer && cookie:
		return authz.Principal{}, &problem{status: http.StatusBadRequest, code: "ambiguous_credentials", detail: "Send an API token or a session, not both."}
	case bearer && (s.APIHost == "" || apiHost):
		return s.token(r, auth)
	case cookie && !apiHost && s.Sessions != nil:
		return s.session(w, r)
	}
	return authz.Principal{}, errUnauthenticated
}

func (s *server) token(r *http.Request, auth []string) (authz.Principal, *problem) {
	scheme, tok, _ := strings.Cut(auth[0], " ")
	if len(auth) != 1 || !strings.EqualFold(scheme, "Bearer") || apitoken.Check(tok) != nil {
		return authz.Principal{}, errUnauthenticated
	}
	ref, ok := tenantRef(r)
	if !ok { // a token can't be verified without its tenant
		return authz.Principal{}, errUnauthenticated
	}
	ctx := r.Context()
	tenantID, err := s.Identity.TenantID(ctx, ref)
	if errors.Is(err, identity.ErrNotMember) {
		tenantID = unissuedTenant
	} else if err != nil {
		return authz.Principal{}, internal(err)
	}
	p, err := s.Tokens.Authenticate(ctx, tenantID, tok)
	if errors.Is(err, apitokens.ErrUnauthenticated) {
		return authz.Principal{}, errUnauthenticated
	}
	if err != nil {
		return authz.Principal{}, internal(err)
	}
	if p.Role == authz.SDK {
		return authz.Principal{}, &problem{status: http.StatusForbidden, code: "forbidden", detail: "sdk tokens can't use the management API."}
	}
	return p, nil
}

func (s *server) session(w http.ResponseWriter, r *http.Request) (authz.Principal, *problem) {
	u, level, code, err := s.Sessions.Check(w, r)
	switch code {
	case 0:
	case http.StatusUnauthorized:
		return authz.Principal{}, errUnauthenticated
	case http.StatusForbidden:
		return authz.Principal{}, &problem{status: code, code: "csrf_failed", detail: "Unsafe requests need the " + weblogin.CSRFHeader + " header and must be same-origin.", err: err}
	default:
		return authz.Principal{}, internal(err)
	}
	ref, ok := tenantRef(r)
	if !ok {
		if userRoutes[r.URL.EscapedPath()] {
			// A principal with no tenant: authz denies every permission to
			// it; only user routes, which act for the user, accept it.
			return authz.Principal{Kind: authz.User, ID: u.ID, Assurance: level}, nil
		}
		return authz.Principal{}, errNotFound
	}
	ctx := r.Context()
	tenantID, err := s.Identity.TenantID(ctx, ref)
	var g authz.Grant
	if err == nil {
		g, err = s.Identity.Grant(ctx, u.ID, tenantID)
	}
	if errors.Is(err, identity.ErrNotMember) {
		return authz.Principal{}, errNotFound
	}
	if err != nil {
		return authz.Principal{}, internal(err)
	}
	return authz.Principal{Kind: authz.User, ID: u.ID, TenantID: tenantID, Role: g.Role, Scope: g.Scope, Assurance: level}, nil
}

// userRoutes are session-only paths outside a tenant, acting for the
// signed-in user (tokens belong to tenants: 401 there, as on any
// non-tenant path).
var userRoutes = map[string]bool{Prefix + "/invitations/accept": true, Prefix + "/me/tenants": true}

// tenantRef is the {tenant} segment of /api/v1/tenants/{tenant}/…, split
// from the escaped path as ServeMux does.
func tenantRef(r *http.Request) (string, bool) {
	rest, ok := strings.CutPrefix(r.URL.EscapedPath(), Prefix+"/tenants/")
	seg, _, _ := strings.Cut(rest, "/")
	ref, err := url.PathUnescape(seg)
	return ref, ok && err == nil && ref != ""
}

func sameHost(a, b string) bool {
	hostOnly := func(h string) string {
		if host, _, err := net.SplitHostPort(h); err == nil {
			return host
		}
		return h
	}
	return strings.EqualFold(hostOnly(a), hostOnly(b))
}

// clean keeps an inbound request ID loggable: printable ASCII, 64 bytes.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return -1
		}
		return r
	}, s)
	return s[:min(len(s), 64)]
}

// queryParams are each operation's query parameters; others answer 400.
// TestRoutesMatchSpec keeps it equal to the spec.
var queryParams = map[string][]string{
	"ListApiTokens":   {"limit", "cursor"},
	"ListMembers":     {"limit", "cursor"},
	"ListInvitations": {"limit", "cursor"},
	"ListLicenses":    {"limit", "cursor", "product_id", "customer_id", "status", "created_after", "created_before"},
	"ListProducts":    {"limit", "cursor", "archived"},
	"ListCustomers":   {"limit", "cursor"},
	"ListAuditEvents": {"limit", "cursor", "after_seq"},
	"ListActivations": {"limit", "cursor"},
	"RemoveMember":    {"revoke_tokens", "revoke_invitations"},
	"UpdateMember":    {"revoke_tokens", "revoke_invitations"},
}

// strictInput refuses unknown query parameters and decodes the body again
// strictly: the generated decoder ignores unknown fields, accepts
// case-variant names and trailing data.
func strictInput(f apigen.StrictHandlerFunc, op string) apigen.StrictHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req any) (any, error) {
		for k := range r.URL.Query() {
			if !slices.Contains(queryParams[op], k) {
				return nil, &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "Unknown query parameter."}
			}
		}
		if v := reflect.ValueOf(req); v.Kind() == reflect.Struct {
			if b := v.FieldByName("Body"); b.IsValid() && b.Kind() == reflect.Pointer {
				raw, _ := ctx.Value(bodyKey{}).([]byte)
				dec := json.NewDecoder(bytes.NewReader(raw))
				dec.DisallowUnknownFields()
				err := dec.Decode(reflect.New(b.Type().Elem()).Interface())
				if err == nil && dec.Decode(&struct{}{}) != io.EOF {
					err = errors.New("data after the JSON object")
				}
				if err == nil && !exactKeys(raw, b.Type().Elem()) {
					err = errors.New("a field name differs from the documented one")
				}
				if err != nil {
					return nil, &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "The body must be one JSON object with only the documented fields.", err: err}
				}
			}
		}
		return f(ctx, w, r, req)
	}
}

// exactKeys reports whether raw is a JSON object (not null) whose keys, at
// every level, are exactly the json names of struct t's fields:
// encoding/json matches names case-insensitively.
func exactKeys(raw []byte, t reflect.Type) bool {
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && m != nil && keysOf(m, t)
}

func keysOf(m map[string]json.RawMessage, t reflect.Type) bool {
	fields := reflect.VisibleFields(t)
	for k, v := range m {
		i := slices.IndexFunc(fields, func(f reflect.StructField) bool {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			return name == k
		})
		if i < 0 || !exactValue(v, fields[i].Type) {
			return false
		}
	}
	return true
}

var unmarshaler = reflect.TypeFor[json.Unmarshaler]()

// exactValue checks the keys inside raw, a value of type t. Types with their
// own JSON form (time.Time), []byte and null are left to the decoder.
func exactValue(raw json.RawMessage, t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if string(raw) == "null" || reflect.PointerTo(t).Implements(unmarshaler) {
		return true
	}
	switch t.Kind() {
	case reflect.Struct:
		var m map[string]json.RawMessage
		return json.Unmarshal(raw, &m) == nil && keysOf(m, t)
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return true
		}
		var a []json.RawMessage
		if json.Unmarshal(raw, &a) != nil {
			return false
		}
		for _, e := range a {
			if !exactValue(e, t.Elem()) {
				return false
			}
		}
	case reflect.Map:
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return false
		}
		for _, v := range m {
			if !exactValue(v, t.Elem()) {
				return false
			}
		}
	}
	return true
}

// unrouted answers a request no route matches: 404, or 405 with Allow.
func (s *server) unrouted(w http.ResponseWriter, r *http.Request) {
	h, _ := s.mux.Handler(r)
	rec := &discard{header: http.Header{}}
	h.ServeHTTP(rec, r)
	if rec.code == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", rec.header.Get("Allow"))
		s.write(w, r, &problem{status: rec.code, code: "method_not_allowed"})
		return
	}
	s.write(w, r, errNotFound)
}

// tracked notes whether the response has started.
type tracked struct {
	http.ResponseWriter
	started bool
}

func (t *tracked) WriteHeader(code int) { t.started = true; t.ResponseWriter.WriteHeader(code) }
func (t *tracked) Write(b []byte) (int, error) {
	t.started = true
	return t.ResponseWriter.Write(b)
}
func (t *tracked) Unwrap() http.ResponseWriter { return t.ResponseWriter }

type discard struct {
	header http.Header
	code   int
}

func (d *discard) Header() http.Header         { return d.header }
func (d *discard) Write(b []byte) (int, error) { return len(b), nil }
func (d *discard) WriteHeader(code int)        { d.code = code }

// problem is an RFC 9457 answer. err is logged, never sent.
type problem struct {
	status       int
	code, detail string
	fields       []fieldError
	err          error
}

type fieldError struct {
	Field   string `json:"field"` // JSON Pointer into the body
	Message string `json:"message"`
}

func (p *problem) Error() string { return p.code }

var (
	errUnauthenticated = &problem{status: http.StatusUnauthorized, code: "unauthenticated", detail: "Missing or invalid credentials."}
	errNotFound        = &problem{status: http.StatusNotFound, code: "not_found"}
)

func internal(err error) *problem {
	return &problem{status: http.StatusInternalServerError, code: "internal", err: err}
}

// badRequest renders binding and body errors.
func (s *server) badRequest(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		s.write(w, r, &problem{status: http.StatusRequestEntityTooLarge, code: "body_too_large", detail: fmt.Sprintf("Bodies are limited to %d bytes.", maxBody), err: err})
		return
	}
	s.write(w, r, &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "Malformed parameter or body.", err: err})
}

// fail is the one error mapper for handler errors.
func (s *server) fail(w http.ResponseWriter, r *http.Request, err error) { s.write(w, r, mapErr(err)) }

// mapErr maps a handler's error to its problem.
func mapErr(err error) *problem {
	var p *problem
	var invalidMember *members.InvalidError
	var invalidLicense *licenses.InvalidError
	var invalidInvitation *invitations.InvalidError
	var invalidCatalog *catalog.InvalidError
	var invalidCustomer *customers.InvalidError
	switch {
	case errors.As(err, &p):
	case errors.Is(err, catalog.ErrNotFound), errors.Is(err, customers.ErrNotFound), errors.Is(err, activations.ErrNotFound):
		p = errNotFound
	case errors.As(err, &invalidCatalog) && invalidCatalog.Conflict:
		p = &problem{status: http.StatusConflict, code: "conflict", detail: "A value is already taken.", fields: []fieldError{{invalidCatalog.Field, invalidCatalog.Message}}}
	case errors.As(err, &invalidCatalog):
		p = invalid(fieldError{invalidCatalog.Field, invalidCatalog.Message})
	case errors.As(err, &invalidCustomer):
		p = invalid(fieldError{invalidCustomer.Field, invalidCustomer.Message})
	case errors.Is(err, customers.ErrState), errors.Is(err, catalog.ErrState):
		p = &problem{status: http.StatusConflict, code: "invalid_state", detail: "Already archived."}
	case activationProblem(err) != nil:
		p = activationProblem(err)
	case errors.Is(err, authz.ErrDenied):
		p = &problem{status: http.StatusForbidden, code: "forbidden", detail: "Your role or scope doesn't allow this.", err: err}
	case errors.Is(err, apitokens.ErrNotFound), errors.Is(err, members.ErrNotFound), errors.Is(err, licenses.ErrNotFound), errors.Is(err, invitations.ErrNotFound):
		p = errNotFound
	case errors.As(err, &invalidMember):
		p = invalid(fieldError{invalidMember.Field, invalidMember.Message})
	case errors.As(err, &invalidLicense):
		p = invalid(fieldError{invalidLicense.Field, invalidLicense.Message})
	case errors.Is(err, licenses.ErrInvalid):
		p = invalid()
	case errors.As(err, &invalidInvitation):
		p = invalid(fieldError{invalidInvitation.Field, invalidInvitation.Message})
	case errors.Is(err, store.ErrInvitation): // one answer for every reason (no oracle)
		p = invalid(fieldError{"/token", "invalid, expired, revoked or used, or not for this account"})
	case errors.Is(err, tenants.ErrPolicyUnmet):
		p = &problem{status: http.StatusConflict, code: "mfa_policy_unmet", detail: "Your session doesn't meet this MFA policy: sign in with the stronger method first, so you can't lock yourself out.", err: err}
	case errors.Is(err, tenants.ErrInvalid):
		p = invalid(fieldError{"/mfa_policy", "must be none, mfa or phishing_resistant"})
	case errors.Is(err, members.ErrLastOwner):
		p = &problem{status: http.StatusConflict, code: "last_owner", detail: "The tenant must keep an owner; make someone else owner first."}
	case errors.Is(err, licenses.ErrState):
		p = &problem{status: http.StatusConflict, code: "invalid_state", detail: "The license's status doesn't allow this."}
	case errors.Is(err, idempotency.ErrInvalidKey):
		p = &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "Idempotency-Key must be 1-255 printable ASCII characters."}
	case errors.Is(err, idempotency.ErrKeyReused):
		p = &problem{status: http.StatusUnprocessableEntity, code: "idempotency_key_reused", detail: "This Idempotency-Key was used with a different request."}
	case errors.Is(err, idempotency.ErrInProgress):
		p = &problem{status: http.StatusConflict, code: "idempotency_in_progress", detail: "A request with this Idempotency-Key is still in progress; retry later."}
	default:
		p = internal(err)
	}
	if p.err == nil {
		p = &problem{status: p.status, code: p.code, detail: p.detail, fields: p.fields, err: err}
	}
	return p
}

func (s *server) write(w http.ResponseWriter, r *http.Request, p *problem) {
	ri, _ := r.Context().Value(reqKey{}).(reqInfo)
	level := slog.LevelInfo
	if p.status >= 500 {
		level = slog.LevelError
	}
	s.Log.Log(r.Context(), level, "api refusal", "request_id", ri.id, "client_request_id", ri.client,
		"method", r.Method, "path", r.URL.Path, "status", p.status, "code", p.code, "err", p.err)
	if p.status == http.StatusUnauthorized {
		scheme := "Bearer"
		if strings.HasPrefix(r.URL.Path, activationPrefix) {
			scheme = "License"
		}
		w.Header().Set("WWW-Authenticate", scheme+` realm="licenseforge"`)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.status)
	_, _ = w.Write(p.body(ri.id))
}

// body is p's problem+json document.
func (p *problem) body(requestID string) []byte {
	b, _ := json.Marshal(struct {
		Type      string       `json:"type"`
		Title     string       `json:"title"`
		Status    int          `json:"status"`
		Detail    string       `json:"detail,omitempty"`
		Code      string       `json:"code"`
		RequestID string       `json:"request_id"`
		Errors    []fieldError `json:"errors,omitempty"`
	}{"about:blank", http.StatusText(p.status), p.status, p.detail, p.code, requestID, p.fields})
	return append(b, '\n')
}
