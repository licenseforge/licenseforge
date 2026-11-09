package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/activations"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/idempotency"
	"licenseforge.io/licenseforge/internal/issue"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/activation"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/sdk/go/fingerprint"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
	"licenseforge.io/licenseforge/sdk/go/online"
)

type actFixture struct {
	*fixture
	keys     signing.Local
	lic      licenses.Service
	plans    map[string]string // slug → ID in tenant a
	customer string
}

func actSetup(t *testing.T) *actFixture {
	t.Helper()
	ctx := context.Background()
	f := setup(t)
	kr, err := secrets.ParseKeyring("k1=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	a := &actFixture{fixture: f, keys: signing.Local{DB: f.db, Keys: kr}, lic: licenses.Service{DB: f.db, Keys: kr}, plans: map[string]string{}}
	f.srv.Activations = activations.Service{DB: f.db, Keys: kr, Issuer: issue.Issuer{DB: f.db, Keys: a.keys}}
	f.srv.Idempotency = idempotency.Store{DB: f.db, Keys: kr}
	for _, tn := range []string{f.a.ID, f.b.ID} {
		owner := authz.Principal{Kind: authz.User, ID: "usr_owner", TenantID: tn, Role: authz.Owner, Scope: authz.Scope{All: true}}
		if _, err := a.keys.Create(authz.WithPrincipal(ctx, owner), tn); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.db.WithTenant(ctx, f.a.ID, func(tx *ent.Tx) error {
		for slug, c := range map[string]func(*ent.PlanCreate){
			"pro":     func(c *ent.PlanCreate) { c.SetDurationMonths(12).SetMaxActivations(2).SetLeaseSeconds(3600) },
			"cluster": func(c *ent.PlanCreate) { c.SetBindType(plan.BindTypeCluster) },
			"offline": func(c *ent.PlanCreate) { c.SetMaxActivations(1).SetOfflineAllowed(true).SetMaxOfflineSeconds(86400) },
		} {
			pc := tx.Plan.Create().SetTenantID(f.a.ID).SetProductID(f.prodA).SetSlug(slug).SetName(slug)
			c(pc)
			pl, err := pc.Save(ctx)
			if err != nil {
				return err
			}
			a.plans[slug] = pl.ID
		}
		c, err := tx.Customer.Create().SetTenantID(f.a.ID).SetName("Contoso").Save(ctx)
		a.customer = c.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *actFixture) issue(t *testing.T, slug string) licenses.Issued {
	t.Helper()
	m := authz.Principal{Kind: authz.User, ID: "usr_mgr", TenantID: a.a.ID, Role: authz.Manager, Scope: authz.Scope{All: true}}
	got, err := a.lic.Issue(context.Background(), m, licenses.IssueRequest{ProductID: a.prodA, PlanID: a.plans[slug], CustomerID: a.customer})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func newFP() string {
	sum := sha256.Sum256([]byte(rand.Text()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func licenseAuth(key string) opt { return header("Authorization", "License "+key) }

func actPath(tenant, op string) string { return Prefix + "/activation/tenants/" + tenant + "/" + op }

func actBody(fp string) string {
	return `{"fingerprint":"` + fp + `","fp_source":"machine-id","hostname":"db-1","app_version":"1.2.3"}`
}

func (a *actFixture) activations(t *testing.T, licenseID string) []*ent.Activation {
	t.Helper()
	var as []*ent.Activation
	if err := a.db.WithTenant(context.Background(), a.a.ID, func(tx *ent.Tx) (err error) {
		as, err = tx.Activation.Query().Where(activation.LicenseID(licenseID)).All(context.Background())
		return
	}); err != nil {
		t.Fatal(err)
	}
	return as
}

func (a *actFixture) events(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := a.db.WithTenant(context.Background(), a.a.ID, func(tx *ent.Tx) (err error) {
		n, err = tx.AuditEvent.Query().Where(auditevent.Action(action)).Count(context.Background())
		return
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestActivationLifecycle(t *testing.T) {
	a := actSetup(t)
	is := a.issue(t, "pro")
	fp := newFP()
	r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(strings.ToLower(is.Key)))
	if r.code != 200 || r.h.Get("Content-Type") != "application/json" || r.h.Get("RateLimit-Policy") != `"license-key";q=60;w=60` ||
		!strings.HasPrefix(r.h.Get("RateLimit"), `"license-key";r=59;t=`) {
		t.Fatalf("activate: %d %v %s", r.code, r.h, r.raw)
	}
	pk, err := a.keys.Public(context.Background(), a.a.ID, r.body["kid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	iat, _ := time.Parse(time.RFC3339, r.body["issued_at"].(string))
	c, status, err := licensefile.Open(r.body["lease"].(string), licensefile.KeySet{{KID: pk.KID, Alg: licensefile.AlgEd25519, Key: pk.Key}},
		licensefile.CheckOptions{Now: iat, Product: "db", Fingerprint: fp})
	if err != nil || status != licensefile.StatusValid || c.LicenseID != is.License.ID {
		t.Fatalf("lease: %v %v %+v", status, err, c)
	}
	as := a.activations(t, is.License.ID)
	if len(as) != 1 || as[0].ID != r.body["activation_id"] {
		t.Fatalf("activations %+v", as)
	}
	if r := a.do(t, "POST", actPath(a.a.ID, "refresh"), actBody(fp), licenseAuth(is.Key)); r.code != 200 || r.body["activation_id"] != as[0].ID {
		t.Errorf("refresh: %d %s", r.code, r.raw)
	}
	if r := a.do(t, "POST", actPath(a.a.ID, "deactivate"), `{"fingerprint":"`+fp+`"}`, licenseAuth(is.Key)); r.code != 204 || r.raw != "" {
		t.Errorf("deactivate: %d %s", r.code, r.raw)
	}
	a.do(t, "POST", actPath(a.a.ID, "refresh"), actBody(fp), licenseAuth(is.Key)).problem(t, 404, "not_activated")
	a.do(t, "POST", actPath(a.a.ID, "deactivate"), `{"fingerprint":"`+fp+`"}`, licenseAuth(is.Key)).problem(t, 404, "not_activated")
}

func TestActivationAuth(t *testing.T) {
	a := actSetup(t)
	is := a.issue(t, "pro")
	tok := a.token(t, a.a.ID, a.ownerA, authz.SDK)
	path, body := actPath(a.a.ID, "activate"), actBody(newFP())
	for name, opts := range map[string][]opt{
		"no credential":        nil,
		"API token":            {bearer(tok.Token)},
		"Bearer license key":   {bearer(is.Key)},
		"malformed key":        {licenseAuth("LF-NOPE")},
		"unknown key":          {licenseAuth(licensekey.New())},
		"session only":         {a.session(t, a.ownerA, true)},
		"two headers":          {licenseAuth(is.Key), func(r *http.Request) { r.Header.Add("Authorization", "License "+is.Key) }},
		"key without a scheme": {header("Authorization", is.Key)},
		"key split over two headers": {func(r *http.Request) {
			r.Header.Add("Authorization", "License "+is.Key[:10])
			r.Header.Add("Authorization", is.Key[10:])
		}},
		"key in another tenant": {licenseAuth(is.Key), func(r *http.Request) { r.URL.Path = actPath(a.b.ID, "activate") }},
		"tenant slug":           {licenseAuth(is.Key), func(r *http.Request) { r.URL.Path = actPath(a.a.Slug, "activate") }},
	} {
		t.Run(name, func(t *testing.T) {
			r := a.do(t, "POST", path, body, opts...)
			r.problem(t, 401, "unauthenticated")
			if r.h.Get("WWW-Authenticate") != `License realm="licenseforge"` {
				t.Errorf("WWW-Authenticate %q", r.h.Get("WWW-Authenticate"))
			}
		})
	}
	if n := len(a.activations(t, is.License.ID)); n != 0 {
		t.Errorf("%d activations", n)
	}
	// A percent-encoded prefix is the same route (ServeMux decodes it): the
	// activation entry with its License challenge, never the management auth.
	encoded := Prefix + "/%61ctivation/tenants/" + a.a.ID + "/activate"
	for name, o := range map[string]opt{"API token": bearer(a.token(t, a.a.ID, a.ownerA, authz.Admin).Token), "session": a.session(t, a.ownerA, true)} {
		r := a.do(t, "POST", encoded, body, o)
		r.problem(t, 401, "unauthenticated")
		if r.h.Get("WWW-Authenticate") != `License realm="licenseforge"` {
			t.Errorf("encoded prefix with %s: %q", name, r.h.Get("WWW-Authenticate"))
		}
	}
	// With an API host, the activation API is served there only.
	a.srv.APIHost = "api.lf.example"
	onHost := func(h string) opt { return func(r *http.Request) { r.Host = h } }
	a.do(t, "POST", path, body, licenseAuth(is.Key), onHost("lf.example")).problem(t, 404, "not_found")
	a.do(t, "POST", encoded, body, a.session(t, a.ownerA, true), onHost("lf.example")).problem(t, 404, "not_found")
	if r := a.do(t, "POST", path, body, licenseAuth(is.Key), onHost("api.lf.example")); r.code != 200 {
		t.Errorf("on the API host: %d %s", r.code, r.raw)
	}
}

func TestActivationRefusals(t *testing.T) {
	a := actSetup(t)
	ctx := context.Background()
	m := authz.Principal{Kind: authz.User, ID: "usr_mgr", TenantID: a.a.ID, Role: authz.Manager, Scope: authz.Scope{All: true}}
	suspended, revoked, full, cluster := a.issue(t, "pro"), a.issue(t, "pro"), a.issue(t, "pro"), a.issue(t, "cluster")
	if _, err := a.lic.Suspend(ctx, m, suspended.License.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.lic.Revoke(ctx, m, revoked.License.ID); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(full.Key)); r.code != 200 {
			t.Fatal(r.raw)
		}
	}
	path := actPath(a.a.ID, "activate")
	for _, tc := range []struct {
		name, key, body string
		status          int
		code            string
	}{
		{"suspended", suspended.Key, actBody(newFP()), 403, "license_suspended"},
		{"revoked", revoked.Key, actBody(newFP()), 403, "license_revoked"},
		{"seats full", full.Key, actBody(newFP()), 409, "activation_limit_reached"},
		{"binding", cluster.Key, actBody(newFP()), 422, "binding_mismatch"},
		{"bad fingerprint", full.Key, `{"fingerprint":"sha256:x","fp_source":"machine-id"}`, 400, "invalid_request"},
		{"bad hostname", full.Key, `{"fingerprint":"` + newFP() + `","fp_source":"machine-id","hostname":"a b"}`, 400, "invalid_request"},
		{"unknown source", full.Key, `{"fingerprint":"` + newFP() + `","fp_source":"bios"}`, 400, "invalid_request"},
		{"unknown field", full.Key, `{"fingerprint":"` + newFP() + `","fp_source":"machine-id","key":"x"}`, 400, "invalid_request"},
		{"not JSON", full.Key, `fingerprint`, 400, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a.do(t, "POST", path, tc.body, licenseAuth(tc.key)).problem(t, tc.status, tc.code)
		})
	}
	a.do(t, "POST", path+"?x=1", actBody(newFP()), licenseAuth(full.Key)).problem(t, 400, "invalid_request")
	a.do(t, "GET", path, "", licenseAuth(full.Key)).problem(t, 405, "method_not_allowed")
	a.do(t, "POST", actPath(a.a.ID, "nope"), actBody(newFP()), licenseAuth(full.Key)).problem(t, 404, "not_found")
	a.do(t, "POST", path, `{"fingerprint":"`+strings.Repeat("a", maxBody)+`"}`, licenseAuth(full.Key)).problem(t, 413, "body_too_large")
}

func TestActivationRateLimit(t *testing.T) {
	a := actSetup(t)
	now := time.Date(2026, 11, 5, 12, 0, 30, 0, time.UTC)
	a.srv.limiter = newKeyLimiter(3)
	a.srv.limiter.now = func() time.Time { return now }
	is, other := a.issue(t, "pro"), a.issue(t, "pro")
	fp := newFP()
	for i := range 3 {
		if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(is.Key)); r.code != 200 || r.h.Get("RateLimit") != fmt.Sprintf(`"license-key";r=%d;t=30`, 2-i) {
			t.Fatalf("request %d: %d %q", i, r.code, r.h.Get("RateLimit"))
		}
	}
	// The same key in another spelling is the same key.
	r := a.do(t, "POST", actPath(a.a.ID, "refresh"), actBody(fp), licenseAuth(strings.ToLower(strings.ReplaceAll(is.Key, "-", ""))))
	r.problem(t, 429, "rate_limited")
	if r.h.Get("Retry-After") != "30" || r.h.Get("RateLimit") != `"license-key";r=0;t=30` || r.h.Get("RateLimit-Policy") != `"license-key";q=3;w=60` {
		t.Errorf("429 headers %v", r.h)
	}
	// Unknown keys count against their own key; another license is unaffected.
	if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(other.Key)); r.code != 200 {
		t.Errorf("other key: %d", r.code)
	}
	// Refused before anything else: no activation, no audit entry.
	before := a.events(t, "activation.create")
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(is.Key)).problem(t, 429, "rate_limited")
	if a.events(t, "activation.create") != before || len(a.activations(t, is.License.ID)) != 1 {
		t.Error("a limited request reached the service")
	}
	// The next minute starts afresh.
	now = now.Add(30 * time.Second)
	if r := a.do(t, "POST", actPath(a.a.ID, "refresh"), actBody(fp), licenseAuth(is.Key)); r.code != 200 || r.h.Get("RateLimit") != `"license-key";r=2;t=60` {
		t.Errorf("next window: %d %q", r.code, r.h.Get("RateLimit"))
	}
}

// Unknown keys don't stay in the limiter, so a flood of them can't push a
// real key past its bound.
func TestActivationRateLimitIgnoresUnknownKeys(t *testing.T) {
	a := actSetup(t)
	a.srv.limiter = newKeyLimiter(3)
	a.srv.limiter.maxKeys = 5
	// A fixed clock: a minute boundary mid-test would reset the counts.
	now := time.Date(2026, 1, 1, 0, 0, 30, 0, time.UTC)
	a.srv.limiter.now = func() time.Time { return now }
	for _, tc := range []struct {
		name, op, body string
		o              []opt
		status         int
		code           string
	}{
		{"activate", "activate", actBody(newFP()), nil, 401, "unauthenticated"},
		{"idempotent activate", "activate", actBody(newFP()), []opt{header("Idempotency-Key", "k")}, 401, "unauthenticated"},
		{"refresh", "refresh", actBody(newFP()), nil, 401, "unauthenticated"},
		{"deactivate", "deactivate", `{"fingerprint":"` + newFP() + `"}`, nil, 401, "unauthenticated"},
		{"bad body", "activate", `{"x":1}`, nil, 400, "invalid_request"},
		{"bad fingerprint", "activate", `{"fingerprint":"x","fp_source":"env"}`, nil, 400, "invalid_request"},
		{"unknown route", "nope", actBody(newFP()), nil, 404, "not_found"},
		{"too large", "activate", `{"fingerprint":"` + strings.Repeat("a", maxBody) + `"}`, nil, 413, "body_too_large"},
	} {
		name := tc.name
		for range 6 {
			a.do(t, "POST", actPath(a.a.ID, tc.op), tc.body, append(tc.o, licenseAuth(licensekey.New()))...).problem(t, tc.status, tc.code)
		}
		if n := len(a.srv.limiter.counts); n != 0 {
			t.Fatalf("%s: %d unknown keys tracked", name, n)
		}
	}
	is := a.issue(t, "pro")
	fp := newFP()
	for i := range 3 {
		if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(is.Key)); r.code != 200 {
			t.Fatalf("request %d: %d", i, r.code)
		}
	}
	a.do(t, "POST", actPath(a.a.ID, "refresh"), actBody(fp), licenseAuth(is.Key)).problem(t, 429, "rate_limited")
	// Refusals of a real license count, and so do idempotent replays.
	m := authz.Principal{Kind: authz.User, ID: "usr_mgr", TenantID: a.a.ID, Role: authz.Manager, Scope: authz.Scope{All: true}}
	susp, idem := a.issue(t, "pro"), a.issue(t, "pro")
	if _, err := a.lic.Suspend(context.Background(), m, susp.License.ID); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(susp.Key)).problem(t, 403, "license_suspended")
	}
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(susp.Key)).problem(t, 429, "rate_limited")
	body := actBody(newFP())
	for range 3 {
		if r := a.do(t, "POST", actPath(a.a.ID, "activate"), body, licenseAuth(idem.Key), header("Idempotency-Key", "k")); r.code != 200 {
			t.Fatal(r.raw)
		}
	}
	a.do(t, "POST", actPath(a.a.ID, "activate"), body, licenseAuth(idem.Key), header("Idempotency-Key", "k")).problem(t, 429, "rate_limited")
}

// Idempotent activation signs in Do's transaction: one pool connection is
// enough (a signer with its own transactions would wait for a second one
// forever).
func TestIdempotentActivateOneConnection(t *testing.T) {
	a := actSetup(t)
	is := a.issue(t, "pro")
	a.db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	withCtx := func(r *http.Request) { *r = *r.WithContext(ctx) }
	if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(is.Key), header("Idempotency-Key", "k1"), withCtx); r.code != 200 {
		t.Fatalf("activate: %d %s", r.code, r.raw)
	}
}

// Past maxKeys distinct keys in a minute, new keys pass untracked (memory
// stays bounded); keys already counted stay limited.
func TestKeyLimiterBounded(t *testing.T) {
	l := newKeyLimiter(5)
	l.maxKeys = 2
	at := time.Date(2026, 11, 8, 12, 0, 30, 0, time.UTC)
	l.now = func() time.Time { return at } // a minute boundary mid-test would reset the counts
	w := httptest.NewRecorder()
	for _, k := range []string{"a", "b"} {
		if ok, _, _ := l.take(w, k); !ok {
			t.Fatal(k)
		}
	}
	for range 10 {
		if ok, _, _ := l.take(w, "c"); !ok {
			t.Fatal("untracked key refused")
		}
	}
	if len(l.counts) != 2 {
		t.Errorf("%d keys tracked", len(l.counts))
	}
	if ok, _, _ := l.take(w, "a"); !ok {
		t.Error("known key refused")
	}
	var mu sync.Mutex // concurrent use is safe (go test -race)
	var wg sync.WaitGroup
	n := 0
	for range 20 {
		wg.Go(func() {
			if ok, _, _ := l.take(httptest.NewRecorder(), "b"); ok {
				mu.Lock()
				n++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if n != 4 { // quota 5, one used
		t.Errorf("%d admitted", n)
	}
}

func TestActivationIdempotency(t *testing.T) {
	a := actSetup(t)
	ctx := context.Background()
	is := a.issue(t, "pro")
	fp := newFP()
	key := header("Idempotency-Key", "order-1")
	first := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(is.Key), key)
	again := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(is.Key), key)
	if first.code != 200 || again.code != 200 || first.raw != again.raw {
		t.Fatalf("replay: %d %d\n%s\n%s", first.code, again.code, first.raw, again.raw)
	}
	if n := len(a.activations(t, is.License.ID)); n != 1 {
		t.Errorf("%d activations", n)
	}
	// The same key with another body.
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(is.Key), key).problem(t, 422, "idempotency_key_reused")
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(is.Key), header("Idempotency-Key", strings.Repeat("k", 256))).problem(t, 400, "invalid_request")
	// Another license with the same key is independent.
	other := a.issue(t, "pro")
	if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(other.Key), key); r.code != 200 || r.raw == first.raw {
		t.Errorf("other license: %d", r.code)
	}

	// A refusal is stored with its audit entry, and replayed.
	full := a.issue(t, "pro")
	for range 2 {
		if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(full.Key)); r.code != 200 {
			t.Fatal(r.raw)
		}
	}
	before := a.events(t, "activation.create")
	third := actBody(newFP())
	a.do(t, "POST", actPath(a.a.ID, "activate"), third, licenseAuth(full.Key), key).problem(t, 409, "activation_limit_reached")
	if a.events(t, "activation.create") != before+1 {
		t.Error("refusal not audited")
	}
	a.do(t, "POST", actPath(a.a.ID, "activate"), third, licenseAuth(full.Key), key).problem(t, 409, "activation_limit_reached")
	if a.events(t, "activation.create") != before+1 {
		t.Error("replay audited again")
	}

	// A replay after the license is revoked answers the revocation (the
	// replay check reruns), not the stored lease.
	m := authz.Principal{Kind: authz.User, ID: "usr_mgr", TenantID: a.a.ID, Role: authz.Manager, Scope: authz.Scope{All: true}}
	if _, err := a.lic.Revoke(ctx, m, is.License.ID); err != nil {
		t.Fatal(err)
	}
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(is.Key), key).problem(t, 403, "license_revoked")

	// Suspended, and expired past grace, answer the same way.
	susp, exp := a.issue(t, "pro"), a.issue(t, "pro")
	sfp, efp := newFP(), newFP()
	for _, l := range []struct{ key, fp string }{{susp.Key, sfp}, {exp.Key, efp}} {
		if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(l.fp), licenseAuth(l.key), key); r.code != 200 {
			t.Fatal(r.raw)
		}
	}
	if _, err := a.lic.Suspend(ctx, m, susp.License.ID); err != nil {
		t.Fatal(err)
	}
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET expires_at = issued_at + interval '1 microsecond', grace_seconds = 0 WHERE id = $1`, exp.License.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(sfp), licenseAuth(susp.Key), key).problem(t, 403, "license_suspended")
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(efp), licenseAuth(exp.Key), key).problem(t, 403, "license_expired")
}

// A release after the window moved on leaves the new window's count alone.
func TestKeyLimiterReleaseOldWindow(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 59, 0, time.UTC)
	l := newKeyLimiter(2)
	l.now = func() time.Time { return now }
	w := httptest.NewRecorder()
	_, _, old := l.take(w, "k")
	now = now.Add(2 * time.Second) // the next minute
	if _, _, cur := l.take(w, "k"); cur.Equal(old) {
		t.Fatal("same window")
	}
	l.release("k", old)
	if n := l.counts[sha256.Sum256([]byte("k"))]; n != 1 {
		t.Errorf("count %d after a stale release", n)
	}
	_, _, cur := l.take(w, "k")
	l.release("k", cur)
	if n := l.counts[sha256.Sum256([]byte("k"))]; n != 1 {
		t.Errorf("count %d after a current release", n)
	}
}

// The dashboard's activation API: list a license's seats, deactivate one
// (activation:manage, audited, the seat freed as the SDK's deactivate frees
// it), and the License view's active_activations.
func TestActivationManagement(t *testing.T) {
	a := actSetup(t)
	ctx := context.Background()
	is, other := a.issue(t, "pro"), a.issue(t, "pro")
	fps := []string{newFP(), newFP()}
	for _, fp := range fps {
		if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(is.Key)); r.code != 200 {
			t.Fatalf("activate: %s", r.raw)
		}
	}
	otherAct := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(other.Key)).body["activation_id"].(string)
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(is.Key)).problem(t, 409, "activation_limit_reached")
	var prodQ string
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
		p, err := tx.Product.Create().SetTenantID(a.a.ID).SetSlug("other").SetName("Other").Save(ctx)
		if err == nil {
			prodQ = p.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	viewer, support := a.session(t, a.viewerA, true), a.session(t, a.join(t, a.a.ID, invitation.RoleSupport, a.ownerA), true)
	scoped := a.session(t, a.join(t, a.a.ID, invitation.RoleSupport, a.ownerA, prodQ), true)
	lp := Prefix + "/tenants/" + a.a.Slug + "/licenses/" + is.License.ID
	list := func(q string, o opt) []any {
		t.Helper()
		r := a.do(t, "GET", lp+"/activations"+q, "", o)
		if r.code != 200 {
			t.Fatalf("list: %d %s", r.code, r.raw)
		}
		var out []any
		for _, it := range r.body["items"].([]any) {
			out = append(out, it.(map[string]any)["fingerprint"])
		}
		if c, ok := r.body["next_cursor"].(string); ok {
			out = append(out, "cursor:"+c)
		}
		return out
	}
	// Newest first, paged.
	if got := list("", viewer); !reflect.DeepEqual(got, []any{fps[1], fps[0]}) {
		t.Errorf("list: %v", got)
	}
	page := list("?limit=1", viewer)
	if len(page) != 2 || page[0] != fps[1] {
		t.Fatalf("page 1: %v", page)
	}
	if got := list("?limit=1&cursor="+strings.TrimPrefix(page[1].(string), "cursor:"), viewer); !reflect.DeepEqual(got, []any{fps[0]}) {
		t.Errorf("page 2: %v", got)
	}
	a.do(t, "GET", lp+"/activations?cursor=x", "", viewer).problem(t, 400, "invalid_cursor")
	a.do(t, "GET", lp+"/activations?status=active", "", viewer).problem(t, 400, "invalid_request")
	seats := func(o opt) any {
		t.Helper()
		got := a.do(t, "GET", lp, "", o).body["active_activations"]
		l := a.do(t, "GET", Prefix+"/tenants/"+a.a.Slug+"/licenses?limit=1", "", o).body["items"].([]any)[0].(map[string]any)
		if l["id"] != other.License.ID || l["active_activations"] != 1.0 {
			t.Errorf("license list: %v", l)
		}
		return got
	}
	if n := seats(viewer); n != 2.0 {
		t.Errorf("active_activations = %v", n)
	}

	// Hidden, missing, malformed and another tenant's answer alike; an
	// activation of another license is missing too.
	acts := a.activations(t, is.License.ID)
	act := acts[0].ID
	missing := a.do(t, "GET", Prefix+"/tenants/"+a.a.Slug+"/licenses/"+ids.License()+"/activations", "", viewer).problem(t, 404, "not_found")
	bOwner := a.session(t, a.ownerB, true)
	for name, c := range map[string]struct {
		method, path string
		o            opt
	}{
		"hidden list":                  {"GET", lp + "/activations", scoped},
		"malformed list":               {"GET", Prefix + "/tenants/" + a.a.Slug + "/licenses/x/activations", viewer},
		"another tenant's list":        {"GET", Prefix + "/tenants/" + a.b.Slug + "/licenses/" + is.License.ID + "/activations", bOwner},
		"hidden deactivate":            {"POST", lp + "/activations/" + act + "/deactivate", scoped},
		"missing license deactivate":   {"POST", Prefix + "/tenants/" + a.a.Slug + "/licenses/" + ids.License() + "/activations/" + act + "/deactivate", support},
		"another license's activation": {"POST", lp + "/activations/" + otherAct + "/deactivate", support},
		"missing activation":           {"POST", lp + "/activations/" + ids.New("act") + "/deactivate", support},
		"malformed activation":         {"POST", lp + "/activations/x/deactivate", support},
		"another tenant's deactivate":  {"POST", Prefix + "/tenants/" + a.b.Slug + "/licenses/" + is.License.ID + "/activations/" + act + "/deactivate", bOwner},
	} {
		if got := a.do(t, c.method, c.path, "", c.o).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	// Refusals are audited: missing as failed, hidden as denied.
	a.do(t, "POST", lp+"/activations/"+otherAct+"/deactivate", "", support)
	if e := a.lastEvent(t, a.a.ID); e.Action != "activation.deactivate" || e.Outcome != auditevent.OutcomeFailure {
		t.Errorf("refused deactivate audit = %+v", e)
	}
	a.do(t, "POST", lp+"/activations/"+act+"/deactivate", "", scoped)
	if e := a.lastEvent(t, a.a.ID); e.Action != "activation.deactivate" || e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("hidden deactivate audit = %+v", e)
	}
	// Seen but not changeable: 403, audited as denied.
	a.do(t, "POST", lp+"/activations/"+act+"/deactivate", "", viewer).problem(t, 403, "forbidden")
	if e := a.lastEvent(t, a.a.ID); e.Action != "activation.deactivate" || e.Outcome != auditevent.OutcomeDenied || *e.ActorID != a.viewerA || *e.ObjectID != act {
		t.Errorf("denied deactivate audit = %+v", e)
	}
	if n := len(a.activations(t, other.License.ID)); n != 1 || a.activations(t, other.License.ID)[0].DeactivatedAt != nil {
		t.Errorf("another license's activation changed")
	}

	// Deactivate: the seat is free, the SDK sees it, and it is audited.
	before := a.events(t, "activation.deactivate")
	r := a.do(t, "POST", lp+"/activations/"+act+"/deactivate", "", support)
	if r.code != 200 || r.body["id"] != act || r.body["deactivated_at"] == nil || r.body["license_id"] != is.License.ID {
		t.Fatalf("deactivate: %d %s", r.code, r.raw)
	}
	e := a.lastEvent(t, a.a.ID)
	if e.Action != "activation.deactivate" || e.Outcome != auditevent.OutcomeSuccess || e.ActorType != auditevent.ActorTypeUser ||
		*e.ObjectID != act || !strings.Contains(e.Details, is.License.ID) {
		t.Errorf("deactivate audit = %+v", e)
	}
	if n := seats(viewer); n != 1.0 {
		t.Errorf("active_activations after deactivate = %v", n)
	}
	a.do(t, "POST", actPath(a.a.ID, "refresh"), actBody(acts[0].Fingerprint), licenseAuth(is.Key)).problem(t, 404, "not_activated")
	if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(is.Key)); r.code != 200 {
		t.Errorf("seat not freed: %s", r.raw)
	}
	// Again: nothing changes, the same answer, no second entry.
	again := a.do(t, "POST", lp+"/activations/"+act+"/deactivate", "", support)
	if again.code != 200 || again.body["deactivated_at"] != r.body["deactivated_at"] {
		t.Errorf("repeat: %d %s", again.code, again.raw)
	}
	if n := a.events(t, "activation.deactivate"); n != before+1 {
		t.Errorf("deactivate entries %d, want %d", n, before+1)
	}
	// A status change answers with the seats counted in its transaction.
	if r := a.do(t, "POST", lp+"/suspend", "", a.session(t, a.ownerA, true)); r.code != 200 || r.body["active_activations"] != 2.0 {
		t.Errorf("suspend: %d %s", r.code, r.raw)
	}
	// Activations created at the same instant page by ID: both come back.
	tie := a.issue(t, "pro")
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
		at := time.Now().UTC().Truncate(time.Microsecond)
		for range 2 {
			if _, err := tx.Activation.Create().SetTenantID(a.a.ID).SetLicenseID(tie.License.ID).SetFingerprint(newFP()).
				SetFpSource(activation.FpSourceMachineID).SetBinding(activation.BindingMachine).SetMode(activation.ModeOnline).
				SetFirstSeenAt(at).SetLastSeenAt(at).SetCreatedAt(at).SetUpdatedAt(at).Save(ctx); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	tp := Prefix + "/tenants/" + a.a.Slug + "/licenses/" + tie.License.ID + "/activations?limit=1"
	r1 := a.do(t, "GET", tp, "", viewer)
	c, _ := r1.body["next_cursor"].(string)
	r2 := a.do(t, "GET", tp+"&cursor="+c, "", viewer)
	i1, _ := r1.body["items"].([]any)
	i2, _ := r2.body["items"].([]any)
	if c == "" || len(i1) != 1 || len(i2) != 1 || i1[0].(map[string]any)["id"] == i2[0].(map[string]any)["id"] {
		t.Errorf("tied pages: %s / %s", r1.raw, r2.raw)
	}
	// Seats are counted only in the caller's product scope.
	q := authz.Principal{Kind: authz.User, ID: "usr_q", TenantID: a.a.ID, Role: authz.Viewer, Scope: authz.Scope{Products: []string{prodQ}}}
	if got, err := a.srv.Activations.ActiveSeats(ctx, q, is.License.ID); err != nil || len(got) != 0 {
		t.Errorf("out-of-scope seats: %v %v", got, err)
	}
}

// Support rehost (ADR-0039): free the old machine, then reset the move
// counter of a license at its limit, so the customer's new machine can move
// in. activation:manage on the license's product; audited.
func TestRehostReset(t *testing.T) {
	a := actSetup(t)
	ctx := context.Background()
	is := a.issue(t, "pro")
	for range 2 {
		if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(is.Key)); r.code != 200 {
			t.Fatalf("activate: %s", r.raw)
		}
	}
	// At the limit: one move allowed, one used.
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET max_rehosts = 1, rehost_count = 1 WHERE id = $1`, is.License.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var prodQ string
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
		p, err := tx.Product.Create().SetTenantID(a.a.ID).SetSlug("other").SetName("Other").Save(ctx)
		if err == nil {
			prodQ = p.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	viewer, support := a.session(t, a.viewerA, true), a.session(t, a.join(t, a.a.ID, invitation.RoleSupport, a.ownerA), true)
	scoped := a.session(t, a.join(t, a.a.ID, invitation.RoleSupport, a.ownerA, prodQ), true)
	lp := Prefix + "/tenants/" + a.a.Slug + "/licenses/" + is.License.ID
	if r := a.do(t, "GET", lp, "", viewer); r.body["rehost_count"] != 1.0 || r.body["max_rehosts"] != 1.0 {
		t.Errorf("license view: %s", r.raw)
	}
	// The dead machine freed, the new one is still a move past the limit.
	if r := a.do(t, "POST", lp+"/activations/"+a.activations(t, is.License.ID)[0].ID+"/deactivate", "", support); r.code != 200 {
		t.Fatalf("deactivate: %s", r.raw)
	}
	newMachine := newFP()
	a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newMachine), licenseAuth(is.Key)).problem(t, 409, "rehost_limit_reached")

	// Hidden, missing, malformed and another tenant's answer alike, audited;
	// seen but not allowed is 403.
	missing := a.do(t, "POST", Prefix+"/tenants/"+a.a.Slug+"/licenses/"+ids.License()+"/rehosts/reset", "", support).problem(t, 404, "not_found")
	for name, c := range map[string]struct {
		path string
		o    opt
	}{
		"hidden":           {lp + "/rehosts/reset", scoped},
		"malformed":        {Prefix + "/tenants/" + a.a.Slug + "/licenses/x/rehosts/reset", support},
		"another tenant's": {Prefix + "/tenants/" + a.b.Slug + "/licenses/" + is.License.ID + "/rehosts/reset", a.session(t, a.ownerB, true)},
	} {
		if got := a.do(t, "POST", c.path, "", c.o).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	a.do(t, "POST", lp+"/rehosts/reset", "", scoped)
	if e := a.lastEvent(t, a.a.ID); e.Action != "license.rehosts_reset" || e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("hidden reset audit = %+v", e)
	}
	a.do(t, "POST", lp+"/rehosts/reset", "", viewer).problem(t, 403, "forbidden")
	if e := a.lastEvent(t, a.a.ID); e.Action != "license.rehosts_reset" || e.Outcome != auditevent.OutcomeDenied || *e.ObjectID != is.License.ID {
		t.Errorf("denied reset audit = %+v", e)
	}
	if r := a.do(t, "GET", lp, "", viewer); r.body["rehost_count"] != 1.0 {
		t.Errorf("refused resets changed the count: %s", r.raw)
	}

	// Reset: counted from zero again, audited with what it was.
	before := a.events(t, "license.rehosts_reset")
	r := a.do(t, "POST", lp+"/rehosts/reset", "", support)
	if r.code != 200 || r.body["id"] != is.License.ID || r.body["rehost_count"] != 0.0 || r.body["max_rehosts"] != 1.0 || r.body["active_activations"] != 1.0 {
		t.Fatalf("reset: %d %s", r.code, r.raw)
	}
	e := a.lastEvent(t, a.a.ID)
	if e.Action != "license.rehosts_reset" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != is.License.ID ||
		!strings.Contains(e.Details, `"previous_rehost_count":1`) || !strings.Contains(e.Details, `"max_rehosts":1`) {
		t.Errorf("reset audit = %+v", e)
	}
	// The new machine moves in, using the move again.
	if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newMachine), licenseAuth(is.Key)); r.code != 200 {
		t.Fatalf("activate after reset: %s", r.raw)
	}
	if r := a.do(t, "GET", lp, "", viewer); r.body["rehost_count"] != 1.0 {
		t.Errorf("after the move: %s", r.raw)
	}
	// At zero: unchanged, no entry.
	if r := a.do(t, "POST", lp+"/rehosts/reset", "", support); r.code != 200 || r.body["rehost_count"] != 0.0 {
		t.Fatalf("second reset: %d %s", r.code, r.raw)
	}
	if r := a.do(t, "POST", lp+"/rehosts/reset", "", support); r.code != 200 || r.body["rehost_count"] != 0.0 {
		t.Errorf("reset at zero: %d %s", r.code, r.raw)
	}
	if n := a.events(t, "license.rehosts_reset"); n != before+2 {
		t.Errorf("reset entries %d, want %d", n, before+2)
	}
	// Suspended: support may prepare a reinstatement.
	owner := a.session(t, a.ownerA, true)
	if r := a.do(t, "POST", lp+"/suspend", "", owner); r.code != 200 {
		t.Fatalf("suspend: %s", r.raw)
	}
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET rehost_count = 1 WHERE id = $1`, is.License.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := a.do(t, "POST", lp+"/rehosts/reset", "", support); r.code != 200 || r.body["rehost_count"] != 0.0 || r.body["status"] != "suspended" {
		t.Errorf("reset a suspended license: %d %s", r.code, r.raw)
	}
	// Revoked: nothing to prepare, 409, audited as a failure.
	if r := a.do(t, "POST", lp+"/revoke", "", owner); r.code != 200 {
		t.Fatalf("revoke: %s", r.raw)
	}
	a.do(t, "POST", lp+"/rehosts/reset", "", support).problem(t, 409, "invalid_state")
	if e := a.lastEvent(t, a.a.ID); e.Action != "license.rehosts_reset" || e.Outcome != auditevent.OutcomeFailure || *e.ObjectID != is.License.ID {
		t.Errorf("revoked reset audit = %+v", e)
	}
}

// A reset takes the license lock activation takes, so a seat move landing
// meanwhile is counted before the reset, and its entry records what it reset.
func TestRehostResetWaitsForLicenseLock(t *testing.T) {
	a := actSetup(t)
	ctx := context.Background()
	is := a.issue(t, "pro")
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE licenses SET rehost_count = 1 WHERE id = $1`, is.License.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
			// What a seat move does: the license lock, then the count.
			if _, err := tx.ExecContext(ctx, `SELECT 1 FROM licenses WHERE id = $1 FOR NO KEY UPDATE`, is.License.ID); err != nil {
				close(locked)
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE licenses SET rehost_count = rehost_count + 1 WHERE id = $1`, is.License.ID)
			close(locked)
			<-release
			return err
		})
	}()
	<-locked
	res := make(chan resp, 1)
	go func() {
		res <- a.do(t, "POST", Prefix+"/tenants/"+a.a.Slug+"/licenses/"+is.License.ID+"/rehosts/reset", "", a.session(t, a.ownerA, true))
	}()
	for deadline := time.Now().Add(10 * time.Second); ; {
		var n int
		if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
			rows, err := tx.QueryContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			rows.Next()
			return rows.Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("the reset never waited on a lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r := <-res; r.code != 200 || r.body["rehost_count"] != 0.0 {
		t.Fatalf("reset: %d %s", r.code, r.raw)
	}
	if e := a.lastEvent(t, a.a.ID); e.Action != "license.rehosts_reset" || !strings.Contains(e.Details, `"previous_rehost_count":2`) {
		t.Errorf("reset audit = %+v (want the concurrent move counted)", e)
	}
}

// A dashboard deactivate waits for the license lock, as the SDK's does, so
// one landing while the SDK deactivates the same machine answers with the
// activation, deactivated, instead of failing on the row.
func TestDeactivateActivationWaitsForLicenseLock(t *testing.T) {
	a := actSetup(t)
	ctx := context.Background()
	is := a.issue(t, "pro")
	act := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(newFP()), licenseAuth(is.Key)).body["activation_id"].(string)
	path := Prefix + "/tenants/" + a.a.Slug + "/licenses/" + is.License.ID + "/activations/" + act + "/deactivate"
	locked, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
			// What the SDK's Deactivate does: the license lock, then the seat.
			if _, err := tx.ExecContext(ctx, `SELECT 1 FROM licenses WHERE id = $1 FOR NO KEY UPDATE`, is.License.ID); err != nil {
				close(locked)
				return err
			}
			_, err := tx.ExecContext(ctx, `UPDATE activations SET deactivated_at = clock_timestamp() WHERE id = $1`, act)
			close(locked)
			<-release
			return err
		})
	}()
	<-locked
	res := make(chan resp, 1)
	go func() { res <- a.do(t, "POST", path, "", a.session(t, a.ownerA, true)) }()
	// Commit once the request waits on a lock (the license's; without it,
	// the activation row's).
	for deadline := time.Now().Add(10 * time.Second); ; {
		var n int
		if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
			rows, err := tx.QueryContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			rows.Next()
			return rows.Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("the request never waited on a lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r := <-res; r.code != 200 || r.body["deactivated_at"] == nil {
		t.Errorf("deactivate: %d %s", r.code, r.raw)
	}
	if n := a.events(t, "activation.deactivate"); n != 0 { // the change was the other transaction's
		t.Errorf("%d entries", n)
	}
}

// The Go SDK's online client against the real handler: activate, refresh,
// a license check on the cached lease, deactivate.
func TestSDKOnlineClient(t *testing.T) {
	a := actSetup(t)
	is := a.issue(t, "pro")
	srv := httptest.NewServer(a.srv)
	defer srv.Close()
	ctx := context.Background()
	var kid string
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) (err error) { kid, err = tx.SigningKey.Query().OnlyID(ctx); return }); err != nil {
		t.Fatal(err)
	}
	pk, err := a.keys.Public(ctx, a.a.ID, kid)
	if err != nil {
		t.Fatal(err)
	}
	fpHash, err := fingerprint.Hash(a.a.ID, "db", "machine-1")
	if err != nil {
		t.Fatal(err)
	}
	c, err := online.New(online.Config{BaseURL: srv.URL, TenantID: a.a.ID, Product: "db", LicenseKey: is.Key,
		Keys:        licensefile.KeySet{{KID: pk.KID, Alg: licensefile.AlgEd25519, Key: pk.Key}},
		Fingerprint: fingerprint.Result{Fingerprint: fpHash, Source: fingerprint.SourceMachineID, Binding: "machine"}, AppVersion: "1.0"})
	if err != nil {
		t.Fatal(err)
	}
	l, err := c.Activate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if claims, st, err := c.Current(); err != nil || st != licensefile.StatusValid || claims.LicenseID != is.License.ID {
		t.Errorf("Current = %v %v", st, err)
	}
	if as := a.activations(t, is.License.ID); len(as) != 1 || as[0].ID != l.ActivationID {
		t.Errorf("activations %+v", as)
	}
	if err := c.Deactivate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(ctx); !errors.Is(err, online.ErrNotActivated) {
		t.Errorf("refresh after deactivate: %v", err)
	}
}

// An offline seat (ADR-0043) answers the SDK's online calls with 409
// offline_seat, and an idempotent activate replays it.
func TestOfflineSeatOverHTTP(t *testing.T) {
	a := actSetup(t)
	is := a.issue(t, "offline")
	fp := newFP()
	text, err := licensefile.EncodeRequest(licensefile.Request{Tenant: a.a.ID, Product: "db", Key: is.Key,
		Binding: licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: fp}, FPSource: "machine-id", Nonce: make([]byte, 16), Created: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	m := authz.Principal{Kind: authz.User, ID: "usr_mgr", TenantID: a.a.ID, Role: authz.Manager, Scope: authz.Scope{All: true}}
	if _, err := a.srv.Activations.Offline(context.Background(), m, text); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(fp), licenseAuth(is.Key), header("Idempotency-Key", "off")).problem(t, 409, "offline_seat")
	}
	a.do(t, "POST", actPath(a.a.ID, "refresh"), actBody(fp), licenseAuth(is.Key)).problem(t, 409, "offline_seat")
	a.do(t, "POST", actPath(a.a.ID, "deactivate"), `{"fingerprint":"`+fp+`"}`, licenseAuth(is.Key)).problem(t, 409, "offline_seat")
}

// Offline activation over the management API (ADR-0043): a session with
// activation:offline turns a request into a file; Idempotency-Key replays it
// after re-checking the caller's rights.
func TestCreateOfflineActivation(t *testing.T) {
	a := actSetup(t)
	ctx := context.Background()
	is := a.issue(t, "offline")
	reqFor := func(key, fp string) string {
		text, err := licensefile.EncodeRequest(licensefile.Request{Tenant: a.a.ID, Product: "db", Key: key,
			Binding: licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: fp}, FPSource: "machine-id", Nonce: make([]byte, 16), Created: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(map[string]string{"request": text})
		return string(b)
	}
	p := Prefix + "/tenants/" + a.a.Slug + "/activation-requests"
	admin := a.session(t, a.adminA, true)
	body := reqFor(is.Key, newFP())
	k := header("Idempotency-Key", "air-1")
	first := a.do(t, "POST", p, body, admin, k)
	if first.code != 201 || first.body["expires_at"] == nil {
		t.Fatalf("first: %d %s", first.code, first.raw)
	}
	file, _ := first.body["license_file"].(string)
	if h, err := licensefile.FileSHA256(file); err != nil || h != first.body["file_sha256"] {
		t.Errorf("file_sha256 %v, file's %s (%v)", first.body["file_sha256"], h, err)
	}
	again := a.do(t, "POST", p, body, admin, k)
	if again.code != 201 || again.body["license_file"] != file || again.body["activation_id"] != first.body["activation_id"] {
		t.Errorf("replay: %d %s", again.code, again.raw)
	}
	if as := a.activations(t, is.License.ID); len(as) != 1 || as[0].Mode != activation.ModeOffline {
		t.Errorf("activations %+v", as)
	}
	online := a.issue(t, "pro")
	onlineFP := newFP()
	if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(onlineFP), licenseAuth(online.Key)); r.code != 200 {
		t.Fatalf("activate: %d %s", r.code, r.raw)
	}
	other := a.issue(t, "offline")
	if r := a.do(t, "POST", actPath(a.a.ID, "activate"), actBody(onlineFP), licenseAuth(other.Key)); r.code != 200 {
		t.Fatalf("activate: %d %s", r.code, r.raw)
	}
	// An idempotent refusal is stored, replayed, and audited once.
	refusals := func() int {
		var n int
		if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) (err error) {
			n, err = tx.AuditEvent.Query().Where(auditevent.Action("activation.offline"), auditevent.OutcomeEQ(auditevent.OutcomeFailure)).Count(ctx)
			return
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before, rk, rb := refusals(), header("Idempotency-Key", "air-refused"), reqFor(online.Key, newFP())
	a.do(t, "POST", p, rb, admin, rk).problem(t, 409, "offline_not_allowed")
	a.do(t, "POST", p, rb, admin, rk).problem(t, 409, "offline_not_allowed")
	if n := refusals() - before; n != 1 {
		t.Errorf("refusal stored and replayed: %d audited", n)
	}
	wrong, err := licensefile.EncodeRequest(licensefile.Request{Tenant: a.b.ID, Product: "db", Key: is.Key,
		Binding: licensefile.Binding{Type: licensefile.BindMachine, Fingerprint: newFP()}, FPSource: "machine-id", Nonce: make([]byte, 16), Created: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	wb, _ := json.Marshal(map[string]string{"request": wrong})
	a.do(t, "POST", p, string(wb), admin).problem(t, 400, "invalid_request")
	a.do(t, "POST", p, reqFor(other.Key, onlineFP), admin).problem(t, 409, "online_seat")
	a.do(t, "POST", p, reqFor(is.Key, newFP()), admin).problem(t, 409, "activation_limit_reached")
	a.do(t, "POST", p, `{"request":"lfreq1.e30"}`, admin).problem(t, 400, "invalid_request")
	a.do(t, "POST", p, reqFor(licensekey.New(), newFP()), admin).problem(t, 404, "not_found")

	// A replay re-checks the caller's rights: demoted to viewer, the stored
	// file isn't handed out again.
	if err := a.db.WithTenant(ctx, a.a.ID, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE memberships SET role = 'viewer' WHERE id = $1`, a.mem[a.adminA])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := a.do(t, "POST", p, body, admin, k).problem(t, 403, "forbidden"); r["license_file"] != nil {
		t.Errorf("replay leaked: %v", r)
	}
}
