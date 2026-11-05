package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
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
	// With an API host, the activation API is served there only.
	a.srv.APIHost = "api.lf.example"
	onHost := func(h string) opt { return func(r *http.Request) { r.Host = h } }
	a.do(t, "POST", path, body, licenseAuth(is.Key), onHost("lf.example")).problem(t, 404, "not_found")
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

// Past maxKeys distinct keys in a minute, new keys pass untracked (memory
// stays bounded); keys already counted stay limited.
func TestKeyLimiterBounded(t *testing.T) {
	l := newKeyLimiter(5)
	l.maxKeys = 2
	w := httptest.NewRecorder()
	for _, k := range []string{"a", "b"} {
		if ok, _ := l.take(w, k); !ok {
			t.Fatal(k)
		}
	}
	for range 10 {
		if ok, _ := l.take(w, "c"); !ok {
			t.Fatal("untracked key refused")
		}
	}
	if len(l.counts) != 2 {
		t.Errorf("%d keys tracked", len(l.counts))
	}
	if ok, _ := l.take(w, "a"); !ok {
		t.Error("known key refused")
	}
	var mu sync.Mutex // concurrent use is safe (go test -race)
	var wg sync.WaitGroup
	n := 0
	for range 20 {
		wg.Go(func() {
			if ok, _ := l.take(httptest.NewRecorder(), "b"); ok {
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
}
