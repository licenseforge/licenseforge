package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

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
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/signing"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
	"licenseforge.io/licenseforge/internal/tenants"
	"licenseforge.io/licenseforge/internal/weblogin"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db                              *store.DB
	srv                             *server
	tokens                          apitokens.Service
	a, b                            *ent.Tenant
	prodA                           string
	ownerA, adminA, viewerA, scoped string // members of a; scoped: admin of prodA only
	ownerB, outsider                string
	mem                             map[string]string // user ID -> membership ID
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	sessions, err := weblogin.NewSessions(identity.Service{DB: d}, "https://lf.example/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{db: d, tokens: apitokens.Service{DB: d}, mem: map[string]string{}}
	kr, err := secrets.ParseKeyring("k1=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	f.srv = New(Config{Tokens: f.tokens, Members: members.Service{DB: d}, Invitations: invitations.Service{DB: d}, Tenants: tenants.Service{DB: d}, Identity: identity.Service{DB: d}, Sessions: sessions,
		Licenses: licenses.Service{DB: d, Keys: kr}, Idempotency: idempotency.Store{DB: d, Keys: kr},
		Products: catalog.Products{DB: d}, Features: catalog.Features{DB: d}, Customers: customers.Service{DB: d}, Audit: audit.Log{DB: d}, SigningKeys: signing.Local{DB: d, Keys: kr}, Activations: activations.Service{DB: d, Keys: kr},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).(*server)
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		for _, tn := range []**ent.Tenant{&f.a, &f.b} {
			if *tn, err = tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx); err != nil {
				return err
			}
		}
		p, err := tx.Product.Create().SetTenantID(f.a.ID).SetSlug("db").SetName("DB").Save(ctx)
		f.prodA = p.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.ownerA = f.join(t, f.a.ID, invitation.RoleOwner, "")
	f.ownerB = f.join(t, f.b.ID, invitation.RoleOwner, "")
	f.adminA = f.join(t, f.a.ID, invitation.RoleAdmin, f.ownerA)
	f.viewerA = f.join(t, f.a.ID, invitation.RoleViewer, f.ownerA)
	f.scoped = f.join(t, f.a.ID, invitation.RoleAdmin, f.ownerA, f.prodA)
	f.outsider = f.join(t, f.b.ID, invitation.RoleViewer, f.ownerB)
	return f
}

// join creates a user and makes them a member through an invitation: by the
// platform for the first owner, else by inviter; scoped to products if any.
func (f *fixture) join(t *testing.T, tenant string, role invitation.Role, inviter string, products ...string) string {
	t.Helper()
	ctx := context.Background()
	email := strings.ToLower(ids.New("u")[2:14]) + "@example.com"
	tok := rand.Text()
	create := func(tx *ent.Tx) error {
		c := tx.Invitation.Create().SetTenantID(tenant).SetEmail(email).SetRole(role).SetScopeAll(len(products) == 0).
			SetTokenHash(store.InvitationTokenHash(tok)).SetExpiresAt(time.Now().Add(time.Hour))
		if inviter != "" {
			c.SetInvitedBy(inviter)
		}
		inv, err := c.Save(ctx)
		for _, p := range products {
			if err == nil {
				_, err = tx.InvitationProduct.Create().SetTenantID(tenant).SetInvitationID(inv.ID).SetProductID(p).Save(ctx)
			}
		}
		return err
	}
	var err error
	if inviter == "" {
		err = f.db.WithPlatform(ctx, create)
	} else {
		err = f.db.WithTenant(ctx, tenant, create)
	}
	if err != nil {
		t.Fatal(err)
	}
	var uid string
	if err := f.db.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail(email).SetEmailVerified(true).Save(ctx)
		if err == nil {
			uid = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	m, err := f.db.AcceptInvitation(ctx, tok, uid, func(*ent.Tx, *ent.Membership) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	f.mem[uid] = m.ID
	return uid
}

// token creates a token in tenant as its owner.
func (f *fixture) token(t *testing.T, tenant, owner string, role authz.Role) apitokens.Created {
	t.Helper()
	ctx := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: owner, TenantID: tenant, Role: authz.Owner, Scope: authz.Scope{All: true}})
	c, err := f.tokens.Create(ctx, "t", role, authz.Scope{All: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type opt func(*http.Request)

func bearer(tok string) opt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}
func header(k, v string) opt { return func(r *http.Request) { r.Header.Set(k, v) } }

// session signs user in and sends the cookie and, with csrf, its token.
func (f *fixture) session(t *testing.T, user string, csrf bool) opt {
	t.Helper()
	return f.sessionAt(t, user, csrf, authz.AssuranceNone)
}

// sessionAt is session for a login that proved assurance a (ADR-0038).
func (f *fixture) sessionAt(t *testing.T, user string, csrf bool, a authz.Assurance) opt {
	t.Helper()
	cookie, err := identity.Service{DB: f.db}.NewSession(context.Background(), user, identity.SessionAuth{Assurance: a})
	if err != nil {
		t.Fatal(err)
	}
	return func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: weblogin.SessionCookie, Value: cookie})
		if csrf {
			r.Header.Set(weblogin.CSRFHeader, weblogin.CSRFToken(cookie))
		}
	}
}

type resp struct {
	code int
	h    http.Header
	raw  string
	body map[string]any
}

func (f *fixture) do(t *testing.T, method, path, body string, opts ...opt) resp {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for _, o := range opts {
		o(r)
	}
	rec := httptest.NewRecorder()
	f.srv.ServeHTTP(rec, r)
	out := resp{code: rec.Code, h: rec.Header(), raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	if out.h.Get("X-Request-Id") == "" || out.h.Get("Cache-Control") != "no-store" || out.h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("%s %s: X-Request-Id %q, Cache-Control %q, X-Content-Type-Options %q", method, path, out.h.Get("X-Request-Id"), out.h.Get("Cache-Control"), out.h.Get("X-Content-Type-Options"))
	}
	return out
}

// problem checks r is a problem+json with status and code, and returns its
// body without request_id (for equality checks).
func (r resp) problem(t *testing.T, status int, code string) map[string]any {
	t.Helper()
	if r.code != status || r.body["code"] != code || r.h.Get("Content-Type") != "application/problem+json" ||
		r.body["type"] != "about:blank" || r.body["request_id"] != r.h.Get("X-Request-Id") {
		t.Errorf("want %d %s, got %d %s %s", status, code, r.code, r.h.Get("Content-Type"), r.raw)
	}
	if status == http.StatusUnauthorized && !slices.Contains([]string{`Bearer realm="licenseforge"`, `License realm="licenseforge"`}, r.h.Get("WWW-Authenticate")) {
		t.Errorf("401 without WWW-Authenticate")
	}
	delete(r.body, "request_id")
	return r.body
}

func tokensPath(tenant string) string { return Prefix + "/tenants/" + tenant + "/api-tokens" }

// mistype changes the token's last character (checksum mismatch).
func mistype(tok string) string {
	last := "a"
	if strings.HasSuffix(tok, last) {
		last = "b"
	}
	return tok[:len(tok)-1] + last
}

func TestCredentials(t *testing.T) {
	f := setup(t)
	p := tokensPath(f.a.Slug)
	ok := f.token(t, f.a.ID, f.ownerA, authz.Viewer)
	f.do(t, "GET", p, "").problem(t, 401, "unauthenticated")
	f.do(t, "GET", p, "", bearer(ok.Token), f.session(t, f.ownerA, true)).problem(t, 400, "ambiguous_credentials")
	for name, o := range map[string]opt{
		"basic":        header("Authorization", "Basic dXNlcjpwYXNz"),
		"jwt":          bearer("eyJhbGciOiJSUzI1NiJ9.e30.c2ln"),
		"mistyped":     bearer(mistype(ok.Token)),
		"empty bearer": header("Authorization", "Bearer"),
		"two headers": func(r *http.Request) {
			r.Header.Add("Authorization", "Bearer "+ok.Token)
			r.Header.Add("Authorization", "Bearer "+ok.Token)
		},
		"dead session": func(r *http.Request) { r.AddCookie(&http.Cookie{Name: weblogin.SessionCookie, Value: "x"}) },
	} {
		if got := f.do(t, "GET", p, "", o).problem(t, 401, "unauthenticated"); got["code"] != "unauthenticated" {
			t.Errorf("%s: %v", name, got)
		}
	}
	if r := f.do(t, "GET", p, "", header("Authorization", "bearer "+ok.Token)); r.code != 200 { // the scheme is case-insensitive
		t.Errorf("lowercase scheme: %d %s", r.code, r.raw)
	}
}

func TestTokenAuth(t *testing.T) {
	f := setup(t)
	good := f.token(t, f.a.ID, f.ownerA, authz.Viewer)
	other := f.token(t, f.b.ID, f.ownerB, authz.Viewer)
	sdk := f.token(t, f.a.ID, f.ownerA, authz.SDK)
	revoked := f.token(t, f.a.ID, f.ownerA, authz.Viewer)
	ownerCtx := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: f.ownerA, TenantID: f.a.ID, Role: authz.Owner, Scope: authz.Scope{All: true}})
	if _, err := f.tokens.Revoke(ownerCtx, revoked.Row.ID); err != nil {
		t.Fatal(err)
	}
	expired := f.token(t, f.a.ID, f.ownerA, authz.Viewer)
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := owner.Exec(`UPDATE api_tokens SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1`, expired.Row.ID); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{f.a.Slug, f.a.ID} {
		if r := f.do(t, "GET", tokensPath(ref), "", bearer(good.Token)); r.code != 200 {
			t.Errorf("good token on %s: %d %s", ref, r.code, r.raw)
		}
	}
	var first map[string]any
	for name, c := range map[string]struct{ ref, tok string }{
		"another tenant's":   {f.a.Slug, other.Token},
		"wrong tenant (ID)":  {f.b.ID, good.Token},
		"unknown slug":       {"nope-" + storetest.Suffix(), good.Token},
		"NUL in slug":        {"%00", good.Token},
		"invalid UTF-8 slug": {"%ff", good.Token},
		"bad UTF-8 sequence": {"x%C3%28", good.Token},
		"unknown tenant ID":  {ids.Tenant(), good.Token},
		"reserved fallback":  {unissuedTenant, good.Token},
		"unknown token":      {f.a.Slug, apitoken.New()},
		"revoked":            {f.a.Slug, revoked.Token},
		"expired":            {f.a.Slug, expired.Token},
	} {
		got := f.do(t, "GET", tokensPath(c.ref), "", bearer(c.tok)).problem(t, 401, "unauthenticated")
		if first == nil {
			first = got
		} else if !reflect.DeepEqual(got, first) {
			t.Errorf("%s: %v differs from %v", name, got, first)
		}
	}
	// sdk tokens are refused before any handler: 403 even where a handler would answer 404.
	f.do(t, "GET", tokensPath(f.a.Slug), "", bearer(sdk.Token)).problem(t, 403, "forbidden")
	f.do(t, "POST", tokensPath(f.a.Slug)+"/"+ids.APIToken()+"/revoke", "", bearer(sdk.Token)).problem(t, 403, "forbidden")
	// Invalid credentials are 401 before anything about the path.
	f.do(t, "GET", Prefix+"/nope", "", bearer("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")).problem(t, 401, "unauthenticated")
	// A token never gets a session's CSRF treatment: no header needed.
	admin := f.token(t, f.a.ID, f.ownerA, authz.Admin)
	f.do(t, "POST", tokensPath(f.a.Slug)+"/"+good.Row.ID+"/revoke", "", bearer(admin.Token), header("Sec-Fetch-Site", "cross-site")).problem(t, 403, "forbidden") // tokens can't manage tokens
}

func TestSessionAuth(t *testing.T) {
	f := setup(t)
	if r := f.do(t, "GET", tokensPath(f.a.Slug), "", f.session(t, f.viewerA, false)); r.code != 200 {
		t.Errorf("member: %d %s", r.code, r.raw)
	}
	nonMember := f.do(t, "GET", tokensPath(f.a.Slug), "", f.session(t, f.outsider, false)).problem(t, 404, "not_found")
	for _, ref := range []string{"nope-" + storetest.Suffix(), ids.Tenant(), f.a.ID + "x", "%00", "%ff", "x%C3%28"} {
		if got := f.do(t, "GET", tokensPath(ref), "", f.session(t, f.ownerA, false)).problem(t, 404, "not_found"); !reflect.DeepEqual(got, nonMember) {
			t.Errorf("unknown tenant %s: %v, non-member %v", ref, got, nonMember)
		}
	}
	body := `{"name":"CI","role":"viewer","all_products":true}`
	f.do(t, "POST", tokensPath(f.a.Slug), body, f.session(t, f.ownerA, false)).problem(t, 403, "csrf_failed")
	f.do(t, "POST", tokensPath(f.a.Slug), body, f.session(t, f.ownerA, true), header("Sec-Fetch-Site", "cross-site")).problem(t, 403, "csrf_failed")
	f.do(t, "POST", tokensPath(f.a.Slug), body, f.session(t, f.ownerA, true), header("Origin", "https://evil.example")).problem(t, 403, "csrf_failed")
	if r := f.do(t, "POST", tokensPath(f.a.Slug), body, f.session(t, f.ownerA, true)); r.code != 201 {
		t.Errorf("create: %d %s", r.code, r.raw)
	}
}

func TestHosts(t *testing.T) {
	f := setup(t)
	f.srv.APIHost = "api.lf.example"
	tok := f.token(t, f.a.ID, f.ownerA, authz.Viewer)
	onHost := func(h string) opt { return func(r *http.Request) { r.Host = h } }
	p := tokensPath(f.a.Slug)
	if r := f.do(t, "GET", p, "", bearer(tok.Token), onHost("API.lf.example:443")); r.code != 200 {
		t.Errorf("token on API host: %d", r.code)
	}
	f.do(t, "GET", p, "", f.session(t, f.ownerA, false), onHost("api.lf.example")).problem(t, 401, "unauthenticated")
	f.do(t, "GET", p, "", bearer(tok.Token), onHost("lf.example")).problem(t, 401, "unauthenticated")
	if r := f.do(t, "GET", p, "", f.session(t, f.ownerA, false), onHost("lf.example")); r.code != 200 {
		t.Errorf("session on dashboard host: %d", r.code)
	}
	f.srv.Sessions = nil // login off: a session is no credential
	f.do(t, "GET", p, "", f.session(t, f.ownerA, false), onHost("lf.example")).problem(t, 401, "unauthenticated")
}

func TestTokenEndpoints(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := tokensPath(f.a.Slug)
	var made []map[string]any
	for _, role := range []string{"viewer", "admin", "sdk"} {
		r := f.do(t, "POST", p, `{"name":"CI `+role+`","role":"`+role+`","all_products":true,"ttl_seconds":3600}`, owner)
		tok, _ := r.body["token"].(string)
		if r.code != 201 || apitoken.Check(tok) != nil || r.body["display"] != apitoken.Display(tok) || r.body["created_by"] != f.ownerA {
			t.Fatalf("create: %d %s", r.code, r.raw)
		}
		made = append(made, r.body)
	}
	scopedTok := f.do(t, "POST", p, `{"name":"scoped","role":"support","all_products":false,"product_ids":["`+f.prodA+`"]}`, owner)
	if scopedTok.code != 201 || !reflect.DeepEqual(scopedTok.body["product_ids"], []any{f.prodA}) {
		t.Errorf("scoped create: %s", scopedTok.raw)
	}
	// Newest first, paginated; never a secret or a hash.
	r1 := f.do(t, "GET", p+"?limit=2", "", owner)
	items, _ := r1.body["items"].([]any)
	next, _ := r1.body["next_cursor"].(string)
	if r1.code != 200 || len(items) != 2 || next == "" || items[0].(map[string]any)["id"] != scopedTok.body["id"] {
		t.Fatalf("page 1: %s", r1.raw)
	}
	r2 := f.do(t, "GET", p+"?limit=2&cursor="+next, "", owner)
	items, _ = r2.body["items"].([]any)
	if _, more := r2.body["next_cursor"]; r2.code != 200 || len(items) != 2 || more || items[1].(map[string]any)["id"] != made[0]["id"] {
		t.Fatalf("page 2: %s", r2.raw)
	}
	for _, m := range made {
		if strings.Contains(r1.raw+r2.raw, m["token"].(string)) || strings.Contains(r1.raw+r2.raw, "hash") {
			t.Fatal("list shows a secret or hash")
		}
	}
	// Revoke: 200 with the object; then, and for hidden or missing ones, the same 404.
	rev := p + "/" + made[0]["id"].(string) + "/revoke"
	if r := f.do(t, "POST", rev, "", owner); r.code != 200 || r.body["revoked_at"] == nil {
		t.Errorf("revoke: %d %s", r.code, r.raw)
	}
	missing := f.do(t, "POST", p+"/"+ids.APIToken()+"/revoke", "", owner).problem(t, 404, "not_found")
	otherTenant := f.token(t, f.b.ID, f.ownerB, authz.Viewer)
	for name, path := range map[string]string{
		"revoked":          rev,
		"another tenant's": p + "/" + otherTenant.Row.ID + "/revoke",
		"malformed ID":     p + "/x/revoke",
	} {
		if got := f.do(t, "POST", path, "", owner).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	// Rights: 403 before 422.
	viewer := f.session(t, f.viewerA, true)
	f.do(t, "POST", p, `{"name":"","role":"nope","all_products":true}`, viewer).problem(t, 403, "forbidden")
	f.do(t, "POST", p+"/"+made[1]["id"].(string)+"/revoke", "", viewer).problem(t, 403, "forbidden")
	f.do(t, "POST", p+"/"+ids.APIToken()+"/revoke", "", viewer).problem(t, 404, "not_found") // lookup before rights
	f.do(t, "POST", p, `{"name":"x","role":"owner","all_products":true}`, f.session(t, f.adminA, true)).problem(t, 403, "forbidden")
	// Validation.
	bad := f.do(t, "POST", p, `{"name":" ","role":"root","all_products":true,"product_ids":["`+f.prodA+`"],"ttl_seconds":59}`, owner).problem(t, 422, "validation_failed")
	var fields []string
	for _, e := range bad["errors"].([]any) {
		fields = append(fields, e.(map[string]any)["field"].(string))
	}
	if !slices.Equal(fields, []string{"/name", "/role", "/product_ids", "/ttl_seconds"}) {
		t.Errorf("fields = %v", fields)
	}
	f.do(t, "POST", p, `{"name":"x","role":"viewer","all_products":false,"product_ids":["`+ids.Product()+`"]}`, owner).problem(t, 422, "validation_failed")
	f.do(t, "POST", p, `{"name":"x","role":"viewer","all_products":true,"extra":1}`, owner).problem(t, 400, "invalid_request")
	for _, trailing := range []string{"{}", "}", "]", " x"} {
		f.do(t, "POST", p, `{"name":"x","role":"viewer","all_products":true}`+trailing, owner).problem(t, 400, "invalid_request")
	}
	f.do(t, "POST", p, `{"NAME":"x","role":"viewer","all_products":true}`, owner).problem(t, 400, "invalid_request")
	for _, body := range []string{"null", " null ", "[]", `"x"`, ""} {
		f.do(t, "POST", p, body, owner).problem(t, 400, "invalid_request")
	}
	if got := f.do(t, "POST", p, `{"name":"x","role":"viewer","all_products":false,"product_ids":[""]}`, owner).problem(t, 422, "validation_failed"); !strings.Contains(fmt.Sprint(got["errors"]), "/product_ids") {
		t.Errorf("empty product ID: %v", got)
	}
	f.do(t, "POST", p, `{"name":"x","Role":"viewer","all_products":true}`, owner).problem(t, 400, "invalid_request")
	f.do(t, "POST", p, `{"name":1}`, owner).problem(t, 400, "invalid_request")
}

func TestProductScopedPrincipal(t *testing.T) {
	f := setup(t)
	tok := f.token(t, f.a.ID, f.ownerA, authz.Viewer)
	scoped := f.session(t, f.scoped, true)
	p := tokensPath(f.a.Slug)
	// Tokens are tenant-wide: a scoped admin sees none, and revoking one
	// answers exactly as for a missing token.
	if r := f.do(t, "GET", p, "", scoped); r.code != 200 || r.raw != `{"items":[]}`+"\n" {
		t.Errorf("scoped list: %d %s", r.code, r.raw)
	}
	hidden := f.do(t, "POST", p+"/"+tok.Row.ID+"/revoke", "", scoped).problem(t, 404, "not_found")
	if missing := f.do(t, "POST", p+"/"+ids.APIToken()+"/revoke", "", scoped).problem(t, 404, "not_found"); !reflect.DeepEqual(hidden, missing) {
		t.Errorf("hidden %v, missing %v", hidden, missing)
	}
	f.do(t, "POST", p, `{"name":"x","role":"viewer","all_products":true}`, scoped).problem(t, 403, "forbidden")
}

func TestErrorsAreProblems(t *testing.T) {
	f := setup(t)
	f.srv.mux.HandleFunc("GET "+Prefix+"/tenants/{tenant}/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	tok := bearer(f.token(t, f.a.ID, f.ownerA, authz.Viewer).Token)
	owner := f.session(t, f.ownerA, true)
	p := tokensPath(f.a.Slug)
	f.do(t, "GET", Prefix+"/tenants/"+f.a.Slug+"/nope", "", tok).problem(t, 404, "not_found")
	f.do(t, "GET", Prefix+"/nope", "", tok).problem(t, 401, "unauthenticated") // no tenant to verify the token in
	f.do(t, "GET", Prefix+"/nope", "", owner).problem(t, 404, "not_found")
	if r := f.do(t, "DELETE", p, "", tok); r.h.Get("Allow") == "" {
		t.Errorf("405 without Allow: %v", r.h)
	} else {
		r.problem(t, 405, "method_not_allowed")
	}
	f.do(t, "POST", p, `{"name":"`+strings.Repeat("x", maxBody)+`"}`, owner).problem(t, 413, "body_too_large")
	f.do(t, "GET", p+"?limit=abc", "", tok).problem(t, 400, "invalid_request")
	f.do(t, "GET", p+"?limit=0", "", tok).problem(t, 400, "invalid_request")
	f.do(t, "GET", p+"?order=desc", "", tok).problem(t, 400, "invalid_request")
	for _, c := range []string{"!!", "MTIz", encodeCursor(time.Now(), "lic_aaaaaaaaaaaaaaaaaaaaaaaaaa")} {
		f.do(t, "GET", p+"?cursor="+c, "", tok).problem(t, 400, "invalid_cursor")
	}
	if r := f.do(t, "GET", Prefix+"/tenants/"+f.a.Slug+"/boom", "", tok); !strings.Contains(r.raw, "internal") || strings.Contains(r.raw, "boom") {
		t.Errorf("panic leaked: %s", r.raw)
	} else {
		r.problem(t, 500, "internal")
	}
	// An inbound request ID is not echoed.
	if r := f.do(t, "GET", p, "", tok, header("X-Request-Id", "mine")); r.h.Get("X-Request-Id") == "mine" {
		t.Error("inbound X-Request-Id echoed")
	}
}

// TestRoutesMatchSpec: every route served is in api/openapi.yaml with the
// same method, and queryParams matches its query parameters.
func TestRoutesMatchSpec(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	type param struct {
		Ref  string `yaml:"$ref"`
		Name string
		In   string
	}
	var spec struct {
		Servers    []struct{ URL string }
		Paths      map[string]map[string]yaml.Node
		Components struct {
			Parameters map[string]param
		}
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	wantQuery := map[string][]string{}
	for path, ops := range spec.Paths {
		for method, node := range ops {
			if method == "parameters" {
				continue
			}
			var op struct {
				OperationID string `yaml:"operationId"`
				Parameters  []param
			}
			if err := node.Decode(&op); err != nil {
				t.Fatal(err)
			}
			want[strings.ToUpper(method)+" "+spec.Servers[0].URL+path] = true
			for _, p := range op.Parameters {
				if p.Ref != "" {
					p = spec.Components.Parameters[strings.TrimPrefix(p.Ref, "#/components/parameters/")]
				}
				if p.In == "query" {
					name := strings.ToUpper(op.OperationID[:1]) + op.OperationID[1:]
					wantQuery[name] = append(wantQuery[name], p.Name)
				}
			}
		}
	}
	rec := &recordMux{ServeMux: http.NewServeMux()}
	(&server{}).routes(rec)
	if len(rec.patterns) != len(want) {
		t.Errorf("served %v, spec %v", rec.patterns, want)
	}
	for _, p := range rec.patterns {
		if !want[p] {
			t.Errorf("served but not in the spec: %s", p)
		}
	}
	if !reflect.DeepEqual(wantQuery, queryParams) {
		t.Errorf("queryParams = %v, spec %v", queryParams, wantQuery)
	}
}

type recordMux struct {
	*http.ServeMux
	patterns []string
}

func (m *recordMux) HandleFunc(p string, h func(http.ResponseWriter, *http.Request)) {
	m.patterns = append(m.patterns, p)
	m.ServeMux.HandleFunc(p, h)
}

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"abc-123":                "abc-123",
		"a\r\nb\x00c d\u202e":    "abcd",
		strings.Repeat("x", 100): strings.Repeat("x", 64),
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q", in, got)
		}
	}
}

func TestPanics(t *testing.T) {
	f := setup(t)
	tok := bearer(f.token(t, f.a.ID, f.ownerA, authz.Viewer).Token)
	f.srv.mux.HandleFunc("GET "+Prefix+"/tenants/{tenant}/abort", func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
	f.srv.mux.HandleFunc("GET "+Prefix+"/tenants/{tenant}/late", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "partial")
		panic("late")
	})
	// http.ErrAbortHandler is re-panicked for net/http to abort the response.
	func() {
		defer func() {
			if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // sentinel panic value
				t.Errorf("recovered %v, want http.ErrAbortHandler", v)
			}
		}()
		f.do(t, "GET", Prefix+"/tenants/"+f.a.Slug+"/abort", "", tok)
	}()
	// After the response started, no problem body is appended and the
	// response is aborted, so it can't pass for a complete 200.
	func() {
		rec := httptest.NewRecorder()
		defer func() {
			if v := recover(); v != http.ErrAbortHandler || strings.Contains(rec.Body.String(), "internal") { //nolint:errorlint // sentinel panic value
				t.Errorf("late panic: recovered %v, body %q", v, rec.Body)
			}
		}()
		r := httptest.NewRequest("GET", Prefix+"/tenants/"+f.a.Slug+"/late", nil)
		tok(r)
		f.srv.ServeHTTP(rec, r)
	}()
}

func TestExactKeys(t *testing.T) {
	type inner struct {
		A string `json:"a"`
	}
	type outer struct {
		In   inner            `json:"in"`
		Ptr  *inner           `json:"ptr"`
		List []inner          `json:"list"`
		Map  map[string]inner `json:"map"`
		T    time.Time        `json:"t"`
		Raw  []byte           `json:"raw"`
	}
	typ := reflect.TypeFor[outer]()
	for raw, want := range map[string]bool{
		`{}`: true,
		`{"in":{"a":"x"},"ptr":{"a":"x"},"list":[{"a":"x"}],"map":{"k":{"a":"x"}},"t":"2026-01-01T00:00:00Z","raw":"eA=="}`: true,
		`{"ptr":null,"list":null}`:       true,
		`null`:                           false,
		`{"In":{}}`:                      false,
		`{"in":{"A":"x"}}`:               false,
		`{"ptr":{"A":"x"}}`:              false,
		`{"list":[{"a":"x"},{"A":"x"}]}`: false,
		`{"map":{"k":{"A":"x"}}}`:        false,
		`{"in":{"a":"x","b":1}}`:         false,
	} {
		if got := exactKeys([]byte(raw), typ); got != want {
			t.Errorf("exactKeys(%s) = %v", raw, got)
		}
	}
}

func membersPath(tenant string) string { return Prefix + "/tenants/" + tenant + "/members" }

func TestMemberEndpoints(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := membersPath(f.a.Slug)
	patch := func(id, body string, o opt) resp {
		return f.do(t, "PATCH", p+"/"+id, body, o, header("Content-Type", "application/merge-patch+json"))
	}
	// List: newest first, paginated, with the user's email; nothing of tenant b.
	r1 := f.do(t, "GET", p+"?limit=2", "", owner)
	items, _ := r1.body["items"].([]any)
	next, _ := r1.body["next_cursor"].(string)
	if r1.code != 200 || len(items) != 2 || next == "" || items[0].(map[string]any)["id"] != f.mem[f.scoped] ||
		!reflect.DeepEqual(items[0].(map[string]any)["product_ids"], []any{f.prodA}) || items[0].(map[string]any)["email"] == nil {
		t.Fatalf("page 1: %s", r1.raw)
	}
	r2 := f.do(t, "GET", p+"?limit=2&cursor="+next, "", owner)
	if items, _ := r2.body["items"].([]any); r2.code != 200 || len(items) != 2 || strings.Contains(r1.raw+r2.raw, f.mem[f.outsider]) {
		t.Fatalf("page 2: %s", r2.raw)
	}
	// PATCH (merge patch): role and scope.
	if r := patch(f.mem[f.viewerA], `{"role":"manager","product_ids":["`+f.prodA+`"]}`, owner); r.code != 200 ||
		r.body["role"] != "manager" || r.body["all_products"] != false {
		t.Errorf("patch: %d %s", r.code, r.raw)
	}
	if r := patch(f.mem[f.viewerA], `{"all_products":true}`, owner); r.code != 200 || r.body["role"] != "manager" || r.body["all_products"] != true {
		t.Errorf("patch scope only: %d %s", r.code, r.raw)
	}
	// Hidden and missing members: the same 404.
	missing := patch(ids.Membership(), `{"role":"viewer"}`, owner).problem(t, 404, "not_found")
	for name, c := range map[string]struct {
		id string
		o  opt
	}{
		"another tenant's": {f.mem[f.outsider], owner},
		"malformed":        {"x", owner},
		"scoped caller":    {f.mem[f.viewerA], f.session(t, f.scoped, true)},
		"viewer, missing":  {ids.Membership(), f.session(t, f.viewerA, true)},
	} {
		if got := patch(c.id, `{"role":"viewer"}`, c.o).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	// Rights before values.
	admin := f.session(t, f.adminA, true)
	patch(f.mem[f.viewerA], `{"role":"owner"}`, admin).problem(t, 403, "forbidden")
	patch(f.mem[f.ownerA], `{"role":"viewer"}`, admin).problem(t, 403, "forbidden")
	patch(f.mem[f.adminA], `{"role":"root"}`, f.session(t, f.viewerA, true)).problem(t, 403, "forbidden")
	adminTok := f.token(t, f.a.ID, f.ownerA, authz.Admin)
	patch(f.mem[f.viewerA], `{"role":"viewer"}`, bearer(adminTok.Token)).problem(t, 403, "forbidden") // tokens can't manage access
	// Values: 422 with the field; null on a non-nullable field is invalid; malformed is 400.
	for body, field := range map[string]string{
		`{"role":"root"}`:      "/role",
		`{"role":null}`:        "/role",
		`{"product_ids":null}`: "/product_ids",
		`{"all_products":null,"product_ids":["` + f.prodA + `"]}`: "/all_products",
		`{"all_products":true,"product_ids":null}`:                "/product_ids",
		`{"all_products":false}`:                                  "/product_ids",
		`{"product_ids":["` + ids.Product() + `"]}`:               "/product_ids",
	} {
		got := patch(f.mem[f.viewerA], body, owner).problem(t, 422, "validation_failed")
		if errs, _ := got["errors"].([]any); len(errs) != 1 || errs[0].(map[string]any)["field"] != field {
			t.Errorf("%s: %v", body, got)
		}
	}
	patch(f.mem[f.viewerA], `{"Role":"viewer"}`, owner).problem(t, 400, "invalid_request")
	patch(f.mem[f.viewerA], `{"role":1}`, owner).problem(t, 400, "invalid_request")
	// The last owner stays.
	patch(f.mem[f.ownerA], `{"role":"admin"}`, owner).problem(t, 409, "last_owner")
	f.do(t, "DELETE", p+"/"+f.mem[f.ownerA], "", owner).problem(t, 409, "last_owner")
	// DELETE revokes the member's tokens by default and ends their access at once.
	createdByAdmin, err := f.tokens.Create(authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: f.adminA,
		TenantID: f.a.ID, Role: authz.Admin, Scope: authz.Scope{All: true}}), "CI", authz.Viewer, authz.Scope{All: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.do(t, "DELETE", p+"/"+f.mem[f.adminA]+"?revoke_tokens=maybe", "", owner).problem(t, 400, "invalid_request")
	if r := f.do(t, "DELETE", p+"/"+f.mem[f.adminA], "", owner); r.code != 204 || r.raw != "" || r.h.Get("X-Revoked-Token-Ids") != createdByAdmin.Row.ID {
		t.Fatalf("delete: %d %s", r.code, r.raw)
	}
	f.do(t, "GET", p, "", admin).problem(t, 404, "not_found")
	f.do(t, "GET", p, "", bearer(createdByAdmin.Token)).problem(t, 401, "unauthenticated")
	f.do(t, "DELETE", p+"/"+f.mem[f.adminA], "", owner).problem(t, 404, "not_found")
	// revoke_tokens=false is accepted (what it keeps: members.TestRemove).
	kept := f.token(t, f.a.ID, f.ownerA, authz.Viewer)
	if r := f.do(t, "DELETE", p+"/"+f.mem[f.viewerA]+"?revoke_tokens=false", "", owner); r.code != 204 {
		t.Fatalf("delete keeping tokens: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "GET", p, "", bearer(kept.Token)); r.code != 200 {
		t.Errorf("unrelated token: %d", r.code)
	}
}

// PATCH caps the member's tokens by default (ADR-0035); revoke_tokens=false keeps them.
func TestMemberPatchCapsTokens(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	mk := func() apitokens.Created {
		c, err := f.tokens.Create(authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: f.adminA,
			TenantID: f.a.ID, Role: authz.Admin, Scope: authz.Scope{All: true}}), "CI", authz.Admin, authz.Scope{All: true}, 0)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	p := membersPath(f.a.Slug) + "/" + f.mem[f.adminA]
	c := mk()
	kept := c.Token
	if r := f.do(t, "PATCH", p+"?revoke_tokens=false", `{"role":"manager"}`, owner); r.code != 200 || fmt.Sprint(r.body["revoked_token_ids"]) != "[]" {
		t.Fatalf("patch keeping tokens: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "GET", tokensPath(f.a.Slug), "", bearer(kept)); r.code != 200 {
		t.Errorf("kept token: %d", r.code)
	}
	if r := f.do(t, "PATCH", p, `{"role":"admin"}`, owner); r.code != 200 {
		t.Fatalf("promote back: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "PATCH", p, `{"role":"manager"}`, owner); r.code != 200 || !reflect.DeepEqual(r.body["revoked_token_ids"], []any{c.Row.ID}) {
		t.Fatalf("patch: %d %s", r.code, r.raw)
	}
	f.do(t, "GET", tokensPath(f.a.Slug), "", bearer(kept)).problem(t, 401, "unauthenticated")
}

func (f *fixture) user(t *testing.T, email string) string {
	t.Helper()
	var uid string
	if err := f.db.WithIdentity(context.Background(), "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail(email).SetEmailVerified(true).Save(context.Background())
		if err == nil {
			uid = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return uid
}

func TestInvitationEndpoints(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	p := Prefix + "/tenants/" + f.a.Slug + "/invitations"
	email := strings.ToLower(ids.New("e")[2:14]) + "@example.com"
	created := f.do(t, "POST", p, `{"email":"`+email+`","role":"support","all_products":false,"product_ids":["`+f.prodA+`"]}`, owner)
	tok, _ := created.body["token"].(string)
	if created.code != 201 || tok == "" || created.body["status"] != "pending" || created.body["invited_by"] != f.ownerA {
		t.Fatalf("create: %d %s", created.code, created.raw)
	}
	second := f.do(t, "POST", p, `{"email":"x`+email+`","role":"viewer","all_products":true}`, owner)
	// Listed newest first, paginated; the token never again.
	r1 := f.do(t, "GET", p+"?limit=1", "", owner)
	items, _ := r1.body["items"].([]any)
	next, _ := r1.body["next_cursor"].(string)
	if r1.code != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != second.body["id"] || next == "" {
		t.Fatalf("page 1: %s", r1.raw)
	}
	r2 := f.do(t, "GET", p+"?limit=1&cursor="+next, "", owner)
	if items, _ := r2.body["items"].([]any); r2.code != 200 || len(items) != 1 || items[0].(map[string]any)["id"] != created.body["id"] {
		t.Fatalf("page 2: %s", r2.raw)
	}
	if strings.Contains(r1.raw+r2.raw, tok) || strings.Contains(r1.raw+r2.raw, second.body["token"].(string)) || strings.Contains(r1.raw+r2.raw, "hash") {
		t.Fatal("list shows a token or hash")
	}
	// Rights before values; values with a field.
	f.do(t, "POST", p, `{"email":"nope","role":"root","all_products":true}`, f.session(t, f.viewerA, true)).problem(t, 403, "forbidden")
	f.do(t, "POST", p, `{"email":"`+email+`","role":"owner","all_products":true}`, f.session(t, f.adminA, true)).problem(t, 403, "forbidden")
	f.do(t, "POST", p, `{"email":"`+email+`","role":"viewer","all_products":true}`, bearer(f.token(t, f.a.ID, f.ownerA, authz.Admin).Token)).problem(t, 403, "forbidden")
	bad := f.do(t, "POST", p, `{"email":"a b@example.com","role":"viewer","all_products":true}`, owner).problem(t, 422, "validation_failed")
	if !strings.Contains(fmt.Sprint(bad["errors"]), "/email") {
		t.Errorf("bad email: %v", bad)
	}
	f.do(t, "POST", p, `{"email":"`+email+`","role":"viewer","all_products":true,"issuer":"x"}`, owner).problem(t, 400, "invalid_request")
	// Revoke: hidden and missing alike; visible but not the caller's to take back: 403.
	sid := second.body["id"].(string)
	missing := f.do(t, "POST", p+"/"+ids.Invitation()+"/revoke", "", owner).problem(t, 404, "not_found")
	bInv := f.do(t, "POST", Prefix+"/tenants/"+f.b.Slug+"/invitations", `{"email":"b`+email+`","role":"viewer","all_products":true}`, f.session(t, f.ownerB, true))
	for name, c := range map[string]struct {
		path string
		o    opt
	}{
		"another tenant's": {p + "/" + bInv.body["id"].(string) + "/revoke", owner},
		"scoped caller":    {p + "/" + sid + "/revoke", f.session(t, f.scoped, true)},
	} {
		if got := f.do(t, "POST", c.path, "", c.o).problem(t, 404, "not_found"); !reflect.DeepEqual(got, missing) {
			t.Errorf("%s: %v, missing %v", name, got, missing)
		}
	}
	f.do(t, "POST", p+"/"+sid+"/revoke", "", f.session(t, f.viewerA, true)).problem(t, 403, "forbidden")
	if r := f.do(t, "POST", p+"/"+sid+"/revoke", "", owner); r.code != 200 || r.body["status"] != "revoked" {
		t.Errorf("revoke: %d %s", r.code, r.raw)
	}
	// Accept: session only, outside the tenant path, CSRF-protected; one
	// answer for every reason it can't be accepted.
	accept := Prefix + "/invitations/accept"
	invitee := f.user(t, email)
	body := `{"token":"` + tok + `"}`
	f.do(t, "POST", accept, body).problem(t, 401, "unauthenticated")
	f.do(t, "POST", accept, body, bearer(f.token(t, f.a.ID, f.ownerA, authz.Admin).Token)).problem(t, 401, "unauthenticated")
	f.do(t, "POST", accept, body, f.session(t, invitee, false)).problem(t, 403, "csrf_failed")
	unknown := f.do(t, "POST", accept, `{"token":"nope"}`, f.session(t, invitee, true)).problem(t, 422, "validation_failed")
	for _, tok := range []string{"", strings.Repeat("a", 65), strings.Repeat("a", 1<<16)} {
		if got := f.do(t, "POST", accept, `{"token":"`+tok+`"}`, f.session(t, invitee, true)).problem(t, 422, "validation_failed"); !reflect.DeepEqual(got, unknown) {
			t.Errorf("token of %d bytes: %v", len(tok), got)
		}
	}
	wrongUser := f.do(t, "POST", accept, body, f.session(t, f.user(t, "y"+email), true)).problem(t, 422, "validation_failed")
	if !reflect.DeepEqual(unknown, wrongUser) {
		t.Errorf("wrong user %v, unknown token %v", wrongUser, unknown)
	}
	f.srv.APIHost = "api.lf.example"
	f.do(t, "POST", accept, body, f.session(t, invitee, true), func(r *http.Request) { r.Host = "api.lf.example" }).problem(t, 401, "unauthenticated")
	f.srv.APIHost = ""
	r := f.do(t, "POST", accept, body, f.session(t, invitee, true))
	if r.code != 200 || r.body["tenant_id"] != f.a.ID || r.body["role"] != "support" || r.body["all_products"] != false {
		t.Fatalf("accept: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "GET", Prefix+"/tenants/"+f.a.ID+"/invitations", "", f.session(t, invitee, false)); r.code != 200 {
		t.Errorf("new member's access: %d %s", r.code, r.raw)
	}
	if got := f.do(t, "POST", accept, body, f.session(t, invitee, true)).problem(t, 422, "validation_failed"); !reflect.DeepEqual(got, unknown) {
		t.Errorf("used twice: %v", got)
	}
	// Other paths outside a tenant stay 404 for sessions.
	f.do(t, "POST", Prefix+"/invitations/nope", body, f.session(t, invitee, true)).problem(t, 404, "not_found")
}

// Member changes report the pending invitations they revoked, and
// revoke_invitations=false keeps them.
func TestMemberChangesRevokeInvitations(t *testing.T) {
	f := setup(t)
	owner := f.session(t, f.ownerA, true)
	admin := f.session(t, f.adminA, true)
	inv := func() string {
		r := f.do(t, "POST", Prefix+"/tenants/"+f.a.Slug+"/invitations", `{"email":"`+strings.ToLower(ids.New("i")[2:14])+`@example.com","role":"viewer","all_products":true}`, admin)
		if r.code != 201 {
			t.Fatalf("invite: %d %s", r.code, r.raw)
		}
		return r.body["id"].(string)
	}
	m := membersPath(f.a.Slug) + "/" + f.mem[f.adminA]
	gone := inv()
	if r := f.do(t, "PATCH", m, `{"product_ids":["`+f.prodA+`"]}`, owner); r.code != 200 || !reflect.DeepEqual(r.body["revoked_invitation_ids"], []any{gone}) {
		t.Fatalf("narrowing: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "PATCH", m, `{"all_products":true}`, owner); r.code != 200 {
		t.Fatalf("widen: %d %s", r.code, r.raw)
	}
	kept := inv()
	if r := f.do(t, "PATCH", m+"?revoke_invitations=false", `{"role":"manager"}`, owner); r.code != 200 || fmt.Sprint(r.body["revoked_invitation_ids"]) != "[]" {
		t.Fatalf("opt-out: %d %s", r.code, r.raw)
	}
	// A later change that doesn't newly exclude it keeps it.
	if r := f.do(t, "PATCH", m, `{"role":"support"}`, owner); r.code != 200 || fmt.Sprint(r.body["revoked_invitation_ids"]) != "[]" {
		t.Fatalf("later demotion: %d %s", r.code, r.raw)
	}
	if r := f.do(t, "DELETE", m, "", owner); r.code != 204 || r.h.Get("X-Revoked-Invitation-Ids") != kept {
		t.Errorf("delete: %d %v", r.code, r.h)
	}
}

// GET /me/tenants: session only, outside a tenant path; the user's own
// memberships with role and scope, and nobody else's.
func TestMyTenants(t *testing.T) {
	f := setup(t)
	path := Prefix + "/me/tenants"
	items := func(r resp) []map[string]any {
		t.Helper()
		if r.code != 200 {
			t.Fatalf("GET %s: %d %s", path, r.code, r.raw)
		}
		raw, ok := r.body["items"].([]any)
		if !ok || len(r.body) != 1 {
			t.Fatalf("body %s: want only an items array", r.raw)
		}
		var out []map[string]any
		for _, it := range raw {
			out = append(out, it.(map[string]any))
		}
		return out
	}
	f.do(t, "GET", path, "").problem(t, 401, "unauthenticated")
	f.do(t, "GET", path, "", bearer(f.token(t, f.a.ID, f.ownerA, authz.Admin).Token)).problem(t, 401, "unauthenticated")
	f.do(t, "GET", path+"?limit=1", "", f.session(t, f.ownerA, false)).problem(t, 400, "invalid_request")
	f.srv.APIHost = "api.lf.example"
	f.do(t, "GET", path, "", f.session(t, f.ownerA, false), func(r *http.Request) { r.Host = "api.lf.example" }).problem(t, 401, "unauthenticated")
	f.srv.APIHost = ""

	want := map[string]any{"tenant_id": f.a.ID, "slug": f.a.Slug, "name": f.a.Name, "role": "owner", "all_products": true, "product_ids": []any{},
		"mfa_policy": "none", "accessible": true}
	if got := items(f.do(t, "GET", path, "", f.session(t, f.ownerA, false))); !reflect.DeepEqual(got, []map[string]any{want}) {
		t.Errorf("owner of a: %v", got)
	}
	scoped := items(f.do(t, "GET", path, "", f.session(t, f.scoped, false)))
	if len(scoped) != 1 || scoped[0]["role"] != "admin" || scoped[0]["all_products"] != false || !reflect.DeepEqual(scoped[0]["product_ids"], []any{f.prodA}) {
		t.Errorf("scoped admin: %v", scoped)
	}
	if got := items(f.do(t, "GET", path, "", f.session(t, f.outsider, false))); len(got) != 1 || got[0]["tenant_id"] != f.b.ID {
		t.Errorf("member of b only: %v", got)
	}
	if got := items(f.do(t, "GET", path, "", f.session(t, f.user(t, "lonely@example.com"), false))); len(got) != 0 {
		t.Errorf("no memberships: %v", got)
	}
	f.do(t, "POST", path, "", f.session(t, f.ownerA, true)).problem(t, 405, "method_not_allowed")
	// The handler itself refuses a principal that isn't a tenant-less user.
	for _, p := range []authz.Principal{{}, {Kind: authz.Token, ID: "tok_1"}, {Kind: authz.User, ID: f.ownerA, TenantID: f.a.ID, Role: authz.Owner}} {
		if _, err := f.srv.ListMyTenants(authz.WithPrincipal(context.Background(), p), apigen.ListMyTenantsRequestObject{}); err != errUnauthenticated {
			t.Errorf("principal %+v: %v", p, err)
		}
	}
}

// GET /me/tenants never lists the reserved platform tenant, orders a scope's
// product IDs, and returns at most identity.MaxMemberships, first by slug.
func TestMyTenantsEdges(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	path := Prefix + "/me/tenants"
	// Two more products of a, joined in reverse ID order.
	var prods []string
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		for _, slug := range []string{"p1", "p2"} {
			p, err := tx.Product.Create().SetTenantID(f.a.ID).SetSlug(slug).SetName(slug).Save(ctx)
			if err != nil {
				return err
			}
			prods = append(prods, p.ID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(prods)
	u := f.join(t, f.a.ID, invitation.RoleViewer, f.ownerA, prods[1], prods[0])
	// Also a member of b and of the platform tenant (direct rows, platform pool).
	email := "edges-" + storetest.Suffix() + "@example.com"
	if err := f.db.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		return tx.User.UpdateOneID(u).SetEmail(email).Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{f.b.ID, audit.PlatformTenant} {
		if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
			inv, err := tx.Invitation.Create().SetTenantID(tenant).SetEmail(email).SetRole(invitation.RoleViewer).SetScopeAll(true).
				SetTokenHash(store.InvitationTokenHash(rand.Text())).SetExpiresAt(time.Now().Add(time.Hour)).
				SetAcceptedAt(time.Now()).SetAcceptedBy(u).Save(ctx)
			if err != nil {
				return err
			}
			return tx.Membership.Create().SetTenantID(tenant).SetUserID(u).SetInvitationID(inv.ID).
				SetRole(membership.RoleViewer).SetScopeAll(true).Exec(ctx)
		}); err != nil {
			t.Fatal(err)
		}
	}
	list := func() []any {
		t.Helper()
		r := f.do(t, "GET", path, "", f.session(t, u, false))
		items, ok := r.body["items"].([]any)
		if r.code != 200 || !ok {
			t.Fatalf("GET %s: %d %s", path, r.code, r.raw)
		}
		return items
	}
	first, second := f.a, f.b
	if second.Slug < first.Slug {
		first, second = second, first
	}
	items := list()
	if len(items) != 2 {
		t.Fatalf("want a and b, not the platform tenant: %v", items)
	}
	for i, want := range []*ent.Tenant{first, second} {
		if got := items[i].(map[string]any); got["tenant_id"] != want.ID {
			t.Errorf("item %d = %v, want %s (sorted by slug)", i, got, want.Slug)
		}
		if items[i].(map[string]any)["tenant_id"] == f.a.ID && fmt.Sprint(items[i].(map[string]any)["product_ids"]) != fmt.Sprint(prods) {
			t.Errorf("product_ids %v, want sorted %v", items[i].(map[string]any)["product_ids"], prods)
		}
	}
	// Scope rows stored in reverse ID order still come back sorted.
	w := f.user(t, "rev-"+storetest.Suffix()+"@example.com")
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		wu, err := tx.User.Get(ctx, w)
		if err != nil {
			return err
		}
		inv, err := tx.Invitation.Create().SetTenantID(f.a.ID).SetEmail(*wu.Email).SetRole(invitation.RoleViewer).SetScopeAll(false).
			SetTokenHash(store.InvitationTokenHash(rand.Text())).SetExpiresAt(time.Now().Add(time.Hour)).
			SetAcceptedAt(time.Now()).SetAcceptedBy(w).Save(ctx)
		if err != nil {
			return err
		}
		m, err := tx.Membership.Create().SetTenantID(f.a.ID).SetUserID(w).SetInvitationID(inv.ID).
			SetRole(membership.RoleViewer).SetScopeAll(false).Save(ctx)
		for _, p := range []string{prods[1], prods[0]} {
			if err == nil {
				err = tx.MembershipProduct.Create().SetTenantID(f.a.ID).SetMembershipID(m.ID).SetProductID(p).Exec(ctx)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if r := f.do(t, "GET", path, "", f.session(t, w, false)); r.code != 200 || fmt.Sprint(r.body["items"].([]any)[0].(map[string]any)["product_ids"]) != fmt.Sprint(prods) {
		t.Errorf("reverse-stored scope: %d %s, want %v", r.code, r.raw, prods)
	}
	defer func(n int) { identity.MaxMemberships = n }(identity.MaxMemberships)
	identity.MaxMemberships = 1
	if items := list(); len(items) != 1 || items[0].(map[string]any)["tenant_id"] != first.ID {
		t.Errorf("capped at 1: %v, want only %s", items, first.Slug)
	}
}
