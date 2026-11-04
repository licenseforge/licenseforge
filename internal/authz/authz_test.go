package authz

import (
	"context"
	"errors"
	"testing"
)

// The matrix is written out in full, independent of how roles are built, so a
// permission added to or dropped from a role shows up here (ADR-0019).
// Columns: owner admin manager support viewer sdk.
var matrix = map[Permission]string{
	TenantRead:        "xxxxx.",
	TenantWrite:       "x.....",
	TenantDelete:      "x.....",
	BillingWrite:      "x.....",
	KeyRead:           "xxxxx.",
	KeyWrite:          "x.....",
	CatalogRead:       "xxxxx.",
	CatalogWrite:      "xx....",
	MemberRead:        "xxxxx.",
	MemberWrite:       "xx....",
	TokenRead:         "xxxxx.",
	TokenWrite:        "xx....",
	WebhookRead:       "xxxxx.",
	WebhookWrite:      "xx....",
	AuditRead:         "xx....",
	CustomerRead:      "xxxxx.",
	CustomerWrite:     "xxx...",
	LicenseRead:       "xxxxx.",
	LicenseIssue:      "xxx...",
	LicenseWrite:      "xxx...",
	ActivationRead:    "xxxxx.",
	ActivationManage:  "xxxx..",
	ActivationOffline: "xxx...",
	ActivationClient:  ".....x",
}

var roles = []Role{Owner, Admin, Manager, Support, Viewer, SDK}

func TestMatrix(t *testing.T) {
	for perm, row := range matrix {
		for i, r := range roles {
			if want := row[i] == 'x'; r.Can(perm) != want {
				t.Errorf("%s.Can(%s) = %v, want %v", r, perm, !want, want)
			}
		}
	}
	// Every permission a role grants is in the matrix.
	for r, perms := range permissions {
		for _, p := range perms {
			if _, ok := matrix[p]; !ok {
				t.Errorf("%s grants %s, missing from the matrix", r, p)
			}
		}
	}
	if Role("root").Valid() || Role("root").Can(TenantRead) || Role("").Can(TenantRead) {
		t.Error("unknown role accepted")
	}
	if SDK.ForMembership() || !Viewer.ForMembership() || Role("").ForMembership() || Role("root").ForMembership() {
		t.Error("ForMembership")
	}
	if len(permissions) != len(roles) {
		t.Error("a role is missing from the test")
	}
}

var all = Scope{All: true}

func ctxWith(p Principal) context.Context { return WithPrincipal(context.Background(), p) }

func TestRequire(t *testing.T) {
	base := Principal{Kind: User, ID: "usr_1", TenantID: "ten_1", Role: Manager, Scope: all}
	with := func(f func(*Principal)) *Principal { p := base; f(&p); return &p }
	scoped := with(func(p *Principal) { p.Scope = Scope{Products: []string{"prd_a"}} })
	for _, c := range []struct {
		name    string
		p       *Principal
		perm    Permission
		product string
		ok      bool
	}{
		{"granted", &base, LicenseIssue, "prd_a", true},
		{"granted tenant-wide", &base, CustomerWrite, "", true},
		{"not granted", &base, CatalogWrite, "prd_a", false},
		{"no principal", nil, TenantRead, "", false},
		{"no tenant", with(func(p *Principal) { p.TenantID = "" }), TenantRead, "", false},
		{"no ID", with(func(p *Principal) { p.ID = "" }), TenantRead, "", false},
		{"no kind", with(func(p *Principal) { p.Kind = "" }), TenantRead, "", false},
		{"unknown kind", with(func(p *Principal) { p.Kind = "platform" }), TenantRead, "", false},
		{"zero scope", with(func(p *Principal) { p.Scope = Scope{} }), LicenseIssue, "prd_a", false},
		{"empty non-nil scope", with(func(p *Principal) { p.Scope = Scope{Products: []string{}} }), LicenseIssue, "prd_a", false},
		{"scope: own product", scoped, LicenseIssue, "prd_a", true},
		{"scope: other product", scoped, LicenseIssue, "prd_b", false},
		{"scope: tenant-wide", scoped, CustomerRead, "", false},
		{"scope: empty product ID", with(func(p *Principal) { p.Scope = Scope{Products: []string{""}} }), CustomerRead, "", false},
		{"scoped token", with(func(p *Principal) { p.Kind = Token; p.Scope = Scope{Products: []string{"prd_a"}} }), LicenseIssue, "prd_a", true},
		{"sdk token", with(func(p *Principal) { p.Kind = Token; p.Role = SDK }), ActivationClient, "prd_a", true},
		{"sdk role on a user", with(func(p *Principal) { p.Role = SDK }), ActivationClient, "prd_a", false},
	} {
		ctx := context.Background()
		if c.p != nil {
			ctx = ctxWith(*c.p)
		}
		err := Require(ctx, c.perm, c.product)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrDenied)) {
			t.Errorf("%s: Require = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestWithPrincipalCopiesScope(t *testing.T) {
	ids := []string{"prd_a"}
	ctx := ctxWith(Principal{Kind: User, ID: "usr_1", TenantID: "ten_1", Role: Viewer, Scope: Scope{Products: ids}})
	ids[0] = "prd_b"
	if Require(ctx, LicenseRead, "prd_b") == nil {
		t.Error("scope changed after WithPrincipal")
	}
}

func TestProductsAndTenantID(t *testing.T) {
	p := Principal{Kind: User, ID: "usr_1", TenantID: "ten_1", Role: Viewer, Scope: Scope{Products: []string{"prd_a"}}}
	if all, ids, err := Products(ctxWith(p), LicenseRead); err != nil || all || len(ids) != 1 || ids[0] != "prd_a" {
		t.Errorf("scoped: %v %v %v", all, ids, err)
	}
	p.Scope = all
	if all, ids, err := Products(ctxWith(p), LicenseRead); err != nil || !all || ids != nil {
		t.Errorf("all: %v %v %v", all, ids, err)
	}
	if _, _, err := Products(ctxWith(p), LicenseIssue); err == nil {
		t.Error("Products without the permission")
	}
	if _, _, err := Products(ctxWith(Principal{Kind: User, ID: "usr_1", TenantID: "ten_1", Role: Viewer}), LicenseRead); err != nil {
		t.Error(err) // zero scope: no error, filter by no products
	}
	if id, err := TenantID(ctxWith(p)); err != nil || id != "ten_1" {
		t.Errorf("TenantID = %q, %v", id, err)
	}
	if _, err := TenantID(context.Background()); err == nil {
		t.Error("TenantID without principal")
	}
	p.TenantID = ""
	if _, err := TenantID(ctxWith(p)); err == nil {
		t.Error("TenantID with empty tenant")
	}
}

func TestCanAssign(t *testing.T) {
	g := func(r Role) *Grant { return &Grant{Role: r, Scope: all} }
	who := func(r Role, s Scope) context.Context {
		return ctxWith(Principal{Kind: User, ID: "usr_1", TenantID: "ten_1", Role: r, Scope: s})
	}
	owner, admin := who(Owner, all), who(Admin, all)
	for _, c := range []struct {
		name     string
		ctx      context.Context
		kind     PrincipalKind
		from, to *Grant
		ok       bool
	}{
		{"admin invites manager", admin, User, nil, g(Manager), true},
		{"admin invites admin", admin, User, nil, g(Admin), true},
		{"admin invites owner", admin, User, nil, g(Owner), false},
		{"admin demotes owner", admin, User, g(Owner), g(Viewer), false},
		{"admin removes owner", admin, User, g(Owner), nil, false},
		{"admin removes viewer", admin, User, g(Viewer), nil, true},
		{"owner promotes to owner", owner, User, g(Admin), g(Owner), true},
		{"owner demotes owner", owner, User, g(Owner), g(Admin), true},
		{"manager invites viewer", who(Manager, all), User, nil, g(Viewer), false},
		{"scoped admin invites", who(Admin, Scope{Products: []string{"prd_a"}}), User, nil, &Grant{Role: Viewer, Scope: Scope{Products: []string{"prd_a"}}}, false},
		{"sdk member", owner, User, nil, g(SDK), false},
		{"sdk token", admin, Token, nil, g(SDK), true},
		{"owner token by admin", admin, Token, nil, g(Owner), false},
		{"unknown role", owner, User, nil, g("root"), false},
		{"unknown token role", owner, Token, nil, g("root"), false},
		{"zero scope", owner, User, nil, &Grant{Role: Viewer}, false},
		{"all and products", owner, User, nil, &Grant{Role: Viewer, Scope: Scope{All: true, Products: []string{"prd_a"}}}, false},
		{"empty product ID", owner, User, nil, &Grant{Role: Viewer, Scope: Scope{Products: []string{""}}}, false},
		{"product scope", owner, User, nil, &Grant{Role: Support, Scope: Scope{Products: []string{"prd_a"}}}, true},
		{"nothing to do", owner, User, nil, nil, false},
		{"unknown kind", owner, "platform", nil, g(Viewer), false},
		{"no principal", context.Background(), User, nil, g(Viewer), false},
	} {
		err := CanAssign(c.ctx, c.kind, c.from, c.to)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrDenied)) {
			t.Errorf("%s: CanAssign = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
