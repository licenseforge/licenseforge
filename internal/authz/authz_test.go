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
	TenantWrite:       "xx....",
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
	if SDK.ForMembership() || !Viewer.ForMembership() {
		t.Error("ForMembership")
	}
}

func TestCanGrant(t *testing.T) {
	// Rows: granter; columns: owner admin manager support viewer sdk.
	want := map[Role]string{
		Owner:   "xxxxxx",
		Admin:   ".xxxxx",
		Manager: "......",
		Support: "......",
		Viewer:  "......",
		SDK:     "......",
	}
	for g, row := range want {
		for i, r := range roles {
			if got := g.CanGrant(r); got != (row[i] == 'x') {
				t.Errorf("%s.CanGrant(%s) = %v", g, r, got)
			}
		}
	}
	if Owner.CanGrant("root") {
		t.Error("unknown role grantable")
	}
}

func TestRequire(t *testing.T) {
	base := Principal{Kind: User, ID: "usr_1", TenantID: "ten_1", Role: Manager}
	scoped := base
	scoped.Products = []string{"prd_a"}
	sdkUser := base
	sdkUser.Role = SDK
	sdkToken := sdkUser
	sdkToken.Kind = Token
	emptyScope := base
	emptyScope.Products = []string{""} // a bad scope row must not widen access
	noTenant := base
	noTenant.TenantID = ""
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
		{"no tenant", &noTenant, TenantRead, "", false},
		{"scope: own product", &scoped, LicenseIssue, "prd_a", true},
		{"scope: other product", &scoped, LicenseIssue, "prd_b", false},
		{"scope: tenant-wide", &scoped, CustomerRead, "", false},
		{"scope: empty product ID", &emptyScope, CustomerRead, "", false},
		{"sdk token", &sdkToken, ActivationClient, "prd_a", true},
		{"sdk role on a user", &sdkUser, ActivationClient, "prd_a", false},
	} {
		ctx := context.Background()
		if c.p != nil {
			ctx = WithPrincipal(ctx, *c.p)
		}
		err := Require(ctx, c.perm, c.product)
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, ErrDenied)) {
			t.Errorf("%s: Require = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
