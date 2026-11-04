package signing

import (
	"context"
	"errors"
	"testing"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/signingkey"
)

// as returns a context acting as an owner of tenantID, the only role with
// key:write (ADR-0019).
func as(tenantID string) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{
		Kind: authz.User, ID: "usr_test", TenantID: tenantID, Role: authz.Owner, Scope: authz.Scope{All: true}})
}

// statuses lists the tenant's keys as "status:id", for before/after checks.
func statuses(t *testing.T, l Local, tenantID string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := l.DB.WithTenant(context.Background(), tenantID, func(tx *ent.Tx) error {
		ks, err := tx.SigningKey.Query().All(context.Background())
		for _, k := range ks {
			out[k.ID] = string(k.Status)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Create, Promote and Discard need key:write on the whole tenant, in the
// tenant they act on: owners (users or tokens) only. Refusals change nothing.
func TestKeyOperationsNeedKeyWrite(t *testing.T) {
	l, _, _ := setup(t)
	other := newTenant(t, l)
	all := authz.Scope{All: true}
	principal := func(kind authz.PrincipalKind, role authz.Role, scope authz.Scope, tenant string) func(string) context.Context {
		return func(tn string) context.Context {
			if tenant != "" {
				tn = tenant
			}
			return authz.WithPrincipal(context.Background(), authz.Principal{Kind: kind, ID: "x_test", TenantID: tn, Role: role, Scope: scope})
		}
	}
	for name, c := range map[string]struct {
		ctx     func(tenantID string) context.Context
		allowed bool
	}{
		"owner":                 {principal(authz.User, authz.Owner, all, ""), true},
		"owner API token":       {principal(authz.Token, authz.Owner, all, ""), true},
		"admin":                 {principal(authz.User, authz.Admin, all, ""), false},
		"manager":               {principal(authz.User, authz.Manager, all, ""), false},
		"support":               {principal(authz.User, authz.Support, all, ""), false},
		"viewer":                {principal(authz.User, authz.Viewer, all, ""), false},
		"admin API token":       {principal(authz.Token, authz.Admin, all, ""), false},
		"sdk token":             {principal(authz.Token, authz.SDK, all, ""), false},
		"product-scoped owner":  {principal(authz.User, authz.Owner, authz.Scope{Products: []string{"prd_aaaaaaaaaaaaaaaaaaaaaaaaaa"}}, ""), false},
		"owner of other tenant": {principal(authz.User, authz.Owner, all, other), false},
		"no principal":          {func(string) context.Context { return context.Background() }, false},
	} {
		t.Run(name, func(t *testing.T) {
			check := func(op string, err error, tn string, before map[string]string) {
				t.Helper()
				switch {
				case c.allowed && err != nil:
					t.Errorf("%s: %v", op, err)
				case !c.allowed && !errors.Is(err, authz.ErrDenied):
					t.Errorf("%s: %v, want authz.ErrDenied", op, err)
				case !c.allowed && len(statuses(t, l, tn)) != len(before):
					t.Errorf("%s: refused but keys changed", op)
				}
				if !c.allowed {
					for id, s := range statuses(t, l, tn) {
						if before[id] != s {
							t.Errorf("%s: refused but %s became %s", op, id, s)
						}
					}
				}
			}
			tn := newTenant(t, l)
			if _, err := l.Create(as(tn), tn); err != nil { // the active key
				t.Fatal(err)
			}

			before := statuses(t, l, tn)
			_, err := l.Create(c.ctx(tn), tn)
			check("Create", err, tn, before)

			pending := func() string {
				for id, s := range statuses(t, l, tn) {
					if s == string(signingkey.StatusPending) {
						return id
					}
				}
				k, err := l.Create(as(tn), tn)
				if err != nil {
					t.Fatal(err)
				}
				return k.ID
			}
			kid := pending()
			before = statuses(t, l, tn)
			check("Discard", l.Discard(c.ctx(tn), tn, kid), tn, before)

			kid = pending()
			before = statuses(t, l, tn)
			check("Promote", l.Promote(c.ctx(tn), tn, kid), tn, before)
		})
	}
}
