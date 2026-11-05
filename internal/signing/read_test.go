package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/signingkey"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// List and Get need key:read on the whole tenant, in the tenant they read:
// every member role and token but sdk; product-scoped principals, another
// tenant's principal and calls without a principal are refused.
func TestReadsNeedKeyRead(t *testing.T) {
	l, _, _ := setup(t)
	tn, other := newTenant(t, l), newTenant(t, l)
	k, err := l.Create(as(tn), tn)
	if err != nil {
		t.Fatal(err)
	}
	all := authz.Scope{All: true}
	ctx := func(kind authz.PrincipalKind, role authz.Role, scope authz.Scope, tenant string) context.Context {
		return authz.WithPrincipal(context.Background(), authz.Principal{Kind: kind, ID: "x_test", TenantID: tenant, Role: role, Scope: scope})
	}
	for name, c := range map[string]struct {
		ctx     context.Context
		allowed bool
	}{
		"owner":                 {ctx(authz.User, authz.Owner, all, tn), true},
		"viewer":                {ctx(authz.User, authz.Viewer, all, tn), true},
		"support API token":     {ctx(authz.Token, authz.Support, all, tn), true},
		"sdk token":             {ctx(authz.Token, authz.SDK, all, tn), false},
		"product-scoped admin":  {ctx(authz.User, authz.Admin, authz.Scope{Products: []string{"prd_aaaaaaaaaaaaaaaaaaaaaaaaaa"}}, tn), false},
		"owner of other tenant": {ctx(authz.User, authz.Owner, all, other), false},
		"no principal":          {context.Background(), false},
	} {
		t.Run(name, func(t *testing.T) {
			ks, lerr := l.List(c.ctx, tn, 10, time.Time{}, "")
			got, gerr := l.Get(c.ctx, tn, k.ID)
			if c.allowed {
				if lerr != nil || len(ks) != 1 || ks[0].ID != k.ID || gerr != nil || got.ID != k.ID {
					t.Errorf("List %v %v, Get %v %v", ks, lerr, got, gerr)
				}
				return
			}
			if !errors.Is(lerr, authz.ErrDenied) || ks != nil || !errors.Is(gerr, authz.ErrDenied) || got != nil {
				t.Errorf("List %v %v, Get %v %v: want authz.ErrDenied", ks, lerr, got, gerr)
			}
		})
	}
}

// Get: missing, malformed and another tenant's keys are ErrNotFound alike.
// List: newest first, paged by (created_at, kid), only this tenant's keys.
func TestListAndGet(t *testing.T) {
	l, _, _ := setup(t)
	tn, other := newTenant(t, l), newTenant(t, l)
	first, err := l.Create(as(tn), tn)
	if err != nil {
		t.Fatal(err)
	}
	second, err := l.Create(as(tn), tn)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := l.Create(as(other), other)
	if err != nil {
		t.Fatal(err)
	}
	for _, kid := range []string{"sk_aaaaaaaaaaaaaaaaaaaaaaaaaa", "nope", theirs.ID} {
		if k, err := l.Get(as(tn), tn, kid); !errors.Is(err, ErrNotFound) || k != nil {
			t.Errorf("Get(%s) = %v, %v", kid, k, err)
		}
	}
	page, err := l.List(as(tn), tn, 1, time.Time{}, "")
	if err != nil || len(page) != 1 || page[0].ID != second.ID {
		t.Fatalf("page 1: %v %v", page, err)
	}
	page, err = l.List(as(tn), tn, 5, page[0].CreatedAt, page[0].ID)
	if err != nil || len(page) != 1 || page[0].ID != first.ID {
		t.Errorf("page 2: %v %v", page, err)
	}
}

// PromoteKey and DiscardKey return the key as committed.
func TestPromoteAndDiscardReturnTheKey(t *testing.T) {
	l, _, _ := setup(t)
	tn := newTenant(t, l)
	if _, err := l.Create(as(tn), tn); err != nil {
		t.Fatal(err)
	}
	next, err := l.Create(as(tn), tn)
	if err != nil {
		t.Fatal(err)
	}
	k, err := l.PromoteKey(as(tn), tn, next.ID)
	if err != nil || k.ID != next.ID || k.Status != "active" || k.ActivatedAt == nil {
		t.Fatalf("PromoteKey = %+v, %v", k, err)
	}
	third, err := l.Create(as(tn), tn)
	if err != nil {
		t.Fatal(err)
	}
	k, err = l.DiscardKey(as(tn), tn, third.ID)
	if err != nil || k.ID != third.ID || k.Status != "retired" || k.RetiredAt == nil || k.PrivateKeyCiphertext != nil {
		t.Errorf("DiscardKey = %+v, %v", k, err)
	}
}

// Keys created at the same instant page by kid: none is skipped.
func TestListTieBreak(t *testing.T) {
	l, _, _ := setup(t)
	tn := newTenant(t, l)
	at := time.Now().UTC().Truncate(time.Microsecond)
	if err := l.DB.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
		for range 2 {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			if _, err := tx.SigningKey.Create().SetID(ids.SigningKey()).SetTenantID(tn).SetAlg(signingkey.AlgEd25519).SetPublicKey(pub).
				SetStatus(signingkey.StatusRetired).SetRetiredAt(at).SetCreatedAt(at).SetUpdatedAt(at).Save(context.Background()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	first, err := l.List(as(tn), tn, 1, time.Time{}, "")
	if err != nil || len(first) != 1 {
		t.Fatalf("page 1: %v %v", first, err)
	}
	second, err := l.List(as(tn), tn, 5, first[0].CreatedAt, first[0].ID)
	if err != nil || len(second) != 1 || second[0].ID == first[0].ID {
		t.Errorf("page 2: %v %v", second, err)
	}
}
