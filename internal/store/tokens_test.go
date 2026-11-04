package store

import (
	"context"
	"strings"
	"testing"
	"time"

	tokens "licenseforge.io/licenseforge/internal/apitoken"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/apitoken"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
)

type tokenOpts struct {
	creator  string // "" = none
	tenant   string
	tok      string
	products []string
	expires  time.Duration
}

// createToken creates an API token as the tenant pool would.
func (f identityFixture) createToken(o tokenOpts) (*ent.APIToken, error) {
	ctx := context.Background()
	if o.tok == "" {
		o.tok = tokens.New()
	}
	if o.expires == 0 {
		o.expires = 90 * 24 * time.Hour
	}
	var t *ent.APIToken
	err := f.d.WithTenant(ctx, o.tenant, func(tx *ent.Tx) error {
		c := tx.APIToken.Create().SetTenantID(o.tenant).SetName("CI").SetRole(apitoken.RoleSdk).SetScopeAll(o.products == nil).
			SetTokenHash(tokens.Hash(o.tok)).SetDisplay(tokens.Display(o.tok)).SetExpiresAt(time.Now().Add(o.expires))
		if o.creator != "" {
			c.SetCreatedBy(o.creator)
		}
		var err error
		if t, err = c.Save(ctx); err != nil {
			return err
		}
		for _, p := range o.products {
			if _, err := tx.APITokenProduct.Create().SetTenantID(o.tenant).SetAPITokenID(t.ID).SetProductID(p).Save(ctx); err != nil {
				return err
			}
		}
		return nil
	})
	return t, err
}

func TestAPITokenCreation(t *testing.T) {
	f := newIdentityFixture(t)
	tok := tokens.New()
	if _, err := f.createToken(tokenOpts{creator: f.ownerA, tenant: f.a, tok: tok}); err != nil {
		t.Fatal(err)
	}
	// The same token hash in another tenant is fine (unique per tenant):
	// an insert conflict can't reveal another tenant's token.
	if _, err := f.createToken(tokenOpts{creator: f.ownerB, tenant: f.b, tok: tok}); err != nil {
		t.Errorf("same hash in another tenant: %v", err)
	}
	for name, o := range map[string]tokenOpts{
		"expiry over a year":        {creator: f.ownerA, tenant: f.a, expires: 366 * 24 * time.Hour},
		"already expired":           {creator: f.ownerA, tenant: f.a, expires: -time.Hour},
		"creator of another tenant": {creator: f.ownerB, tenant: f.a},
		"no creator":                {tenant: f.a},
	} {
		if _, err := f.createToken(o); err == nil {
			t.Errorf("%s: created", name)
		}
	}
}

func TestAPITokenTenantPoolRights(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	tk, err := f.createToken(tokenOpts{creator: f.ownerA, tenant: f.a})
	if err != nil {
		t.Fatal(err)
	}
	exec := func(tenant, q string, args ...any) error {
		return f.d.WithTenant(ctx, tenant, func(tx *ent.Tx) error { _, err := tx.ExecContext(ctx, q, args...); return err })
	}
	for name, q := range map[string]string{
		"insert revoked": `INSERT INTO api_tokens (id, tenant_id, name, role, scope_all, token_hash, display, created_by, expires_at, created_at, updated_at, revoked_at)
			VALUES ('tok_aaaaaaaaaaaaaaaaaaaaaaaaaa', $1, 'x', 'owner', true, $2, 'lf_live_aaaaaaaa…', $3, now() + interval '1 day', now(), now(), now())`,
		"change role": `UPDATE api_tokens SET role = 'owner' WHERE tenant_id = $1 AND token_hash <> $2 AND created_by = $3`,
		"delete":      `DELETE FROM api_tokens WHERE tenant_id = $1 AND token_hash <> $2 AND created_by = $3`,
	} {
		if err := exec(f.a, q, f.a, tokens.Hash(tokens.New()), f.ownerA); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: %v, want permission denied", name, err)
		}
	}
	// Another tenant doesn't see the token.
	var n int
	if err := f.d.WithTenant(ctx, f.b, func(tx *ent.Tx) error {
		var err error
		n, err = tx.APIToken.Query().Where(apitoken.ID(tk.ID)).Count(ctx)
		return err
	}); err != nil || n != 0 {
		t.Errorf("tenant B sees A's token: %d %v", n, err)
	}
	// Revocation is one-way, and a revoked token records no use.
	if err := exec(f.a, `UPDATE api_tokens SET revoked_at = now() WHERE id = $1`, tk.ID); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`UPDATE api_tokens SET revoked_at = NULL WHERE id = $1`, `UPDATE api_tokens SET last_used_at = now() WHERE id = $1`} {
		if err := exec(f.a, q, tk.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		var err error
		n, err = tx.APIToken.Query().Where(apitoken.ID(tk.ID), apitoken.RevokedAtNotNil(), apitoken.LastUsedAtIsNil()).Count(ctx)
		return err
	}); err != nil || n != 1 {
		t.Errorf("a revoked token was changed: %d %v", n, err)
	}
}

func TestAPITokenScope(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	if _, err := f.createToken(tokenOpts{creator: f.ownerA, tenant: f.a, products: []string{f.prodA}}); err != nil {
		t.Fatalf("scoped token: %v", err)
	}
	if _, err := f.createToken(tokenOpts{creator: f.ownerA, tenant: f.a, products: []string{f.prodB}}); err == nil {
		t.Error("another tenant's product in a token's scope")
	}
	all, err := f.createToken(tokenOpts{creator: f.ownerA, tenant: f.a})
	if err != nil {
		t.Fatal(err)
	}
	add := func(tokID, product string) error {
		return f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
			_, err := tx.APITokenProduct.Create().SetTenantID(f.a).SetAPITokenID(tokID).SetProductID(product).Save(ctx)
			return err
		})
	}
	if err := add(all.ID, f.prodA); err == nil {
		t.Error("product on an all-products token")
	}
	used, err := f.createToken(tokenOpts{creator: f.ownerA, tenant: f.a, products: []string{f.prodA}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		return tx.APIToken.UpdateOneID(used.ID).SetLastUsedAt(time.Now()).Exec(ctx)
	}); err != nil {
		t.Fatal(err)
	}
	if err := add(used.ID, f.prodA2); err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("scope widened after use: %v", err)
	}
}

// Tokens belong to the tenant: erasing their creator keeps them (ADR-0029).
func TestAPITokenOutlivesCreator(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	inv := f.invite(t, f.a, f.ownerA, inviteOpts{email: "dev@example.com", role: invitation.RoleAdmin})
	dev := f.newUser(t, "dev@example.com", true)
	if _, err := f.d.AcceptInvitation(ctx, f.tokens[inv.ID], dev, noRecord); err != nil {
		t.Fatal(err)
	}
	tk, err := f.createToken(tokenOpts{creator: dev, tenant: f.a})
	if err != nil {
		t.Fatal(err)
	}
	// The erase command's order (owner login): memberships, accepted
	// invitations, then the user.
	f.owner(t, `DELETE FROM memberships WHERE user_id = $1`, dev)
	f.owner(t, `DELETE FROM invitations WHERE accepted_by = $1`, dev)
	f.owner(t, `DELETE FROM users WHERE id = $1`, dev)
	var got *ent.APIToken
	if err := f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		var err error
		got, err = tx.APIToken.Get(ctx, tk.ID)
		return err
	}); err != nil || got.CreatedBy != nil {
		t.Errorf("token after erasing its creator: %+v %v", got, err)
	}
}

// The identity login has no access to tokens.
func TestIdentityCantReadTokens(t *testing.T) {
	f := newIdentityFixture(t)
	err := f.d.WithIdentity(context.Background(), f.a, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(context.Background(), `SELECT 1 FROM api_tokens LIMIT 1`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("identity read api_tokens: %v", err)
	}
}
