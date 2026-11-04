package store

import (
	"context"
	"slices"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
)

// RecheckPrincipal re-reads a user principal's membership in tx (a WithTenant
// transaction of p's tenant) FOR SHARE and returns authz.ErrDenied unless it
// still exists with p's role and product scope. A request's principal was
// resolved before its transaction began; a service that grants or changes
// access calls this first, so a concurrent removal or demotion either waits
// for it or makes it fail. Token principals have no membership: nil.
func RecheckPrincipal(ctx context.Context, tx *ent.Tx, p authz.Principal) error {
	if p.Kind != authz.User {
		return nil
	}
	m, err := tx.Membership.Query().Where(membership.UserID(p.ID)).WithProducts().ForShare().Only(ctx)
	if ent.IsNotFound(err) {
		return authz.ErrDenied
	}
	if err != nil {
		return err
	}
	var products []string
	for _, mp := range m.Edges.Products {
		products = append(products, mp.ProductID)
	}
	want := slices.Clone(p.Scope.Products)
	slices.Sort(products)
	slices.Sort(want)
	if authz.Role(m.Role) != p.Role || m.ScopeAll != p.Scope.All || !slices.Equal(products, want) {
		return authz.ErrDenied
	}
	return nil
}
