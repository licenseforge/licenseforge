// Package members lists, changes and removes a tenant's members (ADR-0019,
// ADR-0029). Members are created only by accepting an invitation
// (store.AcceptInvitation). Every change and refusal is audited (ADR-0027),
// a change in the same transaction.
package members

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	entapitoken "licenseforge.io/licenseforge/internal/store/ent/apitoken"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/membershipproduct"
	"licenseforge.io/licenseforge/internal/store/ent/user"
	"licenseforge.io/licenseforge/internal/store/ids"
)

var (
	// ErrNotFound means no such member in the tenant, or one the caller
	// can't see (the same answer, ADR-0032).
	ErrNotFound = errors.New("members: no such member")
	// ErrLastOwner means the change would leave the tenant without an owner.
	ErrLastOwner = errors.New("members: the tenant's last owner")
	// ErrInvalid is wrapped by InvalidError.
	ErrInvalid = errors.New("members: invalid request")
)

// InvalidError names the invalid field (a JSON Pointer into the request).
type InvalidError struct{ Field, Message string }

func (e *InvalidError) Error() string { return fmt.Sprintf("members: %s: %s", e.Field, e.Message) }
func (e *InvalidError) Unwrap() error { return ErrInvalid }

// Service works on the tenant pool.
type Service struct{ DB *store.DB }

// List returns up to limit of ctx's tenant's members with their user (id,
// email, name) and products, newest first, after (afterAt, afterID) or from
// the start if afterID is "". Members are tenant-wide: a product-scoped
// caller sees none.
func (s Service) List(ctx context.Context, limit int, afterAt time.Time, afterID string) ([]*ent.Membership, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, _, err := authz.Products(ctx, authz.MemberRead)
	if err != nil || !all {
		return nil, err
	}
	var ms []*ent.Membership
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := withEdges(tx.Membership.Query()).Order(ent.Desc(membership.FieldCreatedAt), ent.Desc(membership.FieldID)).Limit(limit)
		if afterID != "" {
			q.Where(membership.Or(membership.CreatedAtLT(afterAt), membership.And(membership.CreatedAt(afterAt), membership.IDLT(afterID))))
		}
		ms, err = q.All(ctx)
		return err
	})
	return ms, err
}

// withEdges loads the user (only the columns the tenant pool may read) and
// the products.
func withEdges(q *ent.MembershipQuery) *ent.MembershipQuery {
	return q.WithProducts().WithUser(func(q *ent.UserQuery) { q.Select(user.FieldID, user.FieldEmail, user.FieldName) })
}

// Change is a merge-patch of a membership: nil fields stay. Null lists the
// fields the patch set to null (none is nullable: refused as invalid, after
// the rights checks).
type Change struct {
	Role  *authz.Role
	Scope *authz.Scope
	Null  []string
}

// Update changes a member's role or product scope. Order (ADR-0032): the
// member must be visible (else ErrNotFound), the caller must be allowed to
// change it at all (authz.ErrDenied), then the values must be valid
// (InvalidError), within the caller's role, and leave an owner.
//
// With opts (both true by default, ADR-0035) it also revokes, in the same
// transaction and with removal's rules, what this change newly excludes:
// the member's active tokens the new grant doesn't allow (a role above the
// new one, or products outside the new scope), and their pending
// invitations the new grant couldn't have made. Something an earlier change
// kept stays. It returns the member and what it revoked.
func (s Service) Update(ctx context.Context, memberID string, c Change, opts Revoke) (*ent.Membership, Revoked, error) {
	var out *ent.Membership
	var revoked Revoked
	err := s.change(ctx, "member.update", memberID, func(tx *ent.Tx, m *ent.Membership, from authz.Grant, owners int) (map[string]any, error) {
		if len(c.Null) > 0 {
			return nil, &InvalidError{"/" + c.Null[0], "can't be null"}
		}
		to := from
		if c.Role != nil {
			to.Role = *c.Role
		}
		if c.Scope != nil {
			to.Scope = *c.Scope
		}
		if err := valid(to); err != nil {
			return nil, err
		}
		if err := authz.CanAssign(ctx, authz.User, &from, &to); err != nil {
			return nil, err
		}
		if from.Role == authz.Owner && to.Role != authz.Owner && owners == 1 {
			return nil, ErrLastOwner
		}
		var err error
		if revoked.Tokens, _, err = revokeTokens(ctx, tx, m, "member.update", opts.Tokens, func(g authz.Grant) bool { return !exceeds(g, to) || exceeds(g, from) }); err != nil {
			return nil, err
		}
		if revoked.Invitations, _, err = revokeInvitations(ctx, tx, m, "member.update", opts.Invitations, func(g authz.Grant) bool { return canInvite(to, g) || !canInvite(from, g) }); err != nil {
			return nil, err
		}
		// Product rows first: they reference (membership, scope_all = false).
		if c.Scope != nil {
			if _, err := tx.MembershipProduct.Delete().Where(membershipproduct.MembershipID(m.ID)).Exec(ctx); err != nil {
				return nil, err
			}
		}
		if err := tx.Membership.UpdateOne(m).SetRole(membership.Role(to.Role)).SetScopeAll(to.Scope.All).Exec(ctx); err != nil {
			return nil, err
		}
		if c.Scope != nil {
			for _, p := range to.Scope.Products {
				if err := tx.MembershipProduct.Create().SetTenantID(m.TenantID).SetMembershipID(m.ID).SetProductID(p).Exec(ctx); err != nil {
					return nil, productRefusal(err)
				}
			}
		}
		out, err = withEdges(tx.Membership.Query()).Where(membership.ID(m.ID)).Only(ctx)
		return map[string]any{"from_role": string(from.Role), "from_scope_all": from.Scope.All, "from_products": len(from.Scope.Products),
			"role": string(to.Role), "scope_all": to.Scope.All, "products": len(to.Scope.Products),
			"tokens_revoked": len(revoked.Tokens), "invitations_revoked": len(revoked.Invitations)}, err
	})
	if err != nil {
		return nil, Revoked{}, err
	}
	return out, revoked, nil
}

// Revoke says what a member change revokes along with it (ADR-0035): the
// member's API tokens and their pending invitations. Both default to true.
type Revoke struct{ Tokens, Invitations bool }

// Revoked lists what a member change revoked.
type Revoked struct{ Tokens, Invitations []string }

// exceeds reports whether a token's grant g goes beyond grant to: a role with
// a permission to lacks (never sdk, which is always assignable, as in
// authz.CanAssign), or a product outside to's scope.
func exceeds(g, to authz.Grant) bool {
	if g.Role != authz.SDK && !g.Role.Within(to.Role) {
		return true
	}
	if to.Scope.All {
		return false
	}
	return g.Scope.All || slices.ContainsFunc(g.Scope.Products, func(p string) bool { return !slices.Contains(to.Scope.Products, p) })
}

// canInvite reports whether a member with grant inviter could have made an
// invitation with grant g (authz.CanAssign's rules for a user principal:
// member:write on every product, and a role within the inviter's).
func canInvite(inviter, g authz.Grant) bool {
	return inviter.Role.Can(authz.MemberWrite) && inviter.Scope.All && g.Role.Within(inviter.Role)
}

// Remove removes a member. With opts (both true by default, ADR-0029,
// ADR-0035) it also revokes every active API token the member created and
// every pending invitation they sent, each audited, in the same
// transaction; if the caller may not revoke one of them, nothing changes.
// Access through the member's sessions ends at once: every API request
// re-reads the membership. It returns what it revoked. Leaving a tenant
// (removing oneself) needs member:write too.
func (s Service) Remove(ctx context.Context, memberID string, opts Revoke) (Revoked, error) {
	var revoked Revoked
	err := s.change(ctx, "member.remove", memberID, func(tx *ent.Tx, m *ent.Membership, from authz.Grant, owners int) (map[string]any, error) {
		if from.Role == authz.Owner && owners == 1 {
			return nil, ErrLastOwner
		}
		var keptTokens, keptInvitations int
		var err error
		if revoked.Tokens, keptTokens, err = revokeTokens(ctx, tx, m, "member.remove", opts.Tokens, nil); err != nil {
			return nil, err
		}
		if revoked.Invitations, keptInvitations, err = revokeInvitations(ctx, tx, m, "member.remove", opts.Invitations, nil); err != nil {
			return nil, err
		}
		if _, err := tx.MembershipProduct.Delete().Where(membershipproduct.MembershipID(m.ID)).Exec(ctx); err != nil {
			return nil, err
		}
		if err := tx.Membership.DeleteOne(m).Exec(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"role": string(from.Role), "user_id": m.UserID,
			"revoke_tokens": opts.Tokens, "tokens_revoked": len(revoked.Tokens), "tokens_kept": keptTokens,
			"revoke_invitations": opts.Invitations, "invitations_revoked": len(revoked.Invitations), "invitations_kept": keptInvitations}, nil
	})
	if err != nil {
		return Revoked{}, err
	}
	return revoked, nil
}

// revokeTokens revokes m's user's active, unexpired API tokens in this
// tenant, except those keep accepts (nil: none), if revoke; it counts the
// rest as kept. The caller must be allowed to revoke each one
// (authz.CanAssign), else nothing is revoked: the error rolls back.
func revokeTokens(ctx context.Context, tx *ent.Tx, m *ent.Membership, reason string, revoke bool, keep func(authz.Grant) bool) (revoked []string, kept int, err error) {
	p, _ := authz.FromContext(ctx)
	toks, err := tx.APIToken.Query().Where(entapitoken.CreatedBy(m.UserID), entapitoken.RevokedAtIsNil(), notExpired).
		Order(ent.Asc(entapitoken.FieldID)).WithProducts().ForUpdate().All(ctx)
	if err != nil {
		return nil, 0, err
	}
	for _, t := range toks {
		g := authz.Grant{Role: authz.Role(t.Role), Scope: authz.Scope{All: t.ScopeAll}}
		for _, tp := range t.Edges.Products {
			g.Scope.Products = append(g.Scope.Products, tp.ProductID)
		}
		if !revoke || (keep != nil && keep(g)) {
			kept++
			continue
		}
		if err := authz.CanAssign(ctx, authz.Token, &g, nil); err != nil {
			return nil, 0, err
		}
		// The database clock, as apitokens.Revoke (the policies bound it).
		if _, err := tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = clock_timestamp(), updated_at = clock_timestamp()
			WHERE id = $1 AND revoked_at IS NULL`, t.ID); err != nil {
			return nil, 0, err
		}
		if err := recordRevocation(ctx, tx, m, p, "api_token", t.ID, reason); err != nil {
			return nil, 0, err
		}
		revoked = append(revoked, t.ID)
	}
	return revoked, kept, nil
}

// revokeInvitations is revokeTokens for the pending (open, unexpired)
// invitations m's user sent.
func revokeInvitations(ctx context.Context, tx *ent.Tx, m *ent.Membership, reason string, revoke bool, keep func(authz.Grant) bool) (revoked []string, kept int, err error) {
	p, _ := authz.FromContext(ctx)
	invs, err := tx.Invitation.Query().Where(invitation.InvitedBy(m.UserID), invitation.AcceptedAtIsNil(), invitation.RevokedAtIsNil(),
		func(s *entsql.Selector) { s.Where(entsql.ExprP(s.C(invitation.FieldExpiresAt) + " > now()")) }).
		Order(ent.Asc(invitation.FieldID)).WithProducts().ForUpdate().All(ctx)
	if err != nil {
		return nil, 0, err
	}
	for _, inv := range invs {
		g := authz.Grant{Role: authz.Role(inv.Role), Scope: authz.Scope{All: inv.ScopeAll}}
		for _, ip := range inv.Edges.Products {
			g.Scope.Products = append(g.Scope.Products, ip.ProductID)
		}
		if !revoke || (keep != nil && keep(g)) {
			kept++
			continue
		}
		if err := authz.CanAssign(ctx, authz.User, &g, nil); err != nil {
			return nil, 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE invitations SET revoked_at = clock_timestamp(), updated_at = clock_timestamp()
			WHERE id = $1 AND revoked_at IS NULL AND accepted_at IS NULL`, inv.ID); err != nil {
			return nil, 0, err
		}
		if err := recordRevocation(ctx, tx, m, p, "invitation", inv.ID, reason); err != nil {
			return nil, 0, err
		}
		revoked = append(revoked, inv.ID)
	}
	return revoked, kept, nil
}

// recordRevocation audits one revocation made by a member change.
func recordRevocation(ctx context.Context, tx *ent.Tx, m *ent.Membership, p authz.Principal, objectType, id, reason string) error {
	ev := audit.By(p, objectType+".revoke", objectType, id)
	ev.Outcome, ev.Details = auditevent.OutcomeSuccess, map[string]any{"reason": reason, "member_id": m.ID}
	_, err := audit.Record(ctx, tx, m.TenantID, ev)
	return err
}

// notExpired compares with the database clock, as the api_tokens policies do.
func notExpired(s *entsql.Selector) {
	s.Where(entsql.ExprP(s.C(entapitoken.FieldExpiresAt) + " > now()"))
}

type changeFunc func(tx *ent.Tx, m *ent.Membership, from authz.Grant, owners int) (map[string]any, error)

// change runs fn on the locked member, after locking the tenant's owners in
// ID order first (ADR-0029: concurrent demotions can't deadlock or leave no
// owner) and re-checking the caller's own membership, and records the
// outcome.
func (s Service) change(ctx context.Context, action, memberID string, fn changeFunc) error {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.By(p, action, "member", "")
	// Members are tenant-wide: hidden from callers without member:read on
	// every product, like a missing one.
	if authz.Require(ctx, authz.MemberRead, "") != nil || !ids.Valid("mem", memberID) {
		return audit.Refused(ctx, s.DB, tenantID, ev, ErrNotFound, ErrInvalid, ErrNotFound, ErrLastOwner)
	}
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		owners, err := tx.Membership.Query().Where(membership.RoleEQ(membership.RoleOwner)).Order(ent.Asc(membership.FieldID)).ForUpdate().IDs(ctx)
		if err != nil {
			return err
		}
		// The caller was resolved before this transaction; a change made to
		// its own membership meanwhile (it waited on the owners) denies.
		if err := store.RecheckPrincipal(ctx, tx, p); err != nil {
			return err
		}
		m, err := tx.Membership.Query().Where(membership.ID(memberID)).WithProducts().ForUpdate().Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ev.ObjectID = m.ID
		from := authz.Grant{Role: authz.Role(m.Role), Scope: authz.Scope{All: m.ScopeAll}}
		for _, mp := range m.Edges.Products {
			from.Scope.Products = append(from.Scope.Products, mp.ProductID)
		}
		// May the caller change this member at all? Before validating values.
		if err := authz.CanAssign(ctx, authz.User, &from, nil); err != nil {
			return err
		}
		details, err := fn(tx, m, from, len(owners))
		if err != nil {
			return err
		}
		ev.Outcome, ev.Details = auditevent.OutcomeSuccess, details
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrNotFound, ErrLastOwner)
	}
	return nil
}

// valid checks a grant's values (not the caller's right to give it).
func valid(g authz.Grant) error {
	if !g.Role.ForMembership() {
		return &InvalidError{"/role", "unknown role"}
	}
	if g.Scope.All == (len(g.Scope.Products) > 0) {
		return &InvalidError{"/product_ids", "give product IDs exactly when all_products is false"}
	}
	for i, p := range g.Scope.Products {
		if !ids.Valid("prd", p) || slices.Contains(g.Scope.Products[:i], p) {
			return &InvalidError{"/product_ids", "must be distinct product IDs"}
		}
	}
	return nil
}

// productRefusal maps a product outside the tenant (same-tenant key) to an
// InvalidError: missing and another tenant's answer the same.
func productRefusal(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" && pe.ConstraintName == "membership_products_product_same_tenant" {
		return &InvalidError{"/product_ids", "must be products of this tenant"}
	}
	return err
}
