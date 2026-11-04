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

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	entapitoken "licenseforge.io/licenseforge/internal/store/ent/apitoken"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
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

// Change is a merge-patch of a membership: nil fields stay.
type Change struct {
	Role  *authz.Role
	Scope *authz.Scope
}

// Update changes a member's role or product scope. Order (ADR-0032): the
// member must be visible (else ErrNotFound), the caller must be allowed to
// change it at all (authz.ErrDenied), then the values must be valid
// (InvalidError), within the caller's role, and leave an owner.
func (s Service) Update(ctx context.Context, memberID string, c Change) (*ent.Membership, error) {
	var out *ent.Membership
	err := s.change(ctx, "member.update", memberID, func(tx *ent.Tx, m *ent.Membership, from authz.Grant, owners int) (map[string]any, error) {
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
		var err error
		out, err = withEdges(tx.Membership.Query()).Where(membership.ID(m.ID)).Only(ctx)
		return map[string]any{"from_role": string(from.Role), "role": string(to.Role), "scope_all": to.Scope.All, "products": len(to.Scope.Products)}, err
	})
	return out, err
}

// Remove removes a member. revokeTokens (the default ADR-0029 asks for) also
// revokes every active API token the member created, each audited, in the
// same transaction; if the caller may not revoke one of them, nothing
// changes. Access through the member's sessions ends at once: every API
// request re-reads the membership. It returns the number of tokens revoked.
func (s Service) Remove(ctx context.Context, memberID string, revokeTokens bool) (int, error) {
	var revoked int
	err := s.change(ctx, "member.remove", memberID, func(tx *ent.Tx, m *ent.Membership, from authz.Grant, owners int) (map[string]any, error) {
		if from.Role == authz.Owner && owners == 1 {
			return nil, ErrLastOwner
		}
		if revokeTokens {
			n, err := revokeCreatedBy(ctx, tx, m)
			if err != nil {
				return nil, err
			}
			revoked = n
		}
		if _, err := tx.MembershipProduct.Delete().Where(membershipproduct.MembershipID(m.ID)).Exec(ctx); err != nil {
			return nil, err
		}
		if err := tx.Membership.DeleteOne(m).Exec(ctx); err != nil {
			return nil, err
		}
		return map[string]any{"role": string(from.Role), "user_id": m.UserID, "tokens_revoked": revoked}, nil
	})
	return revoked, err
}

func revokeCreatedBy(ctx context.Context, tx *ent.Tx, m *ent.Membership) (int, error) {
	p, _ := authz.FromContext(ctx)
	toks, err := tx.APIToken.Query().Where(entapitoken.CreatedBy(m.UserID), entapitoken.RevokedAtIsNil()).
		Order(ent.Asc(entapitoken.FieldID)).WithProducts().ForUpdate().All(ctx)
	if err != nil {
		return 0, err
	}
	for _, t := range toks {
		g := authz.Grant{Role: authz.Role(t.Role), Scope: authz.Scope{All: t.ScopeAll}}
		for _, tp := range t.Edges.Products {
			g.Scope.Products = append(g.Scope.Products, tp.ProductID)
		}
		if err := authz.CanAssign(ctx, authz.Token, &g, nil); err != nil {
			return 0, err
		}
		// The database clock, as apitokens.Revoke (the policies bound it).
		if _, err := tx.ExecContext(ctx, `UPDATE api_tokens SET revoked_at = clock_timestamp(), updated_at = clock_timestamp()
			WHERE id = $1 AND revoked_at IS NULL`, t.ID); err != nil {
			return 0, err
		}
		ev := event(p, "api_token.revoke", "api_token", t.ID)
		ev.Outcome, ev.Details = auditevent.OutcomeSuccess, map[string]any{"reason": "member.remove", "member_id": m.ID}
		if _, err := audit.Record(ctx, tx, m.TenantID, ev); err != nil {
			return 0, err
		}
	}
	return len(toks), nil
}

type changeFunc func(tx *ent.Tx, m *ent.Membership, from authz.Grant, owners int) (map[string]any, error)

// change runs fn on the locked member, after locking the tenant's owners in
// ID order first (ADR-0029: concurrent demotions can't deadlock or leave no
// owner), and records the outcome.
func (s Service) change(ctx context.Context, action, memberID string, fn changeFunc) error {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return err
	}
	p, _ := authz.FromContext(ctx)
	ev := event(p, action, "member", "")
	// Members are tenant-wide: hidden from callers without member:read on
	// every product, like a missing one.
	if authz.Require(ctx, authz.MemberRead, "") != nil || !ids.Valid("mem", memberID) {
		return s.refused(ctx, tenantID, ev, ErrNotFound)
	}
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		owners, err := tx.Membership.Query().Where(membership.RoleEQ(membership.RoleOwner)).Order(ent.Asc(membership.FieldID)).ForUpdate().IDs(ctx)
		if err != nil {
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
		return s.refused(ctx, tenantID, ev, err)
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

// ponytail: event and refused mirror apitokens'; move them to package audit
// when a third service needs them.
func event(p authz.Principal, action, objectType, objectID string) audit.Event {
	actor := auditevent.ActorTypeUser
	if p.Kind == authz.Token {
		actor = auditevent.ActorTypeToken
	}
	return audit.Event{ActorType: actor, ActorID: p.ID, Action: action, ObjectType: objectType, ObjectID: objectID}
}

// refused records a denied or failed attempt in its own transaction and
// returns err. Infrastructure errors aren't attempts.
func (s Service) refused(ctx context.Context, tenantID string, ev audit.Event, err error) error {
	switch {
	case errors.Is(err, authz.ErrDenied):
		ev.Outcome = auditevent.OutcomeDenied
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrNotFound), errors.Is(err, ErrLastOwner):
		ev.Outcome = auditevent.OutcomeFailure
	default:
		return err
	}
	ev.Details = nil
	if rerr := s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}
