// Package invitations lists, creates, revokes and accepts a tenant's
// invitations (ADR-0019, ADR-0029). The invite link's token is shown once
// and stored as a hash; accepting needs it, a logged-in user whose verified
// email matches, and an open invitation, all enforced by the database
// (store.AcceptInvitation). Every change and refusal is audited (ADR-0027).
package invitations

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// DefaultTTL is how long an invitation stays open (ADR-0029).
const DefaultTTL = 7 * 24 * time.Hour

var (
	// ErrNotFound means no such open invitation in the tenant, or one the
	// caller can't see (the same answer, ADR-0032).
	ErrNotFound = errors.New("invitations: no such open invitation")
	// ErrInvalid is wrapped by InvalidError.
	ErrInvalid = errors.New("invitations: invalid request")
)

// InvalidError names the invalid field (a JSON Pointer into the request).
type InvalidError struct{ Field, Message string }

func (e *InvalidError) Error() string { return fmt.Sprintf("invitations: %s: %s", e.Field, e.Message) }
func (e *InvalidError) Unwrap() error { return ErrInvalid }

// Service works on the tenant pool (and the identity pool to accept).
type Service struct{ DB *store.DB }

// Created is a new invitation. Token goes in the invite link; it is shown
// once and never stored.
type Created struct {
	Token string
	Row   *ent.Invitation
}

// List returns up to limit of ctx's tenant's invitations (open, accepted,
// revoked and expired) with their products, newest first, after (afterAt,
// afterID) or from the start if afterID is "". Invitations are tenant-wide:
// a product-scoped caller sees none.
func (s Service) List(ctx context.Context, limit int, afterAt time.Time, afterID string) ([]*ent.Invitation, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, _, err := authz.Products(ctx, authz.MemberRead)
	if err != nil || !all {
		return nil, err
	}
	var out []*ent.Invitation
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.Invitation.Query().WithProducts().Order(ent.Desc(invitation.FieldCreatedAt), ent.Desc(invitation.FieldID)).Limit(limit)
		if afterID != "" {
			q.Where(invitation.Or(invitation.CreatedAtLT(afterAt), invitation.And(invitation.CreatedAt(afterAt), invitation.IDLT(afterID))))
		}
		out, err = q.All(ctx)
		return err
	})
	return out, err
}

// Create invites email with role and scope, open for DefaultTTL. Order
// (ADR-0032): the caller must be allowed to invite at all (a user with
// member:write on every product: authz.ErrDenied), then the values must be
// valid (InvalidError) and within the caller's role (authz.ErrDenied).
func (s Service) Create(ctx context.Context, email string, role authz.Role, scope authz.Scope) (Created, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return Created{}, err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.By(p, "invitation.create", "invitation", "")
	g := authz.Grant{Role: role, Scope: scope}
	err = authz.CanAssign(ctx, authz.User, nil, &authz.Grant{Role: authz.Viewer, Scope: authz.Scope{All: true}})
	if err == nil {
		err = valid(email, g)
	}
	if err == nil {
		err = authz.CanAssign(ctx, authz.User, nil, &g)
	}
	if err != nil {
		return Created{}, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid)
	}
	tok := rand.Text()
	var row *ent.Invitation
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		// The inviter still holds the grant checked above, until commit.
		if err := store.RecheckPrincipal(ctx, tx, p); err != nil {
			return err
		}
		var err error
		row, err = tx.Invitation.Create().SetTenantID(tenantID).SetEmail(email).SetRole(invitation.Role(role)).
			SetScopeAll(scope.All).SetInvitedBy(p.ID).SetTokenHash(store.InvitationTokenHash(tok)).
			SetExpiresAt(time.Now().Add(DefaultTTL)).Save(ctx)
		if err != nil {
			return err
		}
		for _, pr := range scope.Products {
			if err := tx.InvitationProduct.Create().SetTenantID(tenantID).SetInvitationID(row.ID).SetProductID(pr).Exec(ctx); err != nil {
				return productRefusal(err)
			}
		}
		if row, err = tx.Invitation.Query().Where(invitation.ID(row.ID)).WithProducts().Only(ctx); err != nil {
			return err
		}
		ev.ObjectID, ev.Outcome = row.ID, auditevent.OutcomeSuccess
		// Never the email (ADR-0029).
		ev.Details = map[string]any{"role": string(role), "scope_all": scope.All, "products": len(scope.Products),
			"expires_at": row.ExpiresAt.UTC().Format(time.RFC3339)}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		ev.ObjectID, ev.Details = "", nil
		return Created{}, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid)
	}
	return Created{Token: tok, Row: row}, nil
}

// Revoke closes an open invitation of ctx's tenant and returns it. Order
// (ADR-0032): missing, closed or hidden (product-scoped callers: invitations
// are tenant-wide) is ErrNotFound; then the caller must be allowed to take
// back its grant (authz.ErrDenied).
func (s Service) Revoke(ctx context.Context, id string) (*ent.Invitation, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.By(p, "invitation.revoke", "invitation", "")
	if authz.Require(ctx, authz.MemberRead, "") != nil || !ids.Valid("inv", id) {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, ErrNotFound, ErrNotFound)
	}
	var row *ent.Invitation
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		row, err = tx.Invitation.Query().Where(invitation.ID(id), invitation.AcceptedAtIsNil(), invitation.RevokedAtIsNil()).
			WithProducts().ForUpdate().Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ev.ObjectID = row.ID
		g := authz.Grant{Role: authz.Role(row.Role), Scope: authz.Scope{All: row.ScopeAll}}
		for _, ip := range row.Edges.Products {
			g.Scope.Products = append(g.Scope.Products, ip.ProductID)
		}
		if err := authz.CanAssign(ctx, authz.User, &g, nil); err != nil {
			return err
		}
		if err := store.RecheckPrincipal(ctx, tx, p); err != nil {
			return err
		}
		// The database clock; the revoke_only policy allows nothing else.
		if _, err := tx.ExecContext(ctx, `UPDATE invitations SET revoked_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1`, row.ID); err != nil {
			return err
		}
		if row, err = tx.Invitation.Query().Where(invitation.ID(id)).WithProducts().Only(ctx); err != nil {
			return err
		}
		ev.Outcome, ev.Details = auditevent.OutcomeSuccess, map[string]any{"role": string(g.Role)}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrNotFound)
	}
	return row, nil
}

// Accept makes userID (a signed-in user) a member through the invite link's
// token, audited in the invitation's tenant in the same transaction. Any
// reason it can't be accepted is store.ErrInvitation.
func (s Service) Accept(ctx context.Context, userID, token string) (*ent.Membership, error) {
	return s.DB.AcceptInvitation(ctx, token, userID, func(tx *ent.Tx, m *ent.Membership) error {
		_, err := audit.Record(ctx, tx, m.TenantID, audit.Event{ActorType: auditevent.ActorTypeUser, ActorID: userID,
			Action: "invitation.accept", ObjectType: "invitation", ObjectID: m.InvitationID, Outcome: auditevent.OutcomeSuccess,
			Details: map[string]any{"membership_id": m.ID, "role": string(m.Role), "scope_all": m.ScopeAll}})
		return err
	})
}

func valid(email string, g authz.Grant) error {
	if !identity.UsableEmail(email) {
		return &InvalidError{"/email", "must be an email address without spaces or invisible characters"}
	}
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
	if errors.As(err, &pe) && pe.Code == "23503" && pe.ConstraintName == "invitation_products_product_same_tenant" {
		return &InvalidError{"/product_ids", "must be products of this tenant"}
	}
	return err
}
