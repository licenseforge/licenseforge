package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/invitationproduct"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
)

// ErrInvitation means the invitation can't be accepted by this user: unknown
// token, revoked, expired or used, or the user doesn't qualify (unverified
// or other email, other issuer, disabled, already a member). Callers show one
// message for all of them.
var ErrInvitation = errors.New("store: invitation can't be accepted")

// InvitationTokenHash is what invitations store for the invite link's token.
func InvitationTokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// AcceptInvitation makes userID a member of the invitation's tenant, with its
// role and scope (ADR-0029). token is the invite link's secret. It is the only
// way the identity pool adds members; the database also refuses anything the
// invitation doesn't allow (identity_accept, and a deferred key that the
// invitation is marked accepted by the member at commit). record runs in the
// same transaction, after the membership exists, and must write the audit
// entry (ADR-0027): an acceptance is never committed unrecorded.
//
// The invitation is locked first, so a concurrent revoke either commits
// before (and the accept is refused) or waits until the accept is done.
func (d *DB) AcceptInvitation(ctx context.Context, token, userID string, record func(*ent.Tx, *ent.Membership) error) (*ent.Membership, error) {
	if token == "" || record == nil {
		return nil, errors.New("store: AcceptInvitation needs the token and an audit record func")
	}
	var m *ent.Membership
	err := inTx(ctx, d.identity, func(tx *ent.Tx) error {
		// FOR UPDATE applies identity's UPDATE policy: only open, unexpired
		// invitations match.
		inv, err := tx.Invitation.Query().Where(invitation.TokenHash(InvitationTokenHash(token))).ForUpdate().Only(ctx)
		if ent.IsNotFound(err) {
			return ErrInvitation
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.invite_token', $2, true)`,
			inv.TenantID, token); err != nil {
			return err
		}
		if m, err = tx.Membership.Create().SetTenantID(inv.TenantID).SetUserID(userID).SetRole(membership.Role(inv.Role)).
			SetScopeAll(inv.ScopeAll).SetInvitationID(inv.ID).Save(ctx); err != nil {
			return refused(err)
		}
		products, err := tx.InvitationProduct.Query().Where(invitationproduct.InvitationID(inv.ID)).All(ctx)
		if err != nil {
			return err
		}
		for _, p := range products {
			if _, err := tx.MembershipProduct.Create().SetTenantID(inv.TenantID).SetMembershipID(m.ID).SetProductID(p.ProductID).Save(ctx); err != nil {
				return refused(err)
			}
		}
		n, err := tx.Invitation.Update().Where(invitation.ID(inv.ID), invitation.AcceptedAtIsNil(), invitation.RevokedAtIsNil()).
			SetAcceptedAt(time.Now()).SetAcceptedBy(userID).Save(ctx)
		if err != nil {
			return refused(err)
		}
		// The lock already excludes concurrent revokes; this also catches an
		// expiry between the lock and the mark. Either guard alone holds the
		// race test; both together are defence in depth.
		if n != 1 { // never commit an unmarked membership
			return ErrInvitation
		}
		return record(tx, m)
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// refused maps the database's refusals (row-level security, unique
// violations: already a member or used) to ErrInvitation. Other errors stay,
// including a missing grant ("permission denied", also 42501): that is an
// outage, not the user's invitation.
func refused(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && ((pe.Code == "42501" && strings.Contains(pe.Message, "row-level security")) || pe.Code == "23505") {
		return fmt.Errorf("%w: %s", ErrInvitation, pe.Message)
	}
	return err
}
