package platform

import (
	"context"
	"strings"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/membershipproduct"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/ent/user"
)

// Break-glass recovery for a tenant nobody inside can fix (ADR-0042 and
// ADR-0038, amended 2026-11-12): operator commands on the platform login
// only, never the API (an admin user's Actor is refused), and audited on the
// tenant's own chain as well as the platform's, so the tenant sees them.

// Recovered is what RecoverOwner did: promoted an existing member, or
// invited a new owner (Token shown once).
type Recovered struct {
	Tenant     *ent.Tenant
	Promoted   *ent.Membership
	Invitation *ent.Invitation
	Token      string
}

// RecoverOwner gives a tenant whose owners can't sign in any more an owner
// again: the member whose verified email is email becomes an owner of every
// product, or, when no member has it, an owner invitation for email is
// created. Several members with that email is a conflict; so is a member
// who is already an owner (nothing to recover).
func (s Service) RecoverOwner(ctx context.Context, a Actor, ref, email string) (Recovered, error) {
	ev := a.event("tenant.owner_recovery", "tenant")
	var r Recovered
	err := s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		if a.UserID != "" {
			return ErrNotAdmin // not from the API: an operator's command
		}
		if !identity.UsableEmail(email) {
			return &InvalidError{Field: "/email", Message: "must be an email address without spaces or invisible characters"}
		}
		var err error
		if r.Tenant, err = findTenant(ctx, tx, ref); err != nil {
			return err
		}
		ev.ObjectID = r.Tenant.ID
		// The re-issue lock (ReinviteOwner): one owner change per tenant at a time.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.owner_invitation:' || $1, 0))`, r.Tenant.ID); err != nil {
			return err
		}
		members, err := tx.Membership.Query().Where(membership.TenantID(r.Tenant.ID),
			membership.HasUserWith(user.EmailEqualFold(email), user.EmailVerified(true), user.DisabledAtIsNil())).ForUpdate().All(ctx)
		if err != nil {
			return err
		}
		switch {
		case len(members) > 1:
			return &InvalidError{Field: "/email", Message: "several members have this verified email", Conflict: true}
		case len(members) == 1 && members[0].Role == membership.RoleOwner:
			return &InvalidError{Field: "/email", Message: "this member is already an owner", Conflict: true}
		case len(members) == 1:
			m := members[0]
			if _, err := tx.MembershipProduct.Delete().Where(membershipproduct.MembershipID(m.ID)).Exec(ctx); err != nil {
				return err
			}
			if r.Promoted, err = tx.Membership.UpdateOne(m).SetRole(membership.RoleOwner).SetScopeAll(true).Save(ctx); err != nil {
				return err
			}
			up := a.event("member.update", "membership")
			up.ObjectID, up.Outcome = m.ID, auditevent.OutcomeSuccess
			up.Details["from"], up.Details["to"], up.Details["recovery"] = string(m.Role), "owner", true
			if _, err := audit.Record(ctx, tx, r.Tenant.ID, up); err != nil {
				return err
			}
		default:
			if r.Invitation, r.Token, err = ownerInvitation(ctx, tx, a, r.Tenant.ID, strings.TrimSpace(email)); err != nil {
				return err
			}
		}
		ev.Outcome = auditevent.OutcomeSuccess
		ev.Details["slug"], ev.Details["promoted"] = r.Tenant.Slug, r.Promoted != nil
		_, err = audit.Record(ctx, tx, audit.PlatformTenant, ev)
		return err
	})
	if err != nil {
		return Recovered{}, s.refused(ctx, ev, err)
	}
	return r, nil
}

// LowerMFAPolicy lowers a tenant's MFA policy (ADR-0038: a tenant locked out
// by a policy its members can't meet any more). It only lowers: raising is
// the owners' own change, from a session that meets it.
func (s Service) LowerMFAPolicy(ctx context.Context, a Actor, ref string, policy authz.Assurance) (*ent.Tenant, error) {
	ev := a.event("tenant.mfa_policy_recovery", "tenant")
	var t *ent.Tenant
	err := s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		if a.UserID != "" {
			return ErrNotAdmin
		}
		if !policy.Valid() {
			return &InvalidError{Field: "/mfa_policy", Message: "must be none, mfa or phishing_resistant"}
		}
		var err error
		if t, err = findTenant(ctx, tx, ref); err != nil {
			return err
		}
		ev.ObjectID = t.ID
		if t, err = tx.Tenant.Query().Where(tenant.ID(t.ID)).ForUpdate().Only(ctx); err != nil {
			return err
		}
		from := authz.Assurance(t.MfaPolicy)
		if !from.Meets(policy) || from == policy {
			return &InvalidError{Field: "/mfa_policy", Message: "can only lower the policy (it is " + string(from) + ")", Conflict: true}
		}
		if t, err = tx.Tenant.UpdateOne(t).SetMfaPolicy(tenant.MfaPolicy(policy)).Save(ctx); err != nil {
			return err
		}
		up := a.event("tenant.mfa_policy.update", "tenant")
		up.ObjectID, up.Outcome = t.ID, auditevent.OutcomeSuccess
		up.Details["from"], up.Details["to"], up.Details["recovery"] = string(from), string(policy), true
		if _, err := audit.Record(ctx, tx, t.ID, up); err != nil {
			return err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		ev.Details["slug"], ev.Details["from"], ev.Details["to"] = t.Slug, string(from), string(policy)
		_, err = audit.Record(ctx, tx, audit.PlatformTenant, ev)
		return err
	})
	if err != nil {
		return nil, s.refused(ctx, ev, err)
	}
	return t, nil
}

// findTenant resolves an ID or slug, never the reserved platform tenant.
func findTenant(ctx context.Context, tx *ent.Tx, ref string) (*ent.Tenant, error) {
	t, err := tx.Tenant.Query().Where(tenant.IDNEQ(audit.PlatformTenant), tenant.Or(tenant.ID(ref), tenant.Slug(ref))).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	return t, err
}
