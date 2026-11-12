package platform

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/membershipproduct"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
)

// Break-glass recovery for a tenant nobody inside can fix (ADR-0042 and
// ADR-0038, amended 2026-11-12): operator commands on the platform login
// only, never the API (an admin user's Actor is refused), and audited on the
// tenant's own chain as well as the platform's, so the tenant sees them.

// Recovered is what RecoverOwner did: promoted an existing member, or
// invited a new owner (Token shown once).
type Recovered struct {
	Tenant        *ent.Tenant
	Promoted      *ent.Membership
	PromotedEmail string // and issuer: who got the role, for the operator to check
	PromotedIss   string
	Invitation    *ent.Invitation
	Token         string
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
		// Every member whose email an invitation for this address would match
		// (acceptance's own rule: NFC, lowercase), so none is missed.
		cands, err := similarMembers(ctx, tx, r.Tenant.ID, email)
		if err != nil {
			return err
		}
		conflict := func(msg string) error { return &InvalidError{Field: "/", Message: msg, Conflict: true} }
		switch {
		case len(cands) > 1:
			return conflict("several members have this email")
		case len(cands) == 1 && (!cands[0].verified || cands[0].disabled):
			return conflict("a member has this email, but it isn't verified or the user is disabled: they can't accept an invitation either")
		case len(cands) == 1 && !asciiFold(cands[0].email, email) && strings.TrimSpace(cands[0].email) != strings.TrimSpace(email):
			// The highest privilege, granted at once: like the bootstrap
			// admin (identity.BootstrapMatches), no Unicode look-alike
			// folding; a non-ASCII email must be typed exactly as stored.
			return conflict("a member's email matches this one only after Unicode folding: pass their email exactly as they signed in with it, or use another address")
		case len(cands) == 1 && cands[0].m.Role == membership.RoleOwner:
			return conflict("this member is already an owner")
		case len(cands) == 1:
			m := cands[0].m
			r.PromotedEmail, r.PromotedIss = cands[0].email, cands[0].issuer
			products, err := tx.MembershipProduct.Query().Where(membershipproduct.MembershipID(m.ID)).Count(ctx)
			if err != nil {
				return err
			}
			if _, err := tx.MembershipProduct.Delete().Where(membershipproduct.MembershipID(m.ID)).Exec(ctx); err != nil {
				return err
			}
			if r.Promoted, err = tx.Membership.UpdateOne(m).SetRole(membership.RoleOwner).SetScopeAll(true).Save(ctx); err != nil {
				return err
			}
			up := a.event("member.update", "membership")
			up.ObjectID, up.Outcome = m.ID, auditevent.OutcomeSuccess
			for k, v := range map[string]any{"from_role": string(m.Role), "from_scope_all": m.ScopeAll, "from_products": products,
				"role": "owner", "scope_all": true, "products": 0, "tokens_revoked": 0, "invitations_revoked": 0, "recovery": true} {
				up.Details[k] = v // members.Update's keys
			}
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
		// The owner-change lock first, as ReinviteOwner and RecoverOwner take
		// it: one lock order for the tenant row and the audit chains.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.owner_invitation:' || $1, 0))`, t.ID); err != nil {
			return err
		}
		if t, err = tx.Tenant.Query().Where(tenant.ID(t.ID)).ForUpdate().Only(ctx); err != nil {
			return err
		}
		from := authz.Assurance(t.MfaPolicy)
		if !from.Meets(policy) || from == policy {
			return &InvalidError{Field: "/", Message: "can only lower the policy (it is " + string(from) + ")", Conflict: true}
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

type candidate struct {
	m                  *ent.Membership
	email, issuer      string
	verified, disabled bool
}

// similarMembers returns tenantID's members whose email equals email after
// NFC normalization and lowercasing, locked for the change.
func similarMembers(ctx context.Context, tx *ent.Tx, tenantID, email string) ([]candidate, error) {
	rows, err := tx.QueryContext(ctx, `SELECT m.id, u.email, u.issuer, u.email_verified, u.disabled_at IS NOT NULL
		FROM memberships m JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1 AND u.email IS NOT NULL AND lower(normalize(u.email, NFC)) = lower(normalize($2, NFC))
		ORDER BY m.id FOR UPDATE OF m`, tenantID, strings.TrimSpace(email))
	if err != nil {
		return nil, err
	}
	var out []candidate
	var ids []string
	for rows.Next() {
		var c candidate
		var id string
		if err := rows.Scan(&id, &c.email, &c.issuer, &c.verified, &c.disabled); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids, out = append(ids, id), append(out, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	for i, id := range ids {
		m, err := tx.Membership.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		out[i].m = m
	}
	return out, nil
}

// asciiFold is identity.BootstrapMatches' email rule: both ASCII, equal but
// for ASCII case.
func asciiFold(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	for _, s := range []string{a, b} {
		for i := 0; i < len(s); i++ {
			if s[i] >= utf8.RuneSelf {
				return false
			}
		}
	}
	return strings.EqualFold(a, b)
}
