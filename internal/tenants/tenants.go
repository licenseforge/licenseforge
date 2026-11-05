// Package tenants changes a tenant's own settings. Today: its MFA policy
// (ADR-0038), the assurance a session needs to act in the tenant.
package tenants

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/apitoken"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

var (
	// ErrInvalid means the value isn't an MFA policy.
	ErrInvalid = errors.New("tenants: invalid MFA policy")
	// ErrPolicyUnmet means the policy would be raised above what the
	// caller's own session proved: it would lock the caller out.
	ErrPolicyUnmet = errors.New("tenants: your session doesn't meet this MFA policy")
)

// Service works on the tenant pool.
type Service struct{ DB *store.DB }

// PolicyChange is the result of SetMFAPolicy.
type PolicyChange struct {
	Tenant *ent.Tenant
	From   authz.Assurance
	// ActiveTokens is how many API tokens are active: all were created
	// before the change, and raising the policy doesn't revoke them.
	ActiveTokens int
}

// SetMFAPolicy sets ctx's tenant's MFA policy. Only an owner (tenant:write)
// in a dashboard session may, and raising it needs a session that already
// meets the new level. The change is audited in its transaction; refusals
// in their own (ADR-0027). A nil policy changes nothing (an empty merge
// patch) and returns the tenant.
func (s Service) SetMFAPolicy(ctx context.Context, policyPtr *authz.Assurance) (PolicyChange, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return PolicyChange{}, err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.By(p, "tenant.mfa_policy.update", "tenant", tenantID)
	refused := func(err error) error { return audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrPolicyUnmet) }
	// Owners, from a session: API tokens don't change who may get in.
	if err := authz.Require(ctx, authz.TenantWrite, ""); err != nil || p.Kind != authz.User {
		return PolicyChange{}, refused(authz.ErrDenied)
	}
	if policyPtr != nil && !policyPtr.Valid() {
		return PolicyChange{}, refused(ErrInvalid)
	}
	var out PolicyChange
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		// The caller is still an owner (a concurrent demotion or removal
		// waits for this, or makes it fail).
		if err := store.RecheckPrincipal(ctx, tx, p); err != nil {
			return err
		}
		// NO KEY UPDATE, not FOR UPDATE: audit entries (and every other
		// tenant row) reference the tenant, and their foreign-key checks take
		// KEY SHARE, which FOR UPDATE would block while this transaction
		// waits for the chain lock: a deadlock. Lock order: tenant row, then
		// the audit lock.
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM tenants WHERE id = $1 FOR NO KEY UPDATE`, tenantID); err != nil {
			return err
		}
		t, err := tx.Tenant.Get(ctx, tenantID)
		if err != nil {
			return err
		}
		from := authz.Assurance(t.MfaPolicy)
		policy := from
		if policyPtr != nil {
			policy = *policyPtr
		}
		ev.Details = map[string]any{"from": string(from), "to": string(policy), "session_assurance": string(p.Assurance)}
		// No self-lockout: raising needs a session that already meets it.
		if !from.Meets(policy) && !p.Assurance.Meets(policy) {
			return ErrPolicyUnmet
		}
		out.From = from
		if out.ActiveTokens, err = tx.APIToken.Query().Where(apitoken.RevokedAtIsNil(), notExpired).Count(ctx); err != nil {
			return err
		}
		if from == policy {
			out.Tenant = t
			return nil // no change, nothing to record
		}
		res, err := tx.ExecContext(ctx, `UPDATE tenants SET mfa_policy = $1, updated_at = clock_timestamp() WHERE id = $2`, string(policy), tenantID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(fmt.Errorf("tenants: %d rows updated", n), err)
		}
		if out.Tenant, err = tx.Tenant.Get(ctx, tenantID); err != nil {
			return err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		ev.Details["active_tokens"] = out.ActiveTokens
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return PolicyChange{}, refused(err)
	}
	return out, nil
}

// notExpired compares with the database clock, as the api_tokens policies do.
func notExpired(s *sql.Selector) { s.Where(sql.ExprP(s.C(apitoken.FieldExpiresAt) + " > now()")) }
