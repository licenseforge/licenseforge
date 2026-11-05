package api

import (
	"context"
	"net/url"
	"sync"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// mfaRequired is the answer to a member whose session doesn't meet the
// tenant's MFA policy (ADR-0038): the levels, and where to sign in again
// with the stronger method, coming back to the tenant.
func mfaRequired(t identity.TenantRef, current authz.Assurance) *problem {
	q := url.Values{"assurance": {string(t.MFAPolicy)}, "return": {"/t/" + t.Slug + "/"}}
	detail := "This tenant requires MFA: sign in again with a second factor."
	if t.MFAPolicy == authz.AssurancePhishingResistant {
		detail = "This tenant requires phishing-resistant MFA: sign in again with a passkey or security key."
	}
	return &problem{status: 403, code: "mfa_required", detail: detail, extra: map[string]string{
		"required_assurance": string(t.MFAPolicy), "session_assurance": string(current),
		"step_up_url": "/auth/login?" + q.Encode(),
	}}
}

// mfaAudited remembers the (session, tenant) pairs whose refusal is on the
// audit chain, so a polling dashboard writes one entry, not one a request
// (ADR-0038). ponytail: per replica and capped; the database check behind
// it keeps it to one entry across replicas.
type mfaAudited struct {
	mu   sync.Mutex
	seen map[string]bool
}

const mfaAuditedMax = 10000

func (m *mfaAudited) has(k string) bool { m.mu.Lock(); defer m.mu.Unlock(); return m.seen[k] }

func (m *mfaAudited) add(k string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil || len(m.seen) >= mfaAuditedMax {
		m.seen = map[string]bool{} // forget all: at worst the database check runs again
	}
	m.seen[k] = true
}

// mfaRefused counts every refusal and audits the first one per session and
// tenant on the tenant's chain. Failing to record never changes the answer
// (the request is refused either way); it is logged.
func (s *server) mfaRefused(ctx context.Context, t identity.TenantRef, userID string, sess identity.SessionInfo) {
	metrics.MFARefusals.WithLabelValues(string(t.MFAPolicy)).Inc()
	key := sess.ID + "|" + t.ID
	if s.mfaSeen.has(key) {
		return
	}
	err := s.Tenants.DB.WithTenant(ctx, t.ID, func(tx *ent.Tx) error {
		// The chain's lock first, so two replicas can't both find no entry.
		if err := audit.Lock(ctx, tx, t.ID); err != nil {
			return err
		}
		done, err := tx.AuditEvent.Query().Where(auditevent.TenantID(t.ID), auditevent.Action("session.mfa_required"),
			auditevent.ObjectType("session"), auditevent.ObjectID(sess.ID)).Exist(ctx)
		if err != nil || done {
			return err
		}
		_, err = audit.Record(ctx, tx, t.ID, audit.Event{ActorType: auditevent.ActorTypeUser, ActorID: userID,
			Action: "session.mfa_required", ObjectType: "session", ObjectID: sess.ID, Outcome: auditevent.OutcomeDenied,
			Details: map[string]any{"required": string(t.MFAPolicy), "session_assurance": string(sess.Assurance)}})
		return err
	})
	if err != nil {
		s.Log.ErrorContext(ctx, "audit mfa refusal", "tenant", t.ID, "err", err)
		return
	}
	s.mfaSeen.add(key)
}
