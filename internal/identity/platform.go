package identity

import (
	"context"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/platformadmin"
)

// IsPlatformAdmin reports whether userID is a platform admin, read on the
// identity login. It only tells the dashboard to show the platform screens
// (ADR-0042); the platform routes check for themselves on every request.
func (s Service) IsPlatformAdmin(ctx context.Context, userID string) (bool, error) {
	var ok bool
	err := s.DB.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		var err error
		ok, err = tx.PlatformAdmin.Query().Where(platformadmin.UserID(userID)).Exist(ctx)
		return err
	})
	return ok, err
}

// Source is where a login request came from, for its audit entries: the
// connection's IP (or one set by a trusted proxy) and the user agent.
type Source struct{ IP, UserAgent string }

// Login events and the bootstrap grant have no tenant: they go to the
// platform chain (ADR-0027, ADR-0029), on the platform pool, the only login
// the database lets write it.

// RecordLogin appends a user.login entry to the platform chain, in a
// transaction of its own. userID is empty when the login failed before a user
// was known; reason (snake_case, no personal data) says why it failed.
func (s Service) RecordLogin(ctx context.Context, userID string, outcome auditevent.Outcome, reason string, src Source, auth *SessionAuth) error {
	e := audit.Event{ActorType: auditevent.ActorTypeUser, ActorID: userID, Action: "user.login",
		Outcome: outcome, SourceIP: src.IP, UserAgent: src.UserAgent, Details: map[string]any{}}
	if userID != "" {
		e.ObjectType, e.ObjectID = "user", userID
	}
	if reason != "" {
		e.Details["reason"] = reason
	}
	if auth != nil { // how the session was authenticated (ADR-0038): IA-2 evidence
		e.Details["assurance"], e.Details["amr"], e.Details["acr"], e.Details["acrs"] = string(auth.Assurance), auth.AMR, auth.ACR, auth.ACRs
		if auth.AuthTime != nil {
			e.Details["auth_time"] = auth.AuthTime.Format(time.RFC3339)
		}
	}
	return s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, audit.PlatformTenant, e)
		return err
	})
}

// Bootstrap makes u the first platform admin when u matches setting
// (LICENSEFORGE_BOOTSTRAP_ADMIN, BootstrapMatches) and there is no platform
// admin yet (ADR-0003, ADR-0029, ADR-0031). The grant and its platform-chain
// entry commit together. It reports whether it granted.
func (s Service) Bootstrap(ctx context.Context, setting string, u *ent.User, src Source) (bool, error) {
	if !BootstrapMatches(setting, u) {
		return false, nil
	}
	return s.DB.BootstrapPlatformAdmin(ctx, u.ID, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, audit.PlatformTenant, audit.Event{
			ActorType: auditevent.ActorTypeSystem, Action: "platform_admin.bootstrap",
			ObjectType: "user", ObjectID: u.ID, Outcome: auditevent.OutcomeSuccess,
			SourceIP: src.IP, UserAgent: src.UserAgent,
			Details: map[string]any{"via": "LICENSEFORGE_BOOTSTRAP_ADMIN"},
		})
		return err
	})
}
