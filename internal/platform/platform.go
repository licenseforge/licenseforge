// Package platform is what platform admins do outside any tenant
// (ADR-0019, ADR-0042): list tenants, and create one with its first owner's
// invitation. It works on the platform pool, the only login that sees every
// tenant (ADR-0009).
package platform

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/invitations"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/membership"
	"licenseforge.io/licenseforge/internal/store/ent/platformadmin"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/ent/user"
	"licenseforge.io/licenseforge/internal/store/schema"
)

var (
	// ErrNotAdmin: the caller isn't an enabled platform admin.
	ErrNotAdmin = errors.New("platform: not a platform admin")
	// ErrNotFound: no such tenant (the platform tenant included).
	ErrNotFound = errors.New("platform: no such tenant")
	ErrInvalid  = errors.New("platform: invalid request")
	ErrConflict = errors.New("platform: conflict")
)

// InvalidError names the field a value was refused for (a JSON Pointer).
// Conflict marks a value already taken (409, not 422).
type InvalidError struct {
	Field, Message string
	Conflict       bool
}

func (e *InvalidError) Error() string { return fmt.Sprintf("platform: %s: %s", e.Field, e.Message) }

func (e *InvalidError) Unwrap() error {
	if e.Conflict {
		return ErrConflict
	}
	return ErrInvalid
}

// Service works on the platform pool.
type Service struct{ DB *store.DB }

// Actor is who acts: a platform admin's user ID, or the system (empty: the
// CLI on the platform login). The empty Actor skips the admin check, so only
// operator commands on the platform login may construct it; API handlers
// always pass the admitted user's ID.
type Actor struct{ UserID string }

func (a Actor) event(action, objectType string) audit.Event {
	if a.UserID == "" {
		return audit.Event{ActorType: auditevent.ActorTypeSystem, Action: action, ObjectType: objectType, Details: map[string]any{"via": "cli"}}
	}
	return audit.Event{ActorType: auditevent.ActorTypePlatform, ActorID: a.UserID, Action: action, ObjectType: objectType, Details: map[string]any{}}
}

// IsAdmin reports whether userID is a platform admin whose account isn't
// disabled.
func (s Service) IsAdmin(ctx context.Context, userID string) (bool, error) {
	var ok bool
	err := s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		var err error
		ok, err = isAdmin(ctx, tx, userID, false)
		return err
	})
	return ok, err
}

// isAdmin, with lock: the admin-set lock shared and the user FOR SHARE, so
// removing the admin (ADR-0031) or disabling the user waits for the caller's
// transaction, as store.RecheckPrincipal does for tenant members.
func isAdmin(ctx context.Context, tx *ent.Tx, userID string, lock bool) (bool, error) {
	if lock {
		if err := store.LockPlatformAdminsShared(ctx, tx); err != nil {
			return false, err
		}
		users, err := tx.User.Query().Where(user.ID(userID), user.DisabledAtIsNil()).ForShare().IDs(ctx)
		if err != nil || len(users) == 0 {
			return false, err
		}
	}
	return tx.PlatformAdmin.Query().Where(platformadmin.UserID(userID), platformadmin.HasUserWith(user.DisabledAtIsNil())).Exist(ctx)
}

// Tenants returns up to limit tenants, newest first, after (afterAt,
// afterID) or from the start if afterID is ""; never the reserved platform
// tenant.
func (s Service) Tenants(ctx context.Context, limit int, afterAt time.Time, afterID string) ([]*ent.Tenant, error) {
	var out []*ent.Tenant
	err := s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		q := tx.Tenant.Query().Where(tenant.IDNEQ(audit.PlatformTenant)).
			Order(ent.Desc(tenant.FieldCreatedAt), ent.Desc(tenant.FieldID)).Limit(limit)
		if afterID != "" {
			q.Where(tenant.Or(tenant.CreatedAtLT(afterAt), tenant.And(tenant.CreatedAt(afterAt), tenant.IDLT(afterID))))
		}
		var err error
		out, err = q.All(ctx)
		return err
	})
	return out, err
}

// WithMembers returns which of tenantIDs have at least one member: one
// query, an index probe per tenant (not a scan of their memberships).
func (s Service) WithMembers(ctx context.Context, tenantIDs ...string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(tenantIDs) == 0 {
		return out, nil
	}
	err := s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT t FROM unnest($1::text[]) t WHERE EXISTS (SELECT 1 FROM memberships m WHERE m.tenant_id = t)`, pgtype.FlatArray[string](tenantIDs))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = true
		}
		return rows.Err()
	})
	return out, err
}

// Created is a new tenant and its owner's invitation. Token is the invite
// link's secret: shown once, only its hash is stored.
type Created struct {
	Tenant     *ent.Tenant
	Invitation *ent.Invitation
	Token      string
	Revoked    int // ReinviteOwner: earlier pending owner invitations revoked
}

// CreateTenant creates a tenant, test mode or live for good (ADR-0047), and an owner invitation (every product,
// invitations.DefaultTTL) for ownerEmail in one transaction (ADR-0042). The
// actor, unless the system, must be an enabled platform admin, rechecked in
// the transaction; then the values are checked. tenant.create goes on the
// platform chain, invitation.create (never the email, ADR-0029) is the new
// tenant's first entry. The actor doesn't join the tenant. Refusals are
// audited on the platform chain.
func (s Service) CreateTenant(ctx context.Context, a Actor, slug, name, ownerEmail string, test bool) (Created, error) {
	ev := a.event("tenant.create", "tenant")
	var c Created
	err := s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		if a.UserID != "" {
			ok, err := isAdmin(ctx, tx, a.UserID, true)
			if err != nil {
				return err
			}
			if !ok {
				return ErrNotAdmin
			}
		}
		if err := valid(slug, name, ownerEmail); err != nil {
			return err
		}
		var err error
		c.Tenant, err = tx.Tenant.Create().SetSlug(slug).SetName(name).SetTest(test).Save(ctx)
		if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.Code == "23505" { // the only unique value: the slug ("platform" included)
			return &InvalidError{Field: "/slug", Message: "already used by another tenant", Conflict: true}
		}
		if err != nil {
			return err
		}
		ev.ObjectID, ev.Outcome = c.Tenant.ID, auditevent.OutcomeSuccess
		ev.Details["slug"], ev.Details["test"] = slug, test
		if _, err := audit.Record(ctx, tx, audit.PlatformTenant, ev); err != nil {
			return err
		}
		c.Invitation, c.Token, err = ownerInvitation(ctx, tx, a, c.Tenant.ID, ownerEmail)
		return err
	})
	if err != nil {
		return Created{}, s.refused(ctx, ev, err)
	}
	return c, nil
}

// ownerInvitation creates an owner invitation (every product,
// invitations.DefaultTTL) for email in tenantID and records invitation.create
// on the tenant's chain (never the email, ADR-0029). It returns the token.
func ownerInvitation(ctx context.Context, tx *ent.Tx, a Actor, tenantID, email string) (*ent.Invitation, string, error) {
	token := rand.Text()
	create := tx.Invitation.Create().SetTenantID(tenantID).SetEmail(email).SetRole(invitation.RoleOwner).SetScopeAll(true).
		SetTokenHash(store.InvitationTokenHash(token)).SetExpiresAt(time.Now().Add(invitations.DefaultTTL))
	if a.UserID != "" {
		create.SetInvitedBy(a.UserID)
	}
	row, err := create.Save(ctx)
	if err != nil {
		return nil, "", err
	}
	inv := a.event("invitation.create", "invitation")
	inv.ObjectID, inv.Outcome = row.ID, auditevent.OutcomeSuccess
	inv.Details["role"], inv.Details["scope_all"], inv.Details["products"] = "owner", true, 0
	inv.Details["expires_at"] = row.ExpiresAt.UTC().Format(time.RFC3339)
	if _, err := audit.Record(ctx, tx, tenantID, inv); err != nil {
		return nil, "", err
	}
	return row, token, nil
}

// ReinviteOwner gives a tenant without an owner a new owner invitation for
// ownerEmail (ADR-0042, amended): when the first was lost or expired. ref is
// the tenant's ID or slug. Every pending owner invitation is revoked; after
// a per-tenant advisory lock (one re-issue at a time) they are locked (the
// lock acceptance takes), then the tenant is checked for members, so a concurrent acceptance either wins (ErrConflict) or
// finds its invitation revoked. Checks, audit and refusals as CreateTenant;
// tenant.owner_invitation goes on the platform chain.
func (s Service) ReinviteOwner(ctx context.Context, a Actor, ref, ownerEmail string) (Created, error) {
	ev := a.event("tenant.owner_invitation", "tenant")
	var c Created
	err := s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		if a.UserID != "" {
			ok, err := isAdmin(ctx, tx, a.UserID, true)
			if err != nil {
				return err
			}
			if !ok {
				return ErrNotAdmin
			}
		}
		if !identity.UsableEmail(ownerEmail) {
			return &InvalidError{Field: "/owner_email", Message: "must be an email address without spaces or invisible characters"}
		}
		var err error
		c.Tenant, err = tx.Tenant.Query().Where(tenant.IDNEQ(audit.PlatformTenant), tenant.Or(tenant.ID(ref), tenant.Slug(ref))).Only(ctx)
		if ent.IsNotFound(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		ev.ObjectID = c.Tenant.ID // a refusal from here on names the tenant only when it has an owner (refused)
		// One re-issue per tenant at a time: another one's new invitation
		// would be invisible to this one's pending query (taken after the
		// first commits) and both would stay open. An advisory lock, not the
		// tenant row: an acceptance's membership insert key-share locks that
		// row while holding its invitation, and never takes this lock.
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.owner_invitation:' || $1, 0))`, c.Tenant.ID); err != nil {
			return err
		}
		pending, err := tx.Invitation.Query().Where(invitation.TenantID(c.Tenant.ID), invitation.RoleEQ(invitation.RoleOwner),
			invitation.AcceptedAtIsNil(), invitation.RevokedAtIsNil()).Order(ent.Asc(invitation.FieldID)).ForUpdate().All(ctx)
		if err != nil {
			return err
		}
		// Any member (a suspended owner too: re-enable that user instead)
		// means the tenant runs its own invitations.
		members, err := tx.Membership.Query().Where(membership.TenantID(c.Tenant.ID)).Exist(ctx)
		if err != nil {
			return err
		}
		if members {
			return &InvalidError{Field: "/", Message: "the tenant has an owner: its owners invite members", Conflict: true}
		}
		ev.ObjectID, ev.Outcome = c.Tenant.ID, auditevent.OutcomeSuccess
		c.Revoked = len(pending)
		ev.Details["slug"], ev.Details["revoked"] = c.Tenant.Slug, c.Revoked
		if _, err := audit.Record(ctx, tx, audit.PlatformTenant, ev); err != nil {
			return err
		}
		for _, p := range pending {
			res, err := tx.ExecContext(ctx, `UPDATE invitations SET revoked_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1`, p.ID)
			if err != nil {
				return err
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 { // locked above: can't change meanwhile
				return errors.Join(errors.New("platform: invitation changed while locked"), err)
			}
			rev := a.event("invitation.revoke", "invitation")
			rev.ObjectID, rev.Outcome = p.ID, auditevent.OutcomeSuccess
			rev.Details["role"] = "owner"
			if _, err := audit.Record(ctx, tx, c.Tenant.ID, rev); err != nil {
				return err
			}
		}
		c.Invitation, c.Token, err = ownerInvitation(ctx, tx, a, c.Tenant.ID, ownerEmail)
		return err
	})
	if err != nil {
		return Created{}, s.refused(ctx, ev, err)
	}
	return c, nil
}

// Refusals at the platform routes' gate (ADR-0042), audited once per session
// on the platform chain: a polling client can't flood it.
const (
	ActionDenied      = "session.platform_denied" // not a platform admin
	ActionMFARequired = "session.mfa_required"    // short of the platform MFA policy (ADR-0038)
)

// RecordSessionRefusal audits action (ActionDenied or ActionMFARequired) for
// userID's session sessionID on the platform chain, unless that session's
// refusal is already there. The check runs first without the chain lock
// (a partial index finds it), so repeats never queue behind the chain's
// writes, then again under the lock, so two replicas can't both record.
func (s Service) RecordSessionRefusal(ctx context.Context, action, userID, sessionID string, details map[string]any) error {
	return s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		exists := func() (bool, error) {
			return tx.AuditEvent.Query().Where(auditevent.TenantID(audit.PlatformTenant), auditevent.Action(action),
				auditevent.ObjectType("session"), auditevent.ObjectID(sessionID)).Exist(ctx)
		}
		if done, err := exists(); err != nil || done {
			return err
		}
		if err := audit.Lock(ctx, tx, audit.PlatformTenant); err != nil {
			return err
		}
		if done, err := exists(); err != nil || done {
			return err
		}
		_, err := audit.Record(ctx, tx, audit.PlatformTenant, audit.Event{ActorType: auditevent.ActorTypeUser, ActorID: userID,
			Action: action, ObjectType: "session", ObjectID: sessionID, Outcome: auditevent.OutcomeDenied, Details: details})
		return err
	})
}

// refused records a refusal on the platform chain, in its own transaction:
// denied for ErrNotAdmin, failure for invalid values and conflicts. Other
// errors (outages) are returned unrecorded.
func (s Service) refused(ctx context.Context, ev audit.Event, err error) error {
	switch {
	case errors.Is(err, ErrNotAdmin):
		ev.Outcome = auditevent.OutcomeDenied
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrConflict), errors.Is(err, ErrNotFound):
		ev.Outcome = auditevent.OutcomeFailure
	default:
		return err
	}
	var inv *InvalidError
	if !errors.As(err, &inv) || inv.Field != "/" {
		ev.ObjectID = "" // kept for a refused re-issue: which tenant (with an owner) it was
	}
	via, cli := ev.Details["via"]
	ev.Details = map[string]any{}
	if cli {
		ev.Details["via"] = via // a CLI refusal stays recognizable
	}
	if rerr := s.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := audit.Record(ctx, tx, audit.PlatformTenant, ev)
		return err
	}); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

func valid(slug, name, email string) error {
	switch {
	case len(slug) > 63 || !schema.SlugRE.MatchString(slug):
		return &InvalidError{Field: "/slug", Message: "lowercase letters and digits joined by single dashes, at most 63"}
	case !utf8.ValidString(name) || strings.TrimSpace(name) == "" || len(name) > 200 || strings.ContainsFunc(name, unicode.IsControl):
		return &InvalidError{Field: "/name", Message: "1 to 200 bytes of text, not blank"}
	case !identity.UsableEmail(email):
		return &InvalidError{Field: "/owner_email", Message: "must be an email address without spaces or invisible characters"}
	}
	return nil
}
