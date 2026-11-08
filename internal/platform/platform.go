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

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/invitations"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ent/platformadmin"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/ent/user"
	"licenseforge.io/licenseforge/internal/store/schema"
)

var (
	// ErrNotAdmin: the caller isn't an enabled platform admin.
	ErrNotAdmin = errors.New("platform: not a platform admin")
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
// CLI on the platform login).
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

// Created is a new tenant and its owner's invitation. Token is the invite
// link's secret: shown once, only its hash is stored.
type Created struct {
	Tenant     *ent.Tenant
	Invitation *ent.Invitation
	Token      string
}

// CreateTenant creates a tenant and an owner invitation (every product,
// invitations.DefaultTTL) for ownerEmail in one transaction (ADR-0042). The
// actor, unless the system, must be an enabled platform admin, rechecked in
// the transaction; then the values are checked. tenant.create goes on the
// platform chain, invitation.create (never the email, ADR-0029) is the new
// tenant's first entry. The actor doesn't join the tenant. Refusals are
// audited on the platform chain.
func (s Service) CreateTenant(ctx context.Context, a Actor, slug, name, ownerEmail string) (Created, error) {
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
		c.Tenant, err = tx.Tenant.Create().SetSlug(slug).SetName(name).Save(ctx)
		if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.Code == "23505" { // the only unique value: the slug ("platform" included)
			return &InvalidError{Field: "/slug", Message: "already used by another tenant", Conflict: true}
		}
		if err != nil {
			return err
		}
		c.Token = rand.Text()
		create := tx.Invitation.Create().SetTenantID(c.Tenant.ID).SetEmail(ownerEmail).SetRole(invitation.RoleOwner).SetScopeAll(true).
			SetTokenHash(store.InvitationTokenHash(c.Token)).SetExpiresAt(time.Now().Add(invitations.DefaultTTL))
		if a.UserID != "" {
			create.SetInvitedBy(a.UserID)
		}
		if c.Invitation, err = create.Save(ctx); err != nil {
			return err
		}
		ev.ObjectID, ev.Outcome = c.Tenant.ID, auditevent.OutcomeSuccess
		ev.Details["slug"] = slug
		if _, err := audit.Record(ctx, tx, audit.PlatformTenant, ev); err != nil {
			return err
		}
		inv := a.event("invitation.create", "invitation")
		inv.ObjectID, inv.Outcome = c.Invitation.ID, auditevent.OutcomeSuccess
		inv.Details["role"], inv.Details["scope_all"], inv.Details["products"] = "owner", true, 0
		inv.Details["expires_at"] = c.Invitation.ExpiresAt.UTC().Format(time.RFC3339)
		_, err = audit.Record(ctx, tx, c.Tenant.ID, inv)
		return err
	})
	if err != nil {
		return Created{}, s.refused(ctx, ev, err)
	}
	return c, nil
}

// refused records a refusal on the platform chain, in its own transaction:
// denied for ErrNotAdmin, failure for invalid values and conflicts. Other
// errors (outages) are returned unrecorded.
func (s Service) refused(ctx context.Context, ev audit.Event, err error) error {
	switch {
	case errors.Is(err, ErrNotAdmin):
		ev.Outcome = auditevent.OutcomeDenied
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrConflict):
		ev.Outcome = auditevent.OutcomeFailure
	default:
		return err
	}
	ev.ObjectID = ""
	ev.Details = map[string]any{}
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
