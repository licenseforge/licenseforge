package platform

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

// user creates a verified user with email.
func (f fixture) user(t *testing.T, email string) string {
	t.Helper()
	var id string
	if err := f.db.WithIdentity(context.Background(), "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail(email).SetEmailVerified(true).Save(context.Background())
		if err == nil {
			id = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f fixture) accept(token, userID string) error {
	_, err := f.db.AcceptInvitation(context.Background(), token, userID, func(tx *ent.Tx, m *ent.Membership) error {
		_, err := audit.Record(context.Background(), tx, m.TenantID, audit.Event{ActorType: auditevent.ActorTypeUser, ActorID: userID,
			Action: "invitation.accept", ObjectType: "membership", ObjectID: m.ID, Outcome: auditevent.OutcomeSuccess})
		return err
	})
	return err
}

func (f fixture) chain(t *testing.T, tenantID string) []*ent.AuditEvent {
	t.Helper()
	var es []*ent.AuditEvent
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) (err error) {
		es, err = tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID)).Order(ent.Asc(auditevent.FieldSeq)).All(context.Background())
		return
	}); err != nil {
		t.Fatal(err)
	}
	return es
}

func TestReinviteOwner(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	slug := "lost-" + storetest.Suffix()
	first, err := f.s.CreateTenant(ctx, Actor{UserID: f.admin}, slug, "Lost Link", "typo@lost.example")
	if err != nil {
		t.Fatal(err)
	}
	// By slug, with a corrected address.
	again, err := f.s.ReinviteOwner(ctx, Actor{UserID: f.admin}, slug, "owner@lost.example")
	if err != nil {
		t.Fatal(err)
	}
	if again.Tenant.ID != first.Tenant.ID || again.Invitation.Email != "owner@lost.example" || again.Token == first.Token || !again.Invitation.ScopeAll ||
		*again.Invitation.InvitedBy != f.admin || time.Until(again.Invitation.ExpiresAt) < 6*24*time.Hour {
		t.Fatalf("re-issued %+v", again)
	}
	// The first link no longer works; the new one does.
	if err := f.accept(first.Token, f.user(t, "typo@lost.example")); !errors.Is(err, store.ErrInvitation) {
		t.Errorf("first link: %v", err)
	}
	if err := f.accept(again.Token, f.user(t, "owner@lost.example")); err != nil {
		t.Fatalf("new link: %v", err)
	}
	// With an owner, the tenant runs its own invitations.
	if _, err := f.s.ReinviteOwner(ctx, Actor{UserID: f.admin}, first.Tenant.ID, "x@lost.example"); !errors.Is(err, ErrConflict) {
		t.Errorf("tenant with an owner: %v", err)
	}
	conflict := 0 // the refusal names the tenant with an owner
	for _, e := range f.chain(t, audit.PlatformTenant) {
		if e.Action == "tenant.owner_invitation" && e.Outcome == auditevent.OutcomeFailure && e.ObjectID != nil && *e.ObjectID == first.Tenant.ID {
			conflict++
		}
	}
	if conflict != 1 {
		t.Errorf("%d conflict refusals naming the tenant", conflict)
	}
	es := f.chain(t, first.Tenant.ID)
	var actions []string
	for _, e := range es {
		actions = append(actions, e.Action)
		if strings.Contains(e.Details, "lost.example") {
			t.Errorf("an email on the tenant chain: %+v", e)
		}
	}
	if strings.Join(actions, ",") != "invitation.create,invitation.revoke,invitation.create,invitation.accept" ||
		*es[1].ObjectID != first.Invitation.ID || *es[2].ObjectID != again.Invitation.ID {
		t.Errorf("tenant chain %v", actions)
	}
	var issued, refused int
	for _, e := range f.chain(t, audit.PlatformTenant) {
		if e.Action == "tenant.owner_invitation" && e.ObjectID != nil && *e.ObjectID == first.Tenant.ID && e.Outcome == auditevent.OutcomeSuccess &&
			strings.Contains(e.Details, `"revoked":1`) {
			issued++
		}
		if e.Action == "tenant.owner_invitation" && e.Outcome == auditevent.OutcomeFailure {
			refused++
		}
	}
	if issued != 1 || refused == 0 {
		t.Errorf("platform chain: %d issued, %d refused", issued, refused)
	}
	// The CLI's system actor.
	c, err := f.s.CreateTenant(ctx, Actor{}, "cli-"+storetest.Suffix(), "Via CLI", "o@cli.example")
	if err != nil {
		t.Fatal(err)
	}
	if r, err := f.s.ReinviteOwner(ctx, Actor{}, c.Tenant.Slug, "o@cli.example"); err != nil || r.Invitation.InvitedBy != nil || r.Revoked != 1 {
		t.Errorf("system actor: %+v, %v", r.Invitation, err)
	}
	if _, err := f.s.ReinviteOwner(ctx, Actor{}, c.Tenant.Slug, "not an email"); !errors.Is(err, ErrInvalid) {
		t.Errorf("CLI refusal: %v", err)
	}
	via := map[auditevent.Outcome]bool{}
	for _, e := range f.chain(t, audit.PlatformTenant) {
		if e.Action == "tenant.owner_invitation" && e.ActorType == auditevent.ActorTypeSystem && strings.Contains(e.Details, `"via":"cli"`) {
			via[e.Outcome] = true
		}
	}
	if !via[auditevent.OutcomeSuccess] || !via[auditevent.OutcomeFailure] {
		t.Errorf("CLI entries without via: %v", via)
	}
}

// An expired owner invitation is revoked too; several pending ones all are.
func TestReinviteRevokesEveryPending(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c, err := f.s.CreateTenant(ctx, Actor{UserID: f.admin}, "exp-"+storetest.Suffix(), "Expired", "o@exp.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE invitations SET created_at = now() - interval '9 days', expires_at = now() - interval '2 days' WHERE id = $1`, c.Invitation.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r, err := f.s.ReinviteOwner(ctx, Actor{UserID: f.admin}, c.Tenant.ID, "o@exp.example")
	if err != nil || r.Revoked != 1 {
		t.Fatalf("expired: %d revoked, %v", r.Revoked, err)
	}
	if err := f.accept(c.Token, f.user(t, "o@exp.example")); !errors.Is(err, store.ErrInvitation) {
		t.Errorf("expired link: %v", err)
	}
}

// Two re-issues at once leave one open owner invitation: they take turns
// (deterministic: both are seen waiting before the first may proceed).
func TestConcurrentReinvites(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c, err := f.s.CreateTenant(ctx, Actor{UserID: f.admin}, "twice-"+storetest.Suffix(), "Twice", "o@twice.example")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	done := make(chan Created, 2)
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT 1 FROM invitations WHERE id = $1 FOR UPDATE`, c.Invitation.ID); err != nil {
			return err
		}
		for range 2 {
			go func() {
				r, err := f.s.ReinviteOwner(ctx, Actor{UserID: f.admin}, c.Tenant.ID, "o@twice.example")
				if err != nil {
					t.Error(err)
				}
				done <- r
			}()
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			var n int
			if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
				WHERE NOT l.granted AND a.datname = $1`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n >= 2 {
				return nil // both wait: release the invitation
			}
			if time.Now().After(deadline) {
				return errors.New("the re-issues never both waited")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}); err != nil {
		t.Fatal(err)
	}
	<-done
	<-done
	var open int
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) (err error) {
		open, err = tx.Invitation.Query().Where(invitation.TenantID(c.Tenant.ID), invitation.AcceptedAtIsNil(), invitation.RevokedAtIsNil()).Count(ctx)
		return
	}); err != nil {
		t.Fatal(err)
	}
	if open != 1 {
		t.Errorf("%d open owner invitations after two re-issues", open)
	}
}

func TestReinviteOwnerRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c, err := f.s.CreateTenant(ctx, Actor{UserID: f.admin}, "ref-"+storetest.Suffix(), "Refusals", "o@ref.example")
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.chain(t, audit.PlatformTenant))
	for name, tc := range map[string]struct {
		a     Actor
		ref   string
		email string
		want  error
	}{
		"not an admin":    {Actor{UserID: f.other}, c.Tenant.ID, "o@ref.example", ErrNotAdmin},
		"disabled admin":  {Actor{UserID: f.gone}, c.Tenant.ID, "o@ref.example", ErrNotAdmin},
		"unknown tenant":  {Actor{UserID: f.admin}, "no-such-" + storetest.Suffix(), "o@ref.example", ErrNotFound},
		"platform tenant": {Actor{UserID: f.admin}, audit.PlatformTenant, "o@ref.example", ErrNotFound},
		"bad email":       {Actor{UserID: f.admin}, c.Tenant.ID, "not an email", ErrInvalid},
	} {
		if _, err := f.s.ReinviteOwner(ctx, tc.a, tc.ref, tc.email); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
	// Each refusal is on the platform chain: denied for the non-admins,
	// failure for the rest, without the tenant.
	outcomes := map[auditevent.Outcome]int{}
	for _, e := range f.chain(t, audit.PlatformTenant)[before:] {
		if e.Action == "tenant.owner_invitation" && e.ObjectID == nil {
			outcomes[e.Outcome]++
		}
	}
	if outcomes[auditevent.OutcomeDenied] != 2 || outcomes[auditevent.OutcomeFailure] != 3 {
		t.Errorf("refusals recorded: %v", outcomes)
	}
	// None of them touched the pending invitation.
	if err := f.accept(c.Token, f.user(t, "o@ref.example")); err != nil {
		t.Errorf("the first link after refusals: %v", err)
	}
}

// An acceptance holding its invitation wins over a concurrent re-issue,
// which then finds an owner (deterministic: the re-issue is seen waiting on
// the invitation's lock before the acceptance commits).
func TestReinviteRacesAcceptance(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c, err := f.s.CreateTenant(ctx, Actor{UserID: f.admin}, "race-"+storetest.Suffix(), "Race", "o@race.example")
	if err != nil {
		t.Fatal(err)
	}
	owner := f.user(t, "o@race.example")
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	reissued := make(chan error, 1)
	_, err = f.db.AcceptInvitation(ctx, c.Token, owner, func(tx *ent.Tx, m *ent.Membership) error {
		go func() {
			_, err := f.s.ReinviteOwner(ctx, Actor{UserID: f.admin}, c.Tenant.ID, "o@race.example")
			reissued <- err
		}()
		deadline := time.Now().Add(10 * time.Second)
		for {
			var n int
			if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
				WHERE l.locktype IN ('tuple', 'transactionid') AND NOT l.granted AND a.datname = $1`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("the re-issue never waited on the invitation")
			}
			time.Sleep(5 * time.Millisecond)
		}
		_, err := audit.Record(ctx, tx, m.TenantID, audit.Event{ActorType: auditevent.ActorTypeUser, ActorID: owner,
			Action: "invitation.accept", ObjectType: "membership", ObjectID: m.ID, Outcome: auditevent.OutcomeSuccess})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-reissued; !errors.Is(err, ErrConflict) {
		t.Errorf("re-issue after the acceptance: %v", err)
	}
}
