package weblogin

import (
	"context"
	"database/sql"
	"net/http"
	"testing"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/platformadmin"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

// owner runs statements as the schema owner; undo runs at cleanup.
func owner(t *testing.T, undo string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := db.Exec(undo); err != nil {
			t.Error(err)
		}
		_ = db.Close()
	})
}

// entries returns the platform chain after seq, checking that it verifies.
func (f *fixture) entries(t *testing.T, after int64) []*ent.AuditEvent {
	t.Helper()
	ctx := context.Background()
	var out []*ent.AuditEvent
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		if _, err := audit.Verify(ctx, tx, audit.PlatformTenant); err != nil {
			return err
		}
		var err error
		out, err = tx.AuditEvent.Query().Where(auditevent.TenantID(audit.PlatformTenant), auditevent.SeqGT(after)).
			Order(ent.Asc(auditevent.FieldSeq)).All(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *fixture) head(t *testing.T) int64 {
	if es := f.entries(t, 0); len(es) > 0 {
		return es[len(es)-1].Seq
	}
	return 0
}

func (f *fixture) admins(t *testing.T) []*ent.PlatformAdmin {
	t.Helper()
	var out []*ent.PlatformAdmin
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		var err error
		out, err = tx.PlatformAdmin.Query().Order(ent.Asc(platformadmin.FieldCreatedAt)).All(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *fixture) user(t *testing.T, sub string) *ent.User {
	t.Helper()
	u, err := f.ids.Session(context.Background(), f.session(t))
	if err != nil || u.Subject != sub {
		t.Fatalf("session user %+v, %v", u, err)
	}
	return u
}

func TestLoginBootstrapsAndRecords(t *testing.T) {
	sub := ids.New("sub")
	owner(t, `DELETE FROM platform_admins`, `DELETE FROM platform_admins`)
	email := "root-" + storetest.Suffix() + "@example.com" // the issuer|subject form is covered in identity
	f := setupAdmin(t, email)
	claims := map[string]any{"sub": sub, "email": email}
	head := f.head(t)

	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), claims); code != http.StatusSeeOther {
		t.Fatalf("callback: %d", code)
	}
	u := f.user(t, sub)
	if as := f.admins(t); len(as) != 1 || as[0].UserID != u.ID || !as[0].Bootstrap {
		t.Fatalf("admins: %+v", as)
	}
	es := f.entries(t, head)
	if len(es) != 2 || es[0].Action != "platform_admin.bootstrap" || *es[0].ObjectID != u.ID ||
		es[1].Action != "user.login" || es[1].Outcome != auditevent.OutcomeSuccess || *es[1].ActorID != u.ID ||
		es[1].SourceIP == nil || *es[1].SourceIP != "127.0.0.1" || es[1].UserAgent == nil {
		t.Fatalf("platform chain: %+v", es)
	}
	// The next login is recorded, not granted again.
	head = es[1].Seq
	q = f.start(t)
	if code := f.finish(t, q, q.Get("state"), claims); code != http.StatusSeeOther {
		t.Fatalf("second login: %d", code)
	}
	if es := f.entries(t, head); len(es) != 1 || es[0].Action != "user.login" || len(f.admins(t)) != 1 {
		t.Errorf("second login: %+v, %d admins", es, len(f.admins(t)))
	}
}

// A bootstrap that fails is logged; the user still signs in.
func TestFailedBootstrapDoesNotFailLogin(t *testing.T) {
	sub := ids.New("sub")
	owner(t, `ALTER TABLE platform_admins DROP CONSTRAINT test_refuse`,
		`DELETE FROM platform_admins`, `ALTER TABLE platform_admins ADD CONSTRAINT test_refuse CHECK (false) NOT VALID`)
	email := "root-" + storetest.Suffix() + "@example.com"
	f := setupAdmin(t, email)
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), map[string]any{"sub": sub, "email": email}); code != http.StatusSeeOther {
		t.Fatalf("callback with a failing bootstrap: %d", code)
	}
	f.user(t, sub)
	if n := len(f.admins(t)); n != 0 {
		t.Errorf("%d admins", n)
	}
}

// No session without its audit entry (AU-5).
func TestLoginFailsClosedWithoutAudit(t *testing.T) {
	f := setup(t)
	owner(t, `ALTER TABLE audit_events DROP CONSTRAINT test_refuse`,
		`ALTER TABLE audit_events ADD CONSTRAINT test_refuse CHECK (false) NOT VALID`)
	before := countSessions(t)
	q := f.start(t)
	if code := f.finish(t, q, q.Get("state"), nil); code != http.StatusInternalServerError {
		t.Errorf("login without audit: %d", code)
	}
	if f.session(t) != "" || countSessions(t) != before {
		t.Error("a session survived a login that couldn't be recorded")
	}
}

func countSessions(t *testing.T) int {
	t.Helper()
	db, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
