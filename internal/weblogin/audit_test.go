package weblogin

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/identity"
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
	// The bootstrap was attempted and failed on the database's refusal.
	if logs := f.logs.String(); !strings.Contains(logs, `msg="bootstrap platform admin"`) || !strings.Contains(logs, "test_refuse") {
		t.Errorf("no failed bootstrap in the log:\n%s", logs)
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

// lockedBuffer collects the handler's log; requests write it concurrently.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// A user disabled after Login but before the session (here: while the
// bootstrap waits on the admin-set lock) is refused and the refusal recorded.
func TestDisabledBeforeSessionIsRefused(t *testing.T) {
	ctx := context.Background()
	sub := ids.New("sub")
	email := "late-" + storetest.Suffix() + "@example.com"
	owner(t, `DELETE FROM platform_admins`, `DELETE FROM platform_admins`)
	f := setupAdmin(t, email)
	u, err := f.ids.Login(ctx, identity.Claims{Issuer: f.idp.srv.URL, Subject: sub, Email: email, EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	head := f.head(t)

	// Hold the admin-set lock (store.platformAdminLock) so the callback stops in Bootstrap.
	lock, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	conn, err := lock.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	const adminLock = 0x4C46_5041_444D
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, adminLock); err != nil {
		t.Fatal(err)
	}
	q := f.start(t)
	type result struct {
		code int
		err  error
	}
	done := make(chan result, 1)
	callback := f.callbackURL(q, q.Get("state"), map[string]any{"sub": sub, "email": email})
	go func() { // no t.Fatal here: report back to the test goroutine
		resp, err := f.client.Get(callback)
		if err != nil {
			done <- result{err: err}
			return
		}
		_ = resp.Body.Close()
		done <- result{code: resp.StatusCode}
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		var waiting int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
			AND ((classid::bigint << 32) | objid::bigint) = $1`, int64(adminLock)).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the callback never reached the bootstrap")
		}
	}
	if err := f.db.DisableUser(ctx, u.ID, func(*ent.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, adminLock); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil || r.code != http.StatusForbidden {
			t.Errorf("callback: %d %v, want 403", r.code, r.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("callback didn't return")
	}
	if f.session(t) != "" || len(f.admins(t)) != 0 {
		t.Error("disabled user got a session or the admin role")
	}
	if es := f.entries(t, head); len(es) != 1 || es[0].Outcome != auditevent.OutcomeDenied || *es[0].ActorID != u.ID ||
		es[0].Details != `{"reason":"user_disabled"}` {
		t.Errorf("platform chain: %+v", es)
	}
}
