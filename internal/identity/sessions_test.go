package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func TestSessions(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub()})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := s.NewSession(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cookie) != cookieLen {
		t.Errorf("cookie length %d", len(cookie))
	}
	got, err := s.Session(ctx, cookie)
	if err != nil || got.ID != u.ID {
		t.Fatalf("Session = %v, %v", got, err)
	}
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	age := func(q string) {
		t.Helper()
		if _, err := owner.Exec(q+` WHERE token_hash = $1`, sessionHash(cookie)); err != nil {
			t.Fatal(err)
		}
	}
	// Activity is recorded by the database clock, at most once a minute.
	seen := func() (ago float64) {
		t.Helper()
		if err := owner.QueryRow(`SELECT extract(epoch FROM now() - last_seen_at) FROM sessions WHERE token_hash = $1`, sessionHash(cookie)).Scan(&ago); err != nil {
			t.Fatal(err)
		}
		return ago
	}
	age(`UPDATE sessions SET last_seen_at = now() - interval '30 minutes'`)
	if _, err := s.Session(ctx, cookie); err != nil {
		t.Fatal(err)
	}
	if ago := seen(); ago > 5 {
		t.Errorf("activity not recorded: last seen %vs ago", ago)
	}
	age(`UPDATE sessions SET last_seen_at = now() - interval '30 seconds'`)
	if _, err := s.Session(ctx, cookie); err != nil {
		t.Fatal(err)
	}
	if ago := seen(); ago < 25 {
		t.Errorf("activity written more than once a minute: last seen %vs ago", ago)
	}
	// Activity keeps it alive; idle too long ends it.
	age(`UPDATE sessions SET last_seen_at = now() - interval '59 minutes'`)
	if _, err := s.Session(ctx, cookie); err != nil {
		t.Errorf("active session refused: %v", err)
	}
	age(`UPDATE sessions SET last_seen_at = now() - interval '61 minutes'`)
	if _, err := s.Session(ctx, cookie); !errors.Is(err, ErrNoSession) {
		t.Errorf("idle session: %v", err)
	}
	// Absolute expiry.
	age(`UPDATE sessions SET last_seen_at = now(), created_at = now() - interval '13 hours', expires_at = now() - interval '1 hour'`)
	if _, err := s.Session(ctx, cookie); !errors.Is(err, ErrNoSession) {
		t.Errorf("expired session: %v", err)
	}
	// Unknown and malformed cookies.
	for _, c := range []string{"", "short", strings.Repeat("a", cookieLen)} {
		if _, err := s.Session(ctx, c); !errors.Is(err, ErrNoSession) {
			t.Errorf("cookie %q: %v", c, err)
		}
	}
	// Logout ends it.
	cookie2, err := s.NewSession(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EndSession(ctx, cookie2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, cookie2); !errors.Is(err, ErrNoSession) {
		t.Errorf("after logout: %v", err)
	}
	// Suspension ends every session at once and refuses new ones.
	cookie3, err := s.NewSession(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.DisableUser(ctx, u.ID, func(*ent.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, cookie3); !errors.Is(err, ErrNoSession) {
		t.Errorf("session of a suspended user: %v", err)
	}
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM sessions WHERE user_id = $1`, u.ID).Scan(&n); err != nil || n != 0 {
		t.Errorf("sessions left after suspension: %d %v", n, err)
	}
	if _, err := s.NewSession(ctx, u.ID); !errors.Is(err, ErrDisabled) {
		t.Errorf("new session for a suspended user: %v", err)
	}
	if err := d.DisableUser(ctx, u.ID, func(*ent.Tx) error { return nil }); err == nil {
		t.Error("disabling twice")
	}
}

// A user disabled without DisableUser (directly on the platform pool) has
// no live session either: the lookup checks the user too.
func TestSessionOfUserDisabledDirectly(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub()})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := s.NewSession(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, u.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, cookie); !errors.Is(err, ErrNoSession) {
		t.Errorf("session of a disabled user: %v", err)
	}
}

// Tenants never see sessions.
func TestTenantPoolCantSeeSessions(t *testing.T) {
	_, d := open(t)
	err := d.WithTenant(context.Background(), "tnt_aaaaaaaaaaaaaaaaaaaaaaaaaa", func(tx *ent.Tx) error {
		_, err := tx.ExecContext(context.Background(), `SELECT 1 FROM sessions`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("tenant read sessions: %v", err)
	}
}

// The database refuses sessions that don't start now, outlast a day, or
// belong to a disabled user, even from the identity pool directly.
func TestNewSessionPolicy(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub()})
	if err != nil {
		t.Fatal(err)
	}
	insert := func(created, expires, seen string) error {
		return d.WithIdentity(ctx, "", func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at)
				VALUES ($1, $2, $3, `+created+`, `+expires+`, `+seen+`)`, ids.Session(), u.ID, sessionHash(sub()))
			return err
		})
	}
	const now, later = "clock_timestamp()", "clock_timestamp() + interval '12 hours'"
	if err := insert(now, later, now); err != nil {
		t.Fatalf("valid session refused: %v", err)
	}
	for name, c := range map[string][3]string{
		"created in the past": {"clock_timestamp() - interval '1 hour'", later, now},
		"seen in the future":  {now, later, "clock_timestamp() + interval '1 hour'"},
		"longer than a day":   {"clock_timestamp() + interval '1 minute'", "clock_timestamp() + interval '25 hours'", now},
	} {
		if err := insert(c[0], c[1], c[2]); err == nil || !strings.Contains(err.Error(), "new_session") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = now() WHERE id = $1`, u.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := insert(now, later, now); err == nil || !strings.Contains(err.Error(), "new_session") {
		t.Errorf("session for a disabled user: %v", err)
	}
}

// A session started while DisableUser is running doesn't survive it: either
// DisableUser deletes it, or NewSession waits and sees the user disabled.
func TestNewSessionDuringDisable(t *testing.T) {
	s, d := open(t)
	ctx := context.Background()
	u, err := s.Login(ctx, Claims{Issuer: "https://idp.example", Subject: sub()})
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", env.AdminURL) // sees other logins' queries
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	done := make(chan error, 1)
	if err := d.DisableUser(ctx, u.ID, func(*ent.Tx) error {
		// users is updated and sessions deleted, not yet committed: NewSession
		// must wait for this transaction (proven by its lock wait).
		go func() { _, err := s.NewSession(ctx, u.ID); done <- err }()
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			var waiting int
			if err := admin.QueryRow(`SELECT count(*) FROM pg_stat_activity
				WHERE datname = $1 AND wait_event_type = 'Lock' AND query LIKE '%FOR SHARE%'`, env.Name).Scan(&waiting); err != nil {
				return err
			}
			if waiting > 0 {
				return nil
			}
			select {
			case err := <-done:
				return fmt.Errorf("NewSession didn't wait for DisableUser: %v", err)
			default:
			}
			if time.Now().After(deadline) {
				return errors.New("NewSession never waited")
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, ErrDisabled) {
		t.Errorf("NewSession during DisableUser: %v", err)
	}
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	var n int
	if err := owner.QueryRow(`SELECT count(*) FROM sessions WHERE user_id = $1`, u.ID).Scan(&n); err != nil || n != 0 {
		t.Errorf("sessions left after suspension: %d %v", n, err)
	}
}
