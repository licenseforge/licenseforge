package identity

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/internal/store/ent"
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
	if _, err := s.NewSession(ctx, u.ID); err == nil || !strings.Contains(err.Error(), "new_session") {
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
