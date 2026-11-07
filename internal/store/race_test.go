package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/store/ids"
)

// raced runs first in transaction A and second in transaction B on two
// connections of login url (tenant "": no app.tenant_id), so that B blocks on
// the row A changed; A then commits and B rechecks the newest row version
// (READ COMMITTED's EvalPlanQual) while subqueries in B's policies still read
// B's snapshot from before A's commit. It returns B's rows affected and error.
func raced(t *testing.T, url, tenant, first, second string, args ...any) (int64, error) {
	t.Helper()
	ctx := context.Background()
	db := sqlOpen(t, url)
	begin := func() *sql.Tx {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Fatal(err)
		}
		return tx
	}
	a := begin()
	if _, err := a.ExecContext(ctx, first, args...); err != nil {
		t.Fatalf("first: %v", err)
	}
	b := begin()
	// On a failure below: release A first, so B's statement returns and
	// B's Rollback doesn't wait for it forever. No-ops after Commit.
	defer func() { _ = a.Rollback(); _ = b.Rollback() }()
	var pid int
	if err := b.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	type result struct {
		n   int64
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := b.ExecContext(ctx, second, args...)
		var n int64
		if err == nil {
			n, err = res.RowsAffected()
		}
		done <- result{n, err}
	}()
	owner := sqlOpen(t, env.OwnerURL)
	var early *result
	for deadline := time.Now().Add(10 * time.Second); early == nil; time.Sleep(10 * time.Millisecond) {
		select {
		case r := <-done: // B didn't wait (refused before reaching the row)
			early = &r
			continue
		default:
		}
		var waiting bool
		if err := owner.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_locks WHERE pid = $1 AND NOT granted)`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("B never blocked on A's row")
		}
	}
	if err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	var r result
	if early != nil {
		r = *early
	} else {
		select {
		case r = <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("B didn't finish")
		}
	}
	if r.err != nil {
		_ = b.Rollback()
		return 0, r.err
	}
	return r.n, b.Commit()
}

// A token's last use never moves back, also not by an update that waited for
// a concurrent use (use_moves_forward compares with its snapshot), plain or
// as an upsert; revocation stays final (not_revoked, platform_no_unrevoke).
func TestTokenPoliciesUnderConcurrentCommits(t *testing.T) {
	f := newIdentityFixture(t)
	owner := sqlOpen(t, env.OwnerURL)
	newToken := func() string {
		tok, err := f.createToken(tokenOpts{creator: f.ownerA, tenant: f.a})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(`UPDATE api_tokens SET last_used_at = now() - interval '3 minutes' WHERE id = $1`, tok.ID); err != nil {
			t.Fatal(err)
		}
		return tok.ID
	}
	state := func(id string) (lastUsed time.Time, revoked bool) {
		var r sql.NullTime
		if err := owner.QueryRow(`SELECT last_used_at, revoked_at FROM api_tokens WHERE id = $1`, id).Scan(&lastUsed, &r); err != nil {
			t.Fatal(err)
		}
		return lastUsed, r.Valid
	}
	recent := func(id string) bool { lu, _ := state(id); return lu.After(time.Now().Add(-30 * time.Second)) }
	use := `UPDATE api_tokens SET last_used_at = clock_timestamp() WHERE id = $1`
	// Older than A's use, newer than B's snapshot: passes a snapshot comparison.
	older := `UPDATE api_tokens SET last_used_at = now() - interval '1 minute' WHERE id = $1`
	upsert := `INSERT INTO api_tokens (id, tenant_id, name, role, scope_all, token_hash, display, created_by, expires_at, created_at, updated_at)
		SELECT id, tenant_id, name, role, scope_all, token_hash, display, created_by, expires_at, clock_timestamp(), clock_timestamp() FROM api_tokens WHERE id = $1
		ON CONFLICT (id) DO UPDATE SET last_used_at = now() - interval '1 minute'`
	for name, second := range map[string]string{"update": older, "upsert": upsert} {
		id := newToken()
		n, err := raced(t, env.TenantURL, f.a, use, second, id)
		if !recent(id) {
			t.Errorf("%s waiting for a use moved last use back (%d rows, %v)", name, n, err)
		}
	}
	revoke := `UPDATE api_tokens SET revoked_at = clock_timestamp() WHERE id = $1 AND revoked_at IS NULL`
	id := newToken()
	if n, err := raced(t, env.TenantURL, f.a, revoke, use, id); err == nil && n != 0 {
		t.Error("a use recorded after a concurrent revocation")
	}
	id = newToken()
	if n, err := raced(t, env.PlatformURL, "", revoke, `UPDATE api_tokens SET revoked_at = NULL WHERE id = $1`, id); err == nil && n != 0 {
		t.Error("the platform un-revoked a token revoked concurrently")
	}
	if _, revoked := state(id); !revoked {
		t.Error("revocation lost")
	}
}

// An export cursor never moves back past a concurrent advance.
func TestCursorForwardUnderConcurrentCommits(t *testing.T) {
	f := newIdentityFixture(t)
	owner := sqlOpen(t, env.OwnerURL)
	for seq := 1; seq <= 10; seq++ {
		if _, err := owner.Exec(`INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, action, outcome, details, prev_hash, hash)
			VALUES ($1, $2, $3, now(), 'system', 'test.entry', 'success', '{}', $4, $4)`, ids.AuditEvent(), f.a, seq, make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
	}
	sink := "race-" + ids.New("x")[2:10]
	if _, err := owner.Exec(`INSERT INTO audit_export_sinks (id, created_at) VALUES ($1, now())`, sink); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DELETE FROM audit_export_sinks WHERE id = $1`, sink) })
	cur := ids.AuditExportCursor()
	if _, err := owner.Exec(`INSERT INTO audit_export_cursors (id, tenant_id, sink_id, seq) VALUES ($1, $2, $3, 5)`, cur, f.a, sink); err != nil {
		t.Fatal(err)
	}
	n, err := raced(t, env.PlatformURL, "", `UPDATE audit_export_cursors SET seq = 10 WHERE id = $1`, `UPDATE audit_export_cursors SET seq = 7 WHERE id = $1`, cur)
	var seq int
	if err := owner.QueryRow(`SELECT seq FROM audit_export_cursors WHERE id = $1`, cur).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	if seq != 10 {
		t.Errorf("cursor moved back past a concurrent advance: %d rows, %v, seq %d", n, err, seq)
	}
}
