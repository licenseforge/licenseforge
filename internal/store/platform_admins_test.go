package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// These tests own platform_admins (global): each starts from an empty table.
func emptyAdmins(t *testing.T, f identityFixture) {
	t.Helper()
	f.owner(t, `DELETE FROM platform_admins`)
	t.Cleanup(func() { f.owner(t, `DELETE FROM platform_admins`) })
}

func noAudit(*ent.Tx) error { return nil }

func (f identityFixture) admins(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.d.WithIdentity(context.Background(), "", func(tx *ent.Tx) error {
		var err error
		n, err = tx.PlatformAdmin.Query().Count(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// waitAdvisoryWaiters waits until n sessions wait on an advisory lock.
func (f identityFixture) waitAdvisoryWaiters(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := f.d.platformDB.QueryRowContext(context.Background(),
			`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d sessions waiting on the lock, want %d", waiting, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestBootstrapPlatformAdmin(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	emptyAdmins(t, f)
	// A failing record undoes the grant; a disabled user is never bootstrapped.
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerA, func(*ent.Tx) error { return context.Canceled }); ok || err == nil {
		t.Fatalf("grant kept after record failed: %v %v", ok, err)
	}
	disabled := f.newUser(t, "dis@example.com", true)
	f.platform(t, `UPDATE users SET disabled_at = now() WHERE id = $1`, disabled)
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, disabled, noAudit); ok || err != nil || f.admins(t) != 0 {
		t.Fatalf("disabled user bootstrapped: %v %v", ok, err)
	}
	// Replicas bootstrapping at once, for different users: the first holds
	// its transaction open (in record) until the others wait on the lock.
	inside, release := make(chan struct{}), make(chan struct{})
	first := make(chan bool, 1)
	go func() {
		ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerA, func(*ent.Tx) error { close(inside); <-release; return nil })
		if err != nil {
			t.Error(err)
		}
		first <- ok
	}()
	select {
	case <-inside:
	case <-time.After(10 * time.Second):
		t.Fatal("first bootstrap didn't grant")
	}
	others := make(chan bool, 3)
	var wg sync.WaitGroup
	for range 3 {
		u := f.newUser(t, ids.New("x")+"@example.com", true)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.d.BootstrapPlatformAdmin(ctx, u, noAudit)
			if err != nil {
				t.Error(err)
			}
			others <- ok
		}()
	}
	f.waitAdvisoryWaiters(t, 3)
	close(release)
	wg.Wait()
	close(others)
	granted := 0
	if <-first {
		granted++
	}
	for ok := range others {
		if ok {
			granted++
		}
	}
	if granted != 1 || f.admins(t) != 1 {
		t.Errorf("granted %d times (%d admins), want 1", granted, f.admins(t))
	}
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerB, noAudit); ok || err != nil {
		t.Errorf("second bootstrap: %v %v", ok, err)
	}
}

func TestPlatformAdminGrantsAndRemoval(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	emptyAdmins(t, f)
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerA, noAudit); !ok || err != nil {
		t.Fatal(ok, err)
	}
	// Only an admin grants; a bootstrap-shaped grant isn't possible any more.
	if err := f.d.GrantPlatformAdmin(ctx, f.ownerB, ids.User(), noAudit); err == nil || !strings.Contains(err.Error(), "grant_shape") {
		t.Errorf("grant by a non-admin: %v", err)
	}
	err := f.d.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := tx.PlatformAdmin.Create().SetUserID(f.ownerB).SetBootstrap(true).Save(ctx)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "grant_shape") {
		t.Errorf("second bootstrap-shaped grant: %v", err)
	}
	if err := f.d.GrantPlatformAdmin(ctx, f.ownerB, f.ownerA, noAudit); err != nil {
		t.Fatal(err)
	}
	// Two admins removing each other at once: one removal wins.
	errs := make(chan error, 2)
	for _, u := range []string{f.ownerA, f.ownerB} {
		go func() { errs <- f.d.RemovePlatformAdmin(ctx, u, noAudit) }()
	}
	var ok, last int
	for range 2 {
		switch err := <-errs; {
		case err == nil:
			ok++
		case errors.Is(err, ErrLastPlatformAdmin):
			last++
		default:
			t.Error(err)
		}
	}
	if ok != 1 || last != 1 || f.admins(t) != 1 {
		t.Errorf("ok=%d last=%d admins=%d, want 1 1 1", ok, last, f.admins(t))
	}
	// The database refuses removing the last one even without the function.
	f.platform(t, `DELETE FROM platform_admins`)
	if f.admins(t) != 1 {
		t.Error("the last admin was deleted on the platform pool")
	}
}

// Erasing a platform admin needs their admin row removed first (ADR-0031).
func TestErasingPlatformAdminIsRefused(t *testing.T) {
	f := newIdentityFixture(t)
	emptyAdmins(t, f)
	u := f.newUser(t, "pa@example.com", true)
	if ok, err := f.d.BootstrapPlatformAdmin(context.Background(), u, noAudit); !ok || err != nil {
		t.Fatal(ok, err)
	}
	db, err := openPool(env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, u); err == nil || !strings.Contains(err.Error(), "platform_admin") {
		t.Errorf("erasing a platform admin: %v", err)
	}
}

// Tenants never see platform admins; identity only reads them.
func TestPlatformAdminsAccess(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	for name, run := range map[string]func() error{
		"tenant read": func() error {
			return f.d.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
				_, err := tx.ExecContext(ctx, `SELECT 1 FROM platform_admins`)
				return err
			})
		},
		"identity insert": func() error {
			return f.d.WithIdentity(ctx, "", func(tx *ent.Tx) error {
				_, err := tx.ExecContext(ctx, `INSERT INTO platform_admins (id, user_id, bootstrap, created_at) VALUES ('pad_aaaaaaaaaaaaaaaaaaaaaaaaaa', $1, true, now())`, f.ownerA)
				return err
			})
		},
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: %v, want permission denied", name, err)
		}
	}
}
