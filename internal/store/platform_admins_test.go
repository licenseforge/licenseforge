package store

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func TestBootstrapPlatformAdmin(t *testing.T) {
	f := newIdentityFixture(t)
	ctx := context.Background()
	// Platform admins are global, so start from an empty table.
	f.owner(t, `DELETE FROM platform_admins`)
	t.Cleanup(func() { f.owner(t, `DELETE FROM platform_admins`) })
	noAudit := func(*ent.Tx) error { return nil }
	// A failing record undoes the grant.
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerA, func(*ent.Tx) error { return context.Canceled }); ok || err == nil {
		t.Fatalf("grant kept after record failed: %v %v", ok, err)
	}
	// Replicas bootstrapping at once, for different users: the first holds its
	// transaction open (in record) while the others try; exactly one admin.
	inside, release := make(chan struct{}), make(chan struct{})
	first := make(chan bool, 1)
	go func() {
		ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerA, func(*ent.Tx) error { close(inside); <-release; return nil })
		if err != nil {
			t.Error(err)
		}
		first <- ok
	}()
	<-inside
	others := make(chan bool, 3)
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.d.BootstrapPlatformAdmin(ctx, f.newUser(t, ids.New("x")+"@example.com", true), noAudit)
			if err != nil {
				t.Error(err)
			}
			others <- ok
		}()
	}
	time.Sleep(300 * time.Millisecond) // the others reach the lock (or, without it, insert)
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
	if granted != 1 {
		t.Errorf("granted %d times, want 1", granted)
	}
	// Not while one exists, even for another user.
	if ok, err := f.d.BootstrapPlatformAdmin(ctx, f.ownerB, noAudit); ok || err != nil {
		t.Errorf("second bootstrap: %v %v", ok, err)
	}
	// (With every admin removed the table is empty again, and the bootstrap
	// user is granted on next login: the documented recovery path.)
	var n int
	if err := f.d.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		var err error
		n, err = tx.PlatformAdmin.Query().Count(ctx)
		return err
	}); err != nil || n != 1 {
		t.Errorf("identity reads platform admins: %d %v", n, err)
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
				_, err := tx.ExecContext(ctx, `INSERT INTO platform_admins (id, user_id, created_at) VALUES ('pad_aaaaaaaaaaaaaaaaaaaaaaaaaa', $1, now())`, f.ownerA)
				return err
			})
		},
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: %v, want permission denied", name, err)
		}
	}
}
