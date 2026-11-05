package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// Reads are recorded once per reader per window: a denied attempt doesn't
// count as a read, and an expired window records again.
func TestListRecordsReads(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	l := Log{DB: d}
	reads := func() int {
		t.Helper()
		var n int
		if err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) (err error) {
			n, err = tx.AuditEvent.Query().Where(auditevent.Action("audit_event.read"), auditevent.OutcomeEQ(auditevent.OutcomeSuccess)).Count(context.Background())
			return
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	p := authz.Principal{Kind: authz.User, ID: "usr_1", TenantID: tn, Role: authz.Viewer, Scope: authz.Scope{All: true}}
	if _, err := l.List(context.Background(), p, Page{Limit: 10}); err == nil {
		t.Fatal("viewer read the log")
	}
	p.Role = authz.Admin // the same user, promoted: the denied attempt wasn't a read
	for range 2 {
		if _, err := l.List(context.Background(), p, Page{Limit: 10}); err != nil {
			t.Fatal(err)
		}
	}
	if n := reads(); n != 1 {
		t.Fatalf("%d reads recorded, want 1", n)
	}
	defer func(w string) { readWindow = w }(readWindow)
	readWindow = "0 seconds"
	if _, err := l.List(context.Background(), p, Page{Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if n := reads(); n != 2 {
		t.Errorf("after the window: %d reads recorded, want 2", n)
	}
}

// Concurrent first reads by one reader record one entry: the check is
// repeated under the chain's lock.
func TestConcurrentReadsRecordOnce(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	l := Log{DB: d}
	p := authz.Principal{Kind: authz.User, ID: "usr_1", TenantID: tn, Role: authz.Admin, Scope: authz.Scope{All: true}}
	var wg sync.WaitGroup
	errs := make([]error, 20)
	for i := range errs {
		wg.Go(func() { _, errs[i] = l.List(context.Background(), p, Page{Limit: 10}) })
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	var n int
	if err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) (err error) {
		n, err = tx.AuditEvent.Query().Where(auditevent.Action("audit_event.read")).Count(context.Background())
		return
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d read entries, want 1", n)
	}
}

// A read whose entry can't be written returns no entries (fail closed,
// ADR-0027).
func TestReadFailsWithoutItsEntry(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	record(t, d, tn, ev)
	defer func(r func(context.Context, *ent.Tx, string, Event) (*ent.AuditEvent, error)) { recordRead = r }(recordRead)
	recordRead = func(context.Context, *ent.Tx, string, Event) (*ent.AuditEvent, error) {
		return nil, errors.New("audit down")
	}
	p := authz.Principal{Kind: authz.User, ID: "usr_1", TenantID: tn, Role: authz.Admin, Scope: authz.Scope{All: true}}
	if es, err := (Log{DB: d}).List(context.Background(), p, Page{Limit: 10}); err == nil || es != nil {
		t.Errorf("List = %v, %v; want an error and no entries", es, err)
	}
}

// The re-check runs under the chain's lock: a read entry committed by a
// transaction that held the lock while this read waited is seen, and no
// second entry is written.
func TestReadRechecksUnderTheLock(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	ctx := context.Background()
	p := authz.Principal{Kind: authz.User, ID: "usr_1", TenantID: tn, Role: authz.Admin, Scope: authz.Scope{All: true}}
	held, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- d.WithTenant(ctx, tn, func(tx *ent.Tx) error {
			_, err := Record(ctx, tx, tn, Event{ActorType: auditevent.ActorTypeUser, ActorID: p.ID, Action: "audit_event.read", Outcome: auditevent.OutcomeSuccess})
			close(held)
			<-release
			return err
		})
	}()
	<-held
	read := make(chan error, 1)
	go func() { _, err := (Log{DB: d}).List(ctx, p, Page{Limit: 10}); read <- err }()
	// Commit once the read waits on a lock (the chain's).
	for deadline := time.Now().Add(10 * time.Second); ; {
		var n int
		if err := d.WithTenant(ctx, tn, func(tx *ent.Tx) error {
			rows, err := tx.QueryContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			rows.Next()
			return rows.Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatal("the read never waited on a lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-read; err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.WithTenant(ctx, tn, func(tx *ent.Tx) (err error) {
		n, err = tx.AuditEvent.Query().Where(auditevent.Action("audit_event.read")).Count(ctx)
		return
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("%d read entries, want 1", n)
	}
}
