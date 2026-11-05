package store

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// heldBy counts sessions holding advisory lock key in the test database.
func heldBy(t *testing.T, key int64) int {
	t.Helper()
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	var n int
	if err := admin.QueryRow(`SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted
		AND ((classid::bigint << 32) | objid::bigint) = $1
		AND database = (SELECT oid FROM pg_database WHERE datname = $2)`, key, env.Name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

const testLockKey = 0x4C46_5445_5354 // "LFTEST"

func TestSessionLock(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()
	l, ok, err := d.TryPlatformLock(ctx, testLockKey)
	if err != nil || !ok || heldBy(t, testLockKey) != 1 {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if _, ok, err := d.TryPlatformLock(ctx, testLockKey); err != nil || ok {
		t.Errorf("taken twice: %v %v", ok, err)
	}
	if err := l.Alive(ctx); err != nil {
		t.Errorf("Alive: %v", err)
	}
	l.Release()
	if n := heldBy(t, testLockKey); n != 0 {
		t.Errorf("held by %d sessions after Release", n)
	}
}

// If the unlock fails while the session lives, Release discards the
// connection, so it doesn't sit in the pool still holding the lock.
func TestSessionLockReleaseDiscardsOnFailure(t *testing.T) {
	d := openDB(t)
	l, ok, err := d.TryPlatformLock(context.Background(), testLockKey)
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	old := unlockTimeout
	unlockTimeout = time.Nanosecond // the unlock can't finish
	t.Cleanup(func() { unlockTimeout = old })
	l.Release()
	deadline := time.Now().Add(5 * time.Second)
	for heldBy(t, testLockKey) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the lock is still held by a pooled connection after a failed unlock")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
