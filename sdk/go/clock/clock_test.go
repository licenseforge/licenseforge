package clock

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// memStore is an in-process Store; failSave simulates read-only storage.
type memStore struct {
	mu       sync.Mutex
	b        []byte
	failSave bool
}

func (m *memStore) Update(fn func([]byte) ([]byte, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := fn(m.b)
	if err != nil || next == nil {
		return err
	}
	if m.failSave {
		return errors.New("read-only file system")
	}
	m.b = append([]byte(nil), next...)
	return nil
}

var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func dur(d time.Duration) *time.Duration { return &d }

func newGuard(t *testing.T, s Store, opts ...Options) *Guard {
	t.Helper()
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	g, err := New(s, "LF-TEST-KEY", o)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func mustNow(t *testing.T, g *Guard, local time.Time) time.Time {
	t.Helper()
	now, err := g.Now(local)
	if err != nil {
		t.Fatalf("Now(%v): %v", local, err)
	}
	return now
}

func TestNeverMovesBackwards(t *testing.T) {
	g := newGuard(t, &memStore{})
	if got := mustNow(t, g, t0); !got.Equal(t0) {
		t.Fatalf("first call: %v", got)
	}
	later := t0.Add(48 * time.Hour)
	mustNow(t, g, later)
	if got := mustNow(t, g, later.Add(-23*time.Hour)); !got.Equal(later) {
		t.Fatalf("small rollback: got %v, want mark %v", got, later)
	}
	if _, err := g.Now(later.Add(-24*time.Hour - time.Second)); !errors.Is(err, ErrRollback) {
		t.Fatalf("big rollback: got %v, want ErrRollback", err)
	}
	if _, err := g.Now(later.Add(-24 * time.Hour)); err != nil {
		t.Fatalf("at tolerance: %v", err)
	}
}

func TestToleranceOptions(t *testing.T) {
	strict := newGuard(t, &memStore{}, Options{Tolerance: dur(0)})
	mustNow(t, strict, t0)
	if _, err := strict.Now(t0.Add(-time.Second)); !errors.Is(err, ErrRollback) {
		t.Fatalf("strict: got %v, want ErrRollback", err)
	}
	if _, err := New(&memStore{}, "k", Options{Tolerance: dur(-time.Hour)}); err == nil {
		t.Fatal("negative tolerance must be rejected")
	}
	if _, err := New(&memStore{}, "", Options{}); err == nil {
		t.Fatal("empty license key must be rejected")
	}
}

func TestObserveCapsFutureTimes(t *testing.T) {
	g := newGuard(t, &memStore{})
	// A license signed by a vendor clock 3 days fast must not poison the mark.
	if err := g.Observe(t0.Add(72*time.Hour), t0); err != nil {
		t.Fatal(err)
	}
	if got := mustNow(t, g, t0); !got.Equal(t0.Add(DefaultTolerance)) {
		t.Fatalf("got %v, want mark capped at local+tolerance", got)
	}
	// The honest clock right after is still accepted (not a rollback).
	if _, err := g.Now(t0.Add(time.Minute)); err != nil {
		t.Fatalf("honest clock after capped observe: %v", err)
	}
	// Observing an older time never lowers the mark.
	_ = g.Observe(t0.Add(-time.Hour), t0)
	if got := mustNow(t, g, t0); !got.Equal(t0.Add(DefaultTolerance)) {
		t.Fatalf("mark lowered to %v", got)
	}
}

// The guard must not hide licensefile's future-iat (clock skew) check.
func TestWithLicenseClockSkewStillDetected(t *testing.T) {
	g := newGuard(t, &memStore{})
	c, err := licensefile.ParseClaims([]byte(`{"v":1,"lid":"l","product":"p","iat":"2026-11-18T12:00:00Z"}`)) // local + 72h
	if err != nil {
		t.Fatal(err)
	}
	now := mustNow(t, g, t0)
	if _, err := c.Check(licensefile.CheckOptions{Now: now, Product: "p"}); !errors.Is(err, licensefile.ErrClockSkew) {
		t.Fatalf("got %v, want ErrClockSkew", err)
	}
}

func TestResetCanLowerTheMark(t *testing.T) {
	g := newGuard(t, &memStore{})
	mustNow(t, g, t0.Add(30*24*time.Hour)) // local clock once jumped forward a month
	if _, err := g.Now(t0); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want ErrRollback", err)
	}
	if err := g.Reset(t0); err != nil { // server says the real time is t0
		t.Fatal(err)
	}
	if got := mustNow(t, g, t0); !got.Equal(t0) {
		t.Fatalf("after reset: %v", got)
	}
}

func TestReadOnlyStoreDoesNotLockOut(t *testing.T) {
	s := &memStore{}
	g := newGuard(t, s)
	mustNow(t, g, t0)
	s.failSave = true
	now, err := g.Now(t0.Add(time.Hour))
	if !errors.Is(err, ErrNotPersisted) || !now.Equal(t0.Add(time.Hour)) {
		t.Fatalf("got %v, %v; want the time plus ErrNotPersisted", now, err)
	}
	// Rollback detection still works from the last persisted mark.
	if _, err := g.Now(t0.Add(-25 * time.Hour)); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want ErrRollback", err)
	}
}

func TestWritesOnlyWhenMarkMovesAMinute(t *testing.T) {
	s := &memStore{}
	g := newGuard(t, s)
	mustNow(t, g, t0)
	before := string(s.b)
	mustNow(t, g, t0.Add(30*time.Second))
	if string(s.b) != before {
		t.Fatal("mark rewritten for a 30s change")
	}
	mustNow(t, g, t0.Add(time.Minute))
	if string(s.b) == before {
		t.Fatal("mark not written after a minute")
	}
}

func TestTamperAndCorruption(t *testing.T) {
	s := &memStore{}
	g := newGuard(t, s)
	mustNow(t, g, t0)
	edited := append([]byte(nil), s.b...)
	copy(edited[len(`{"mark":"`):], "2020") // move the mark back by hand
	s.b = edited
	if _, err := g.Now(t0); !errors.Is(err, ErrTampered) {
		t.Fatalf("edited mark: got %v, want ErrTampered", err)
	}
	// State from another license key does not verify.
	s2 := &memStore{}
	mustNow(t, newGuard(t, s2), t0)
	other, err := New(s2, "LF-OTHER-KEY", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Now(t0); !errors.Is(err, ErrTampered) {
		t.Fatalf("other key: got %v, want ErrTampered", err)
	}
	// Empty or truncated state (crash, disk issue) counts as no state.
	for _, b := range []string{"", `{"mark":"2026-11-15T12:0`, "garbage"} {
		s.b = []byte(b)
		if _, err := g.Now(t0); err != nil {
			t.Fatalf("corrupt %q: %v", b, err)
		}
	}
}

func TestConcurrentGuardsShareOneFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	server := t0.Add(20 * time.Hour)
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := newGuard(t, FileStore{Path: path}) // separate guard, like separate processes
			if i == 0 {
				if err := g.Observe(server, server); err != nil {
					t.Error(err)
				}
				return
			}
			if _, err := g.Now(t0.Add(time.Duration(i) * time.Minute)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := mustNow(t, newGuard(t, FileStore{Path: path}), t0); !got.Equal(server) {
		t.Fatalf("mark = %v, want %v (an update was lost)", got, server)
	}
}

func TestFileStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clock.json")
	mustNow(t, newGuard(t, FileStore{Path: path}), t0)
	// A new guard (e.g. after a restart) sees the persisted mark.
	if _, err := newGuard(t, FileStore{Path: path}).Now(t0.Add(-48 * time.Hour)); !errors.Is(err, ErrRollback) {
		t.Fatalf("after restart: got %v, want ErrRollback", err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, %v; want 0600", info.Mode().Perm(), err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("temp or lock files left behind: %v", entries)
	}
	// A stale lock from a crashed process is taken over.
	lock := path + ".lock"
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := newGuard(t, FileStore{Path: path}).Now(t0.Add(time.Hour)); err != nil {
		t.Fatalf("stale lock: %v", err)
	}
}

func TestFileStoreReadOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("permission semantics differ")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "clock.json")
	mustNow(t, newGuard(t, FileStore{Path: path}), t0)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	now, err := newGuard(t, FileStore{Path: path}).Now(t0.Add(time.Hour))
	if !errors.Is(err, ErrNotPersisted) || !now.Equal(t0.Add(time.Hour)) {
		t.Fatalf("read-only dir: %v, %v; want the time plus ErrNotPersisted", now, err)
	}
}
