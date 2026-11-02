package clock

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

type memStore struct{ b []byte }

func (m *memStore) Load() ([]byte, error) { return m.b, nil }
func (m *memStore) Save(b []byte) error   { m.b = append([]byte(nil), b...); return nil }

var t0 = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func newGuard(t *testing.T, s Store) *Guard {
	t.Helper()
	g, err := New(s, "LF-TEST-KEY", 0)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func mustNow(t *testing.T, g *Guard, local time.Time, trusted ...time.Time) time.Time {
	t.Helper()
	now, err := g.Now(local, trusted...)
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
	// Clock turned back 23h: within tolerance, but time used for checks stays at the mark.
	if got := mustNow(t, g, later.Add(-23*time.Hour)); !got.Equal(later) {
		t.Fatalf("small rollback: got %v, want mark %v", got, later)
	}
	// Turned back more than 24h: refused.
	if _, err := g.Now(later.Add(-24*time.Hour - time.Second)); !errors.Is(err, ErrRollback) {
		t.Fatalf("big rollback: got %v, want ErrRollback", err)
	}
	// Exactly at the tolerance is still accepted.
	if _, err := g.Now(later.Add(-24 * time.Hour)); err != nil {
		t.Fatalf("at tolerance: %v", err)
	}
}

func TestTrustedTimesRaiseTheMark(t *testing.T) {
	g := newGuard(t, &memStore{})
	server := t0.Add(10 * time.Hour)
	if got := mustNow(t, g, t0, server); !got.Equal(server) {
		t.Fatalf("got %v, want server time %v", got, server)
	}
	// The mark now follows the server time: local 25h behind it is a rollback.
	if _, err := g.Now(server.Add(-25 * time.Hour)); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v, want ErrRollback", err)
	}
}

func TestTamperDetection(t *testing.T) {
	s := &memStore{}
	g := newGuard(t, s)
	mustNow(t, g, t0)

	edited := append([]byte(nil), s.b...)
	copy(edited[len(`{"mark":"`):], "2020") // move the mark back by hand
	s.b = edited
	if _, err := g.Now(t0); !errors.Is(err, ErrTampered) {
		t.Fatalf("edited mark: got %v, want ErrTampered", err)
	}
	s.b = []byte("garbage")
	if _, err := g.Now(t0); !errors.Is(err, ErrTampered) {
		t.Fatalf("garbage: got %v, want ErrTampered", err)
	}

	// State written for another license key does not verify.
	s2 := &memStore{}
	mustNow(t, newGuard(t, s2), t0)
	other, err := New(s2, "LF-OTHER-KEY", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Now(t0); !errors.Is(err, ErrTampered) {
		t.Fatalf("other key: got %v, want ErrTampered", err)
	}
}

func TestResetRecovers(t *testing.T) {
	s := &memStore{b: []byte("garbage")}
	g := newGuard(t, s)
	if err := g.Reset(t0); err != nil {
		t.Fatal(err)
	}
	if got := mustNow(t, g, t0.Add(-time.Hour)); !got.Equal(t0) {
		t.Fatalf("after reset: %v", got)
	}
}

func TestCustomTolerance(t *testing.T) {
	g, err := New(&memStore{}, "k", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	mustNow(t, g, t0)
	if _, err := g.Now(t0.Add(-2 * time.Minute)); !errors.Is(err, ErrRollback) {
		t.Fatalf("got %v", err)
	}
}

func TestNewRejectsEmptyKey(t *testing.T) {
	if _, err := New(&memStore{}, "", 0); err == nil {
		t.Fatal("empty license key must fail")
	}
}

func TestConcurrentUse(t *testing.T) {
	g := newGuard(t, &memStore{})
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mustNow(t, g, t0.Add(time.Duration(i)*time.Minute))
		}()
	}
	wg.Wait()
	if got := mustNow(t, g, t0); !got.Equal(t0.Add(19 * time.Minute)) {
		t.Fatalf("mark = %v", got)
	}
}

func TestFileStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	fs := FileStore{Path: path}
	if b, err := fs.Load(); b != nil || err != nil {
		t.Fatalf("missing file: %q, %v", b, err)
	}
	g := newGuard(t, fs)
	mustNow(t, g, t0)
	// A new guard (e.g. after a restart) sees the persisted mark.
	if _, err := newGuard(t, fs).Now(t0.Add(-48 * time.Hour)); !errors.Is(err, ErrRollback) {
		t.Fatalf("after restart: got %v, want ErrRollback", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, %v; want 0600", info.Mode().Perm(), err)
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}
