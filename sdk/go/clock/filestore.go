package clock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileStore keeps the state in a file. Updates are serialized across
// processes with a lock file (Path + ".lock", created exclusively) and written
// atomically: temp file with mode 0600, fsync, rename, fsync of the directory.
// Use persistent storage for offline licenses: with memory-only storage the
// mark resets on every restart (ADR-0018).
type FileStore struct{ Path string }

const (
	lockWait  = 2 * time.Second  // give up acquiring the lock after this
	lockStale = 30 * time.Second // a lock older than this was left by a crashed process
)

// Update implements Store.
func (f FileStore) Update(fn func(current []byte) ([]byte, error)) error {
	unlock, err := f.lock()
	if err != nil {
		return err
	}
	defer unlock()

	cur, err := os.ReadFile(f.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	next, err := fn(cur)
	if err != nil || next == nil {
		return err
	}
	return f.write(next)
}

func (f FileStore) lock() (func(), error) {
	lockPath := f.Path + ".lock"
	deadline := time.Now().Add(lockWait)
	for {
		lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = lf.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > lockStale {
			// ponytail: two processes can both see the lock as stale and race; harmless
			// at a 30s threshold for a state that changes at most once a minute.
			_ = os.Remove(lockPath) // stale lock from a crashed process
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s", lockPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (f FileStore) write(b []byte) error {
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, ".licenseforge-clock-*") // mode 0600
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// On Windows, rename fails while another process has the target open
	// (sharing violation); readers hold it only briefly, so retry.
	for attempt := 0; ; attempt++ {
		err = os.Rename(tmp.Name(), f.Path)
		if err == nil || attempt == 4 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	// Make the rename durable. Opening a directory fails on Windows, where
	// rename durability is handled by the filesystem; ignore that case.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
