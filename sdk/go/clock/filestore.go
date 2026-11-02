package clock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileStore keeps the state in a file. Updates are serialized across
// processes with an OS advisory lock on Path + ".lock" (flock on Unix,
// LockFileEx on Windows; the OS releases it if a process dies) and written
// atomically: temp file with mode 0600, fsync, rename, fsync of the directory.
//
// If the lock can't be taken (read-only directory, contention) the state is
// still read and checked, and only the write is skipped (ErrNotPersisted).
// Use persistent storage for offline licenses: with memory-only storage the
// mark resets on every restart (ADR-0018).
type FileStore struct{ Path string }

// lockWait bounds how long a check waits for another process's lock.
const lockWait = 2 * time.Second

// Update implements Store.
func (f FileStore) Update(fn func(current []byte) ([]byte, error)) error {
	unlock, lockErr := lockFile(f.Path+".lock", lockWait)
	if lockErr == nil {
		defer unlock()
	}
	cur, err := os.ReadFile(f.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrUnreadable, err)
	}
	next, err := fn(cur)
	if err != nil || next == nil {
		return err
	}
	if lockErr != nil {
		return fmt.Errorf("lock: %w", lockErr)
	}
	return f.write(next)
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
	// On Windows, rename fails while another program (antivirus, backup) has
	// the target open; retry briefly.
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
	// the filesystem handles this; ignore that case.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
