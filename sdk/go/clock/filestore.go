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
// The rollback check always runs. If another process holds the lock the write
// is skipped (ErrNotPersisted); if locking is unavailable (read-only
// directory, network filesystem, unsupported platform) the write is attempted
// without it, since rename is atomic. An unreadable state file counts as no
// state (like deletion) and is reported as ErrNotPersisted.
// Use persistent storage for offline licenses: with memory-only storage the
// mark resets on every restart (ADR-0018).
type FileStore struct{ Path string }

// lockWait bounds how long a check waits for another process's lock.
const lockWait = 2 * time.Second

// ErrLocked means another process held the lock for the whole wait: the
// change wasn't written. Retry.
var ErrLocked = errors.New("clock: state locked by another process")

// Update implements Store.
func (f FileStore) Update(fn func(current []byte) ([]byte, error)) error {
	unlock, lockErr := lockFile(f.Path+".lock", lockWait)
	if lockErr == nil {
		defer unlock()
	}
	cur, readErr := os.ReadFile(f.Path)
	if errors.Is(readErr, os.ErrNotExist) {
		readErr = nil
	}
	next, err := fn(cur) // cur is nil if unreadable: treated as no state
	if err != nil {
		return err
	}
	var writeErr error
	switch {
	case next == nil:
	case errors.Is(lockErr, ErrLocked):
		writeErr = lockErr // another process is updating; skip our write
	default:
		writeErr = f.write(next)
	}
	if readErr != nil {
		return errors.Join(fmt.Errorf("read: %w", readErr), writeErr)
	}
	return writeErr
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
