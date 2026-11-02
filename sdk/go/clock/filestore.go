package clock

import (
	"errors"
	"os"
	"path/filepath"
)

// FileStore keeps the state in a file, written atomically (temp file + rename)
// with owner-only permissions. Use persistent storage for offline licenses:
// with memory-only storage the mark resets on every restart (ADR-0018).
type FileStore struct{ Path string }

// Load returns (nil, nil) if the file does not exist.
func (f FileStore) Load() ([]byte, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Save writes the state atomically.
func (f FileStore) Save(b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(f.Path), ".licenseforge-clock-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename; CreateTemp uses mode 0600
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
	return os.Rename(tmp.Name(), f.Path)
}
