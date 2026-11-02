// Package clock protects license time checks against the system clock being
// turned back (ADR-0018).
//
// A Guard keeps a high-water mark: the latest time it has seen. Now(local)
// returns max(local, mark), the value to use as licensefile.CheckOptions.Now,
// so time used for license checks never moves backwards; a local clock more
// than the tolerance behind the mark fails with ErrRollback.
//
// The mark is raised by Now itself, by Observe (a license iat that already
// passed its claim checks, capped at local+tolerance) and set by Reset (the
// server's time after a successful online refresh, the only way to lower it).
//
// The stored mark is authenticated with HMAC-SHA256 under a key derived from
// the license key, which ties the state to one license (a renewed key starts
// fresh). State that fails authentication, is corrupt or can't be read is
// ignored, exactly like deleted state.
// Deleting, corrupting or replacing the state with an old copy therefore
// resets the mark; that is within the threat model (ADR-0014), and
// max_offline bounds the gain. The MAC is not a FIPS security function: its
// key lives on the client. Offline recovery from ErrRollback, after fixing the
// clock, is deleting the state file.
package clock

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DefaultTolerance is how far the local clock may be behind the mark (ADR-0018).
const DefaultTolerance = 24 * time.Hour

// persistEvery is the smallest mark increase worth writing: it avoids an
// fsync on every license check and is far below any tolerance.
const persistEvery = time.Minute

var (
	// ErrRollback means the local clock is too far behind the latest trusted time.
	ErrRollback = errors.New("clock: system clock is behind the last trusted time; fix the clock, refresh the license online, or (offline) delete the clock state")
	// ErrUnreadable means the store couldn't run the rollback check at all.
	// There is no usable time.
	ErrUnreadable = errors.New("clock: state unreadable")
	// ErrNotPersisted means the time returned is valid but the new mark could
	// not be saved (e.g. read-only storage). Callers may continue.
	ErrNotPersisted = errors.New("clock: mark not persisted")
)

// Store persists the guard's state.
type Store interface {
	// Update calls fn with the current state (nil if none) and stores the
	// bytes fn returns; fn returning nil means "no change". It should be
	// atomic with respect to other processes using the same state.
	//
	// Update must call fn, even if it can't lock or write (then it returns
	// the lock/write error after fn). State that can't be read may be passed
	// as nil (no state). A store that can't call fn at all must return an
	// error; the Guard reports ErrUnreadable either way.
	Update(fn func(current []byte) ([]byte, error)) error
}

// Options configures a Guard.
type Options struct {
	// Tolerance is how far the local clock may be behind the mark.
	// nil = DefaultTolerance, 0 = strict, negative is invalid.
	Tolerance *time.Duration
}

// Guard tracks the high-water mark for one license. It is safe for concurrent use.
type Guard struct {
	mu        sync.Mutex
	store     Store
	key       []byte
	tolerance time.Duration
}

// New returns a Guard storing its state in store, authenticated with a key
// derived from licenseKey.
func New(store Store, licenseKey string, opts Options) (*Guard, error) {
	if licenseKey == "" {
		return nil, errors.New("clock: empty license key")
	}
	tol := DefaultTolerance
	if opts.Tolerance != nil {
		if *opts.Tolerance < 0 {
			return nil, errors.New("clock: negative tolerance")
		}
		tol = *opts.Tolerance
	}
	// SHA-256 rather than HKDF: FIPS 140-only mode rejects HKDF inputs shorter
	// than 112 bits, and license keys can be shorter than that.
	sum := sha256.Sum256([]byte("licenseforge clock v1|" + licenseKey))
	return &Guard{store: store, key: sum[:], tolerance: tol}, nil
}

type state struct {
	Mark string `json:"mark"` // RFC 3339, UTC
	MAC  []byte `json:"mac"`
}

func (g *Guard) mac(mark string) []byte {
	h := hmac.New(sha256.New, g.key)
	h.Write([]byte("v1|" + mark))
	return h.Sum(nil)
}

// decode returns the stored mark, or the zero time for no state. State that
// is empty, unparsable or fails the MAC counts as no state: an attacker could
// get the same by deleting it, and treating it as an error would only lock out
// honest users (crash damage, a new license key).
func (g *Guard) decode(b []byte) time.Time {
	var s state
	if len(b) == 0 || json.Unmarshal(b, &s) != nil || !hmac.Equal(s.MAC, g.mac(s.Mark)) {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s.Mark)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (g *Guard) encode(t time.Time) ([]byte, error) {
	mark := t.UTC().Round(0).Format(time.RFC3339Nano)
	return json.Marshal(state{Mark: mark, MAC: g.mac(mark)})
}

// update runs fn on the stored mark under the store's lock. fn returns the
// new mark, or the zero time for "no change".
// The check always runs on the stored state; if it can't (unreadable state)
// the error is returned as is, never as ErrNotPersisted.
func (g *Guard) update(fn func(mark time.Time) (time.Time, error)) error {
	var ran bool
	var fnErr error
	err := g.store.Update(func(cur []byte) ([]byte, error) {
		ran = true
		next, err := fn(g.decode(cur))
		if err != nil || next.IsZero() {
			fnErr = err
			return nil, nil
		}
		return g.encode(next)
	})
	switch {
	case !ran: // the check never ran: no usable time, whatever the store said
		if err == nil || errors.Is(err, ErrUnreadable) {
			return errors.Join(ErrUnreadable, err)
		}
		return fmt.Errorf("%w: %w", ErrUnreadable, err)
	case fnErr != nil:
		return fnErr
	case err == nil:
		return nil
	default:
		return fmt.Errorf("%w: %w", ErrNotPersisted, err)
	}
}

// Now returns the time to use for license checks given the system clock.
//
// Errors: ErrRollback and ErrUnreadable mean no usable time. ErrNotPersisted
// means the check passed and the returned time is valid, but the mark could
// not be saved (read-only storage, lock contention).
func (g *Guard) Now(local time.Time) (time.Time, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := local
	err := g.update(func(mark time.Time) (time.Time, error) {
		if !mark.IsZero() && local.Before(mark.Add(-g.tolerance)) {
			return time.Time{}, ErrRollback
		}
		if mark.After(now) {
			now = mark
		}
		if mark.IsZero() || local.Sub(mark) >= persistEvery {
			return local, nil
		}
		return time.Time{}, nil
	})
	if err != nil && !errors.Is(err, ErrNotPersisted) {
		return time.Time{}, err
	}
	return now, err
}

// Observe raises the mark to t, a time known to be genuine, such as the iat of
// a license that already passed its claim checks. Values more than the
// tolerance ahead of local are capped at local+tolerance, so a fast vendor
// clock can't lock out an honest user.
func (g *Guard) Observe(t, local time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if limit := local.Add(g.tolerance); t.After(limit) {
		t = limit
	}
	return g.update(func(mark time.Time) (time.Time, error) {
		if t.After(mark) {
			return t, nil
		}
		return time.Time{}, nil
	})
}

// Reset sets the mark to serverTime after a successful online refresh, even
// if that lowers it. It is the online way out of ErrRollback. serverTime must
// be authenticated (the iat of a signature-verified lease), never an
// unauthenticated value such as an HTTP Date header.
func (g *Guard) Reset(serverTime time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.update(func(time.Time) (time.Time, error) { return serverTime, nil })
}
