// Package clock protects license time checks against the system clock being
// turned back (ADR-0018).
//
// A Guard keeps a high-water mark: the latest trusted time it has seen (local
// clock, license issue times, server times). If the local clock is more than
// the tolerance behind it, Now fails with ErrRollback; otherwise Now returns
// the later of the local clock and the mark, so time used for license checks
// never moves backwards. The stored mark is authenticated with HMAC-SHA256
// under a key derived (SHA-256) from the license key, so editing it by hand is detected
// (ErrTampered). Deleting it resets the mark; that is within the documented
// threat model, and max_offline on leases bounds the gain.
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

var (
	// ErrRollback means the local clock is too far behind the latest trusted time.
	ErrRollback = errors.New("clock: system clock is behind the last trusted time; fix the clock or refresh the license online")
	// ErrTampered means the stored mark failed authentication.
	ErrTampered = errors.New("clock: stored clock state is invalid or was modified")
)

// Store persists the guard's state. Load returns (nil, nil) when nothing is stored.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Guard tracks the high-water mark for one license. It is safe for concurrent use.
type Guard struct {
	mu        sync.Mutex
	store     Store
	key       []byte
	tolerance time.Duration
}

// New returns a Guard storing its state in store, authenticated with a key
// derived from licenseKey. tolerance <= 0 means DefaultTolerance.
func New(store Store, licenseKey string, tolerance time.Duration) (*Guard, error) {
	if licenseKey == "" {
		return nil, errors.New("clock: empty license key")
	}
	// SHA-256 rather than HKDF: FIPS 140-only mode rejects HKDF inputs shorter
	// than 112 bits, and license keys can be shorter than that.
	sum := sha256.Sum256([]byte("licenseforge clock v1|" + licenseKey))
	key := sum[:]
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	return &Guard{store: store, key: key, tolerance: tolerance}, nil
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

func (g *Guard) load() (time.Time, error) {
	b, err := g.store.Load()
	if err != nil {
		return time.Time{}, fmt.Errorf("clock: load: %w", err)
	}
	if b == nil {
		return time.Time{}, nil
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil || !hmac.Equal(s.MAC, g.mac(s.Mark)) {
		return time.Time{}, ErrTampered
	}
	t, err := time.Parse(time.RFC3339Nano, s.Mark)
	if err != nil {
		return time.Time{}, ErrTampered
	}
	return t, nil
}

func (g *Guard) save(t time.Time) error {
	mark := t.UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(state{Mark: mark, MAC: g.mac(mark)})
	if err != nil {
		return err
	}
	if err := g.store.Save(b); err != nil {
		return fmt.Errorf("clock: save: %w", err)
	}
	return nil
}

// Now returns the time to use for license checks. local is the system clock;
// trusted are times known to be genuine (license iat, server time from a lease).
// It fails with ErrRollback if local is more than the tolerance behind the
// stored mark, and with ErrTampered if the stored state was modified.
func (g *Guard) Now(local time.Time, trusted ...time.Time) (time.Time, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	mark, err := g.load()
	if err != nil {
		return time.Time{}, err
	}
	if !mark.IsZero() && local.Before(mark.Add(-g.tolerance)) {
		return time.Time{}, ErrRollback
	}
	next := mark
	if local.After(next) {
		next = local
	}
	for _, t := range trusted {
		if t.After(next) {
			next = t
		}
	}
	if next.After(mark) {
		if err := g.save(next); err != nil {
			return time.Time{}, err
		}
	}
	if local.After(next) {
		return local, nil
	}
	return next, nil
}

// Reset replaces the stored mark with serverTime after a successful online
// refresh. It is the way out of ErrRollback and ErrTampered once the server
// has confirmed the current time.
func (g *Guard) Reset(serverTime time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.save(serverTime)
}
