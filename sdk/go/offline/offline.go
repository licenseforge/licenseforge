// Package offline runs a license on an air-gapped machine (ADR-0006,
// ADR-0043): the app writes an activation request, someone carries it to the
// vendor's LicenseForge and carries the signed license file back, the app
// installs it. To give the seat back, the app deletes the file and writes a
// deactivation receipt for the vendor.
//
// The installed file and the files returned are kept in a clock.Store (for
// example clock.FileStore: locked, atomic writes). Every use verifies the
// file again, so a renewed file installed by another process is picked up
// without a restart.
package offline

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
	"licenseforge.io/licenseforge/sdk/go/fingerprint"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
	"licenseforge.io/licenseforge/sdk/go/online"
)

var (
	// ErrNoLicense: no license file is installed.
	ErrNoLicense = errors.New("offline: no license file installed")
	// ErrBadFile: the file doesn't verify, or isn't for this tenant, product
	// or machine.
	ErrBadFile = errors.New("offline: license file not valid for this machine")
	// ErrReturned: the file is one this machine returned (or older than it):
	// its seat was given back, so it can't be installed again.
	ErrReturned = errors.New("offline: this license file was returned; request a new one")
	// ErrOtherLicense: another license's file is installed. Deactivate it
	// first, so its seat can be returned with a receipt.
	ErrOtherLicense = errors.New("offline: another license is installed; deactivate it first")
	// ErrForeignState: the store holds something else, such as the clock
	// guard's state: give each its own store (file).
	ErrForeignState = errors.New("offline: the store holds other state (shared with the clock guard?); use a store of its own")
)

// Config configures a Client. Clock, the versions, Hostname,
// ClockTolerance and BuildDate are optional.
type Config struct {
	TenantID    string // tnt_…, the license's tenant claim
	Product     string // the product slug the app expects
	LicenseKey  string // as the user typed it: it goes in the request
	Keys        licensefile.KeySet
	Fingerprint fingerprint.Result
	Hostname    string
	AppVersion  string
	// Store keeps the installed file and the files returned: its own file
	// (clock.FileStore), never the clock guard's. Use persistent storage: on
	// a memory store, a returned file could be installed again after a
	// restart. Unreadable state counts as none (ADR-0014), and a store
	// without file locking (some network file systems) can lose a returned
	// file when two processes change it at once.
	Store clock.Store
	// Clock protects the time checks against the clock being turned back
	// (ADR-0018); strongly advised offline, where no server time comes in.
	Clock          *clock.Guard
	ClockTolerance *time.Duration
	BuildDate      time.Time
}

// Client runs one license on one machine. It is safe for concurrent use;
// the Store serializes changes.
type Client struct {
	cfg  Config
	now  func() time.Time
	rand io.Reader
}

// New checks cfg.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.TenantID == "" || cfg.Product == "" || cfg.LicenseKey == "" || len(cfg.Keys) == 0 || cfg.Fingerprint.Fingerprint == "" || cfg.Store == nil:
		return nil, errors.New("offline: TenantID, Product, LicenseKey, Keys, Fingerprint and Store are required")
	case cfg.Fingerprint.Binding != string(licensefile.BindMachine) && cfg.Fingerprint.Binding != string(licensefile.BindCluster):
		return nil, errors.New("offline: Fingerprint.Binding must be machine or cluster")
	}
	return &Client{cfg: cfg, now: time.Now, rand: rand.Reader}, nil
}

// Request returns an activation request (lfreq1) for this machine, to be
// carried to the vendor. It contains the license key: handle it like the key.
func (c *Client) Request() (string, error) {
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(c.rand, nonce); err != nil {
		return "", err
	}
	return licensefile.EncodeRequest(licensefile.Request{Tenant: c.cfg.TenantID, Product: c.cfg.Product, Key: c.cfg.LicenseKey,
		Binding:  licensefile.Binding{Type: licensefile.BindingType(c.cfg.Fingerprint.Binding), Fingerprint: c.cfg.Fingerprint.Fingerprint},
		FPSource: string(c.cfg.Fingerprint.Source), Nonce: nonce, Created: c.now(),
		Hostname: c.cfg.Hostname, AppVersion: c.cfg.AppVersion, SDKVersion: online.SDKVersion})
}

// state is what the Store holds.
type state struct {
	Kind int    `json:"offline"` // 1: tells this state from others in a shared store
	File string `json:"file,omitempty"`
	// Returned: license ID → iat of the newest file returned. Deleting the
	// state forgets it, like deleting the clock state (ADR-0014).
	Returned map[string]time.Time `json:"returned,omitempty"`
}

// decode reads the stored state. Unparsable state counts as none, as in
// package clock: corrupting it gains no more than deleting it (ADR-0014).
// Well-formed state of another kind is ErrForeignState: the stores are
// mixed up, and writing would destroy the other state.
func decode(b []byte) (state, error) {
	var got state
	if len(b) == 0 || json.Unmarshal(b, &got) != nil {
		return state{Kind: 1}, nil
	}
	if got.Kind != 1 {
		return got, ErrForeignState
	}
	return got, nil
}

// update runs fn on the stored state; fn returns the new state, or nil for
// no change.
func (c *Client) update(fn func(s state) (*state, error)) error {
	var fnErr error
	err := c.cfg.Store.Update(func(cur []byte) ([]byte, error) {
		s, err := decode(cur)
		if err == nil {
			var next *state
			if next, err = fn(s); err == nil && next != nil {
				return json.Marshal(next)
			}
		}
		fnErr = err
		return nil, nil
	})
	if fnErr != nil {
		return fnErr
	}
	return err
}

// verify checks file as issued for this machine: signature, the claim
// checks at its own iat, tenant, product, and a machine or cluster binding
// to this fingerprint (an unbound file would run anywhere).
func (c *Client) verify(file string) (*licensefile.Claims, error) {
	payload, _, err := licensefile.Verify(file, c.cfg.Keys)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadFile, err)
	}
	claims, err := licensefile.ParseClaims(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadFile, err)
	}
	if _, err := claims.Check(licensefile.CheckOptions{Now: claims.IssuedAt, Product: c.cfg.Product, Fingerprint: c.cfg.Fingerprint.Fingerprint}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadFile, err)
	}
	if claims.Tenant != c.cfg.TenantID || string(claims.Binding.Type) != c.cfg.Fingerprint.Binding {
		return nil, fmt.Errorf("%w: for tenant %q, binding %q", ErrBadFile, claims.Tenant, claims.Binding.Type)
	}
	return claims, nil
}

// options are the check options at the current time; with Config.Clock,
// the time has passed the rollback check.
func (c *Client) options() (licensefile.CheckOptions, error) {
	o := licensefile.CheckOptions{Now: c.now(), Product: c.cfg.Product, Fingerprint: c.cfg.Fingerprint.Fingerprint,
		ClockTolerance: c.cfg.ClockTolerance, BuildDate: c.cfg.BuildDate}
	if c.cfg.Clock != nil {
		t, err := c.cfg.Clock.Now(o.Now)
		if err != nil && !errors.Is(err, clock.ErrNotPersisted) {
			return o, err
		}
		o.Now = t
	}
	return o, nil
}

// Install verifies file (the vendor's answer to Request) and installs it,
// replacing the installed file of the same license (a renewal). A file that
// isn't usable now, that this machine returned, or of another license while
// one is installed (ErrOtherLicense) is refused and nothing changes; with
// Config.Clock, the guard is raised to the file's iat only once it is
// installed. ErrLocked from a clock.FileStore: another process is changing
// the state; retry.
func (c *Client) Install(file string) (*licensefile.Claims, licensefile.Status, error) {
	claims, err := c.verify(file)
	if err != nil {
		return nil, "", err
	}
	local := c.now()
	o, err := c.options()
	if err != nil {
		return nil, "", err
	}
	// The vendor's clock may be ahead of this machine's: within the guard's
	// tolerance, its iat is a time this machine will accept (ADR-0018).
	if c.cfg.Clock != nil && claims.IssuedAt.After(o.Now) && !claims.IssuedAt.After(local.Add(c.cfg.Clock.Tolerance())) {
		o.Now = claims.IssuedAt
	}
	st, err := claims.Check(o)
	if err != nil {
		return nil, "", err
	}
	err = c.update(func(s state) (*state, error) {
		if r, ok := s.Returned[claims.LicenseID]; ok && !claims.IssuedAt.After(r) {
			return nil, ErrReturned
		}
		if s.File != "" {
			if cur, err := c.verify(s.File); err == nil && cur.LicenseID != claims.LicenseID {
				return nil, ErrOtherLicense
			}
		}
		s.File = file
		return &s, nil
	})
	if err != nil {
		return nil, "", err
	}
	if c.cfg.Clock != nil {
		_ = c.cfg.Clock.Observe(claims.IssuedAt, local) // a genuine time now in use; Current reports a guard that can't be written
	}
	return claims, st, nil
}

// Current verifies the installed file and checks it now: its claims and
// status (valid, or grace: usable with a warning). Any error means: don't run
// as licensed.
func (c *Client) Current() (*licensefile.Claims, licensefile.Status, error) {
	var file string
	if err := c.update(func(s state) (*state, error) { file = s.File; return nil, nil }); err != nil {
		return nil, "", err
	}
	if file == "" {
		return nil, "", ErrNoLicense
	}
	claims, err := c.verify(file)
	if err != nil {
		return nil, "", err
	}
	o, err := c.options()
	if err != nil {
		return claims, "", err
	}
	st, err := claims.Check(o)
	return claims, st, err
}

// Deactivate gives the seat back: it deletes the installed file, remembers
// it so it can't be installed again, and returns the deactivation receipt
// (lfrcpt1) for the vendor, who frees the seat with it. The receipt is
// returned only once the state is saved. Keep it until the vendor has it:
// it is the only proof. A file that no longer verifies on this machine
// (its signing key dropped from Keys, a changed fingerprint) can't be
// deactivated here (ErrBadFile): the vendor frees the seat from the
// dashboard.
func (c *Client) Deactivate() (string, error) {
	var receipt string
	err := c.update(func(s state) (*state, error) {
		if s.File == "" {
			return nil, ErrNoLicense
		}
		claims, err := c.verify(s.File)
		if err != nil {
			return nil, err
		}
		h, err := licensefile.FileSHA256(s.File)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, 16)
		if _, err := io.ReadFull(c.rand, nonce); err != nil {
			return nil, err
		}
		if receipt, err = licensefile.EncodeReceipt(licensefile.Receipt{Tenant: c.cfg.TenantID, LicenseID: claims.LicenseID,
			Fingerprint: c.cfg.Fingerprint.Fingerprint, FileSHA256: h, Nonce: nonce, Created: c.now()}); err != nil {
			return nil, err
		}
		if s.Returned == nil {
			s.Returned = map[string]time.Time{}
		}
		if r := s.Returned[claims.LicenseID]; claims.IssuedAt.After(r) {
			s.Returned[claims.LicenseID] = claims.IssuedAt
		}
		s.File = ""
		return &s, nil
	})
	if err != nil {
		return "", err
	}
	return receipt, nil
}
