package licensefile

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// Claim check results that are not usable licenses. Each maps to a spec result class.
var (
	ErrUnsupportedVersion = errors.New("licensefile: unsupported version")
	ErrWrongProduct       = errors.New("licensefile: wrong product")
	ErrBindingMismatch    = errors.New("licensefile: binding mismatch")
	ErrClockSkew          = errors.New("licensefile: issued in the future (clock skew)")
	ErrNotYetValid        = errors.New("licensefile: not yet valid")
	ErrOfflineExceeded    = errors.New("licensefile: offline period exceeded")
	ErrExpired            = errors.New("licensefile: expired")
	ErrUpdatesExpired     = errors.New("licensefile: build not covered by updates_until")
)

// Status of a license that passed all claim checks.
type Status string

const (
	StatusValid Status = "valid"
	StatusGrace Status = "grace" // past exp but within grace: usable, warn the user
)

// DefaultClockTolerance is how far in the future iat may be (ADR-0018).
const DefaultClockTolerance = 24 * time.Hour

// Binding ties a license to a machine or cluster.
type Binding struct {
	Type        string // "none", "machine" or "cluster"
	Fingerprint string
}

// Entitlements are the features and numeric limits granted by the license.
type Entitlements struct {
	Features []string         `json:"features"`
	Limits   map[string]int64 `json:"limits"`
}

// Claims is the parsed lf1 payload. Optional times and durations are zero when absent.
type Claims struct {
	Version      int
	LicenseID    string
	Tenant       string
	Product      string
	Plan         string
	CustomerID   string
	CustomerName string
	IssuedAt     time.Time
	NotBefore    time.Time
	Expires      time.Time // zero = perpetual
	RefreshAfter time.Time
	UpdatesUntil time.Time
	Grace        time.Duration
	MaxOffline   time.Duration // zero = not limited
	Binding      Binding
	Entitlements Entitlements
}

type rawClaims struct {
	V        *int    `json:"v"`
	LID      *string `json:"lid"`
	Tenant   string  `json:"tenant"`
	Product  *string `json:"product"`
	Plan     string  `json:"plan"`
	Customer struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"customer"`
	IAT          *string `json:"iat"`
	NBF          *string `json:"nbf"`
	EXP          *string `json:"exp"`
	RefreshAfter *string `json:"refresh_after"`
	UpdatesUntil *string `json:"updates_until"`
	Grace        *string `json:"grace"`
	MaxOffline   *string `json:"max_offline"`
	Bind         struct {
		Type string `json:"type"`
		FP   string `json:"fp"`
	} `json:"bind"`
	Entitlements Entitlements `json:"entitlements"`
}

const timeLayout = "2006-01-02T15:04:05Z"

// ParseClaims decodes a verified payload. Call it only on the payload returned by Verify.
func ParseClaims(payload []byte) (*Claims, error) {
	var r rawClaims
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	// Version first: a future version may have different required fields.
	if r.V == nil {
		return nil, fmt.Errorf("%w: missing v", ErrMalformed)
	}
	if *r.V != 1 {
		return nil, ErrUnsupportedVersion
	}
	if r.LID == nil || *r.LID == "" || r.Product == nil || *r.Product == "" || r.IAT == nil {
		return nil, fmt.Errorf("%w: missing required claim", ErrMalformed)
	}
	c := &Claims{
		Version: *r.V, LicenseID: *r.LID, Tenant: r.Tenant, Product: *r.Product, Plan: r.Plan,
		CustomerID: r.Customer.ID, CustomerName: r.Customer.Name, Entitlements: r.Entitlements,
		Binding: Binding{Type: r.Bind.Type, Fingerprint: r.Bind.FP},
	}
	var err error
	for _, f := range []struct {
		raw *string
		dst *time.Time
	}{{r.IAT, &c.IssuedAt}, {r.NBF, &c.NotBefore}, {r.EXP, &c.Expires}, {r.RefreshAfter, &c.RefreshAfter}, {r.UpdatesUntil, &c.UpdatesUntil}} {
		if f.raw != nil {
			if *f.dst, err = parseTime(*f.raw); err != nil {
				return nil, err
			}
		}
	}
	for _, f := range []struct {
		raw *string
		dst *time.Duration
	}{{r.Grace, &c.Grace}, {r.MaxOffline, &c.MaxOffline}} {
		if f.raw != nil {
			if *f.dst, err = parseDuration(*f.raw); err != nil {
				return nil, err
			}
		}
	}
	switch c.Binding.Type {
	case "":
		c.Binding.Type = "none"
	case "none":
	case "machine", "cluster":
		if c.Binding.Fingerprint == "" {
			return nil, fmt.Errorf("%w: %s binding without fingerprint", ErrMalformed, c.Binding.Type)
		}
	default:
		return nil, fmt.Errorf("%w: unknown binding type %q", ErrMalformed, c.Binding.Type)
	}
	return c, nil
}

// CheckOptions are the local facts a license is checked against.
type CheckOptions struct {
	Now            time.Time
	Product        string
	Fingerprint    string        // local machine or cluster fingerprint
	BuildDate      time.Time     // zero = don't check updates_until
	ClockTolerance time.Duration // zero = DefaultClockTolerance
}

// Check applies the spec's claim checks in order. It returns StatusValid or
// StatusGrace for a usable license, or one of the Err* claim errors.
func (c *Claims) Check(o CheckOptions) (Status, error) {
	tol := o.ClockTolerance
	if tol == 0 {
		tol = DefaultClockTolerance
	}
	switch {
	case c.Product != o.Product:
		return "", ErrWrongProduct
	case c.Binding.Type != "none" && c.Binding.Fingerprint != o.Fingerprint:
		return "", ErrBindingMismatch
	case c.IssuedAt.After(o.Now.Add(tol)):
		return "", ErrClockSkew
	case !c.NotBefore.IsZero() && o.Now.Before(c.NotBefore):
		return "", ErrNotYetValid
	case c.MaxOffline > 0 && o.Now.After(c.IssuedAt.Add(c.MaxOffline)):
		return "", ErrOfflineExceeded
	case !c.Expires.IsZero() && o.Now.After(c.Expires.Add(c.Grace)):
		return "", ErrExpired
	case !c.UpdatesUntil.IsZero() && !o.BuildDate.IsZero() && o.BuildDate.After(c.UpdatesUntil):
		return "", ErrUpdatesExpired
	case !c.Expires.IsZero() && o.Now.After(c.Expires):
		return StatusGrace, nil
	}
	return StatusValid, nil
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil || t.Format(timeLayout) != s {
		return time.Time{}, fmt.Errorf("%w: timestamp %q", ErrMalformed, s)
	}
	return t, nil
}

var durationRE = regexp.MustCompile(`^P(?:(\d{1,6})D)?(?:T(?:(\d{1,6})H)?(?:(\d{1,6})M)?(?:(\d{1,6})S)?)?$`)

// parseDuration accepts the spec's ISO 8601 subset P[nD][T[nH][nM][nS]].
func parseDuration(s string) (time.Duration, error) {
	m := durationRE.FindStringSubmatch(s)
	if m == nil || s == "P" || s[len(s)-1] == 'T' {
		return 0, fmt.Errorf("%w: duration %q", ErrMalformed, s)
	}
	var d time.Duration
	for i, unit := range []time.Duration{24 * time.Hour, time.Hour, time.Minute, time.Second} {
		if m[i+1] != "" {
			n, _ := strconv.Atoi(m[i+1]) // at most 6 digits, cannot overflow
			d += time.Duration(n) * unit
		}
	}
	return d, nil
}

// Open verifies a license's signature, parses its claims and checks them.
// It is the usual entry point for applications. On a claim failure the parsed
// claims are still returned, so callers can show details (e.g. expiry date).
func Open(license string, keys KeySet, o CheckOptions) (*Claims, Status, error) {
	payload, _, err := Verify(license, keys)
	if err != nil {
		return nil, "", err
	}
	c, err := ParseClaims(payload)
	if err != nil {
		return nil, "", err
	}
	st, err := c.Check(o)
	return c, st, err
}
