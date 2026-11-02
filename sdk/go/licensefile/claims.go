package licensefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
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
	// ErrInvalidOptions is a caller error in CheckOptions, not a verdict about the license.
	ErrInvalidOptions = errors.New("licensefile: invalid check options")
)

// Status of a license that passed all claim checks. New values may be added in
// future versions; only a non-nil error means the license is unusable.
type Status string

const (
	StatusValid Status = "valid"
	StatusGrace Status = "grace" // past exp but within grace: usable, warn the user
)

// DefaultClockTolerance is how far in the future iat may be (ADR-0018).
const DefaultClockTolerance = 24 * time.Hour

// BindingType says what a license is bound to.
type BindingType string

const (
	BindNone    BindingType = "none"
	BindMachine BindingType = "machine"
	BindCluster BindingType = "cluster"
)

// Binding ties a license to a machine or cluster.
type Binding struct {
	Type        BindingType
	Fingerprint string
}

// Entitlements are the features and numeric limits granted by the license
// (ADR-0015). Unknown keys are never an error: HasFeature returns false and
// Limit returns 0, so apps can check features that older licenses don't have.
type Entitlements struct {
	Features []string
	Limits   map[string]int64 // Unlimited (-1) or a non-negative limit
}

// Unlimited is the limit value meaning "no limit".
const Unlimited int64 = -1

// HasFeature reports whether the license grants the boolean feature key.
func (e Entitlements) HasFeature(key string) bool {
	for _, f := range e.Features {
		if f == key {
			return true
		}
	}
	return false
}

// Limit returns the numeric limit for key: Unlimited (-1), a non-negative
// value, or 0 if the license doesn't set it.
func (e Entitlements) Limit(key string) int64 {
	return e.Limits[key]
}

// Allows reports whether using n units of the limit key is within the license.
func (e Entitlements) Allows(key string, n int64) bool {
	l := e.Limit(key)
	return l == Unlimited || n <= l
}

// Claims is the parsed lf1 payload. Optional fields are nil when absent.
type Claims struct {
	LicenseID    string
	Tenant       string
	Product      string
	Plan         string
	CustomerID   string
	CustomerName string
	IssuedAt     time.Time
	NotBefore    *time.Time
	Expires      *time.Time // nil = perpetual
	RefreshAfter *time.Time
	UpdatesUntil *time.Time
	Grace        time.Duration  // absent = 0
	MaxOffline   *time.Duration // nil = not limited; zero is a real limit
	Binding      Binding
	Entitlements Entitlements
}

const (
	maxDurationSeconds = 36500 * 24 * 60 * 60 // 100 years
	maxSafeInteger     = 1<<53 - 1
)

var (
	intTokenRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	timeRE     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	durationRE = regexp.MustCompile(`^P(?:([0-9]{1,6})D)?(?:T(?:([0-9]{1,6})H)?(?:([0-9]{1,6})M)?(?:([0-9]{1,6})S)?)?$`)
)

const timeLayout = "2006-01-02T15:04:05Z"

func malformed(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrMalformed}, a...)...)
}

// ParseClaims decodes a verified payload under the spec's strict encoding rules.
// Call it only on the payload returned by Verify.
func ParseClaims(payload []byte) (*Claims, error) {
	if err := wellFormed(payload); err != nil {
		return nil, err
	}
	m, err := object(payload, true)
	if err != nil {
		return nil, err
	}

	// Version first: a future version may change any other field.
	vRaw, ok := m["v"]
	if !ok {
		return nil, malformed("missing v")
	}
	vTok, err := intToken(vRaw, "v")
	if err != nil {
		return nil, err
	}
	if vTok != "1" {
		return nil, ErrUnsupportedVersion
	}

	c := &Claims{}
	if c.LicenseID, err = reqString(m, "lid"); err != nil {
		return nil, err
	}
	if c.Product, err = reqString(m, "product"); err != nil {
		return nil, err
	}
	if c.Tenant, _, err = optString(m, "tenant"); err != nil {
		return nil, err
	}
	if c.Plan, _, err = optString(m, "plan"); err != nil {
		return nil, err
	}
	if cust, ok, err := optObject(m, "customer"); err != nil {
		return nil, err
	} else if ok {
		if c.CustomerID, _, err = optString(cust, "id"); err != nil {
			return nil, err
		}
		if c.CustomerName, _, err = optString(cust, "name"); err != nil {
			return nil, err
		}
	}

	iat, err := optTime(m, "iat")
	if err != nil {
		return nil, err
	}
	if iat == nil {
		return nil, malformed("missing iat")
	}
	c.IssuedAt = *iat
	for _, f := range []struct {
		key string
		dst **time.Time
	}{{"nbf", &c.NotBefore}, {"exp", &c.Expires}, {"refresh_after", &c.RefreshAfter}, {"updates_until", &c.UpdatesUntil}} {
		if *f.dst, err = optTime(m, f.key); err != nil {
			return nil, err
		}
	}
	grace, err := optDuration(m, "grace")
	if err != nil {
		return nil, err
	}
	if grace != nil {
		c.Grace = *grace
	}
	if c.MaxOffline, err = optDuration(m, "max_offline"); err != nil {
		return nil, err
	}
	if c.Binding, err = parseBinding(m); err != nil {
		return nil, err
	}
	if c.Entitlements, err = parseEntitlements(m); err != nil {
		return nil, err
	}
	return c, nil
}

func parseBinding(m map[string]json.RawMessage) (Binding, error) {
	b, ok, err := optObject(m, "bind")
	if err != nil || !ok {
		return Binding{Type: BindNone}, err
	}
	typ, hasType, err := optString(b, "type")
	if err != nil {
		return Binding{}, err
	}
	fp, hasFP, err := optString(b, "fp")
	if err != nil {
		return Binding{}, err
	}
	if !hasType {
		typ = string(BindNone)
	}
	switch BindingType(typ) {
	case BindNone:
		if hasFP {
			return Binding{}, malformed("bind type none must not have fp")
		}
	case BindMachine, BindCluster:
		if fp == "" {
			return Binding{}, malformed("%s binding without fp", typ)
		}
	default:
		return Binding{}, malformed("unknown binding type %q", typ)
	}
	return Binding{Type: BindingType(typ), Fingerprint: fp}, nil
}

func parseEntitlements(m map[string]json.RawMessage) (Entitlements, error) {
	var e Entitlements
	ent, ok, err := optObject(m, "entitlements")
	if err != nil || !ok {
		return e, err
	}
	if raw, ok := ent["features"]; ok {
		if bytes.Equal(raw, []byte("null")) || len(raw) == 0 || raw[0] != '[' {
			return e, malformed("features must be an array")
		}
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return e, malformed("features: %v", err)
		}
		for _, it := range items {
			s, err := stringValue(it, "features[]")
			if err != nil {
				return e, err
			}
			e.Features = append(e.Features, s)
		}
	}
	limits, ok, err := optObject(ent, "limits")
	if err != nil {
		return e, err
	}
	if ok {
		e.Limits = make(map[string]int64, len(limits))
		for k, raw := range limits {
			tok, err := intToken(raw, "limits."+k)
			if err != nil {
				return e, err
			}
			n, err := strconv.ParseInt(tok, 10, 64)
			if err != nil || n < -1 || n > maxSafeInteger {
				return e, malformed("limit %q out of range", k)
			}
			e.Limits[k] = n
		}
	}
	return e, nil
}

// maxDepth is the deepest object/array nesting a payload may have (spec).
const maxDepth = 32

// wellFormed applies the spec's JSON well-formedness rules, checked before v:
// valid UTF-8 (no BOM), exactly one top-level object, no duplicate keys in any
// object (known or unknown), nesting depth <= maxDepth, no unpaired surrogate
// escapes.
func wellFormed(payload []byte) error {
	if !utf8.Valid(payload) {
		return malformed("payload is not valid UTF-8")
	}
	if err := checkSurrogates(payload); err != nil {
		return err
	}
	type frame struct {
		obj     bool
		keys    map[string]bool
		wantKey bool
	}
	var stack []*frame
	valueDone := func() {
		if n := len(stack); n > 0 && stack[n-1].obj {
			stack[n-1].wantKey = true
		}
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	for first := true; first || len(stack) > 0; first = false {
		tok, err := dec.Token()
		if err != nil {
			return malformed("%v", err)
		}
		if first && tok != json.Delim('{') {
			return malformed("expected a JSON object")
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if len(stack) > 0 && stack[len(stack)-1].obj {
					stack[len(stack)-1].wantKey = false
				}
				stack = append(stack, &frame{obj: t == '{', keys: map[string]bool{}, wantKey: t == '{'})
				if len(stack) > maxDepth {
					return malformed("nesting deeper than %d", maxDepth)
				}
			default: // '}' or ']'
				stack = stack[:len(stack)-1]
				valueDone()
			}
		case string:
			if top := stack[len(stack)-1]; top.obj && top.wantKey {
				if top.keys[t] {
					return malformed("duplicate key %q", t)
				}
				top.keys[t] = true
				top.wantKey = false
				continue
			}
			valueDone()
		default:
			valueDone()
		}
	}
	if _, err := dec.Token(); err != io.EOF {
		return malformed("trailing data after payload object")
	}
	return nil
}

// checkSurrogates rejects \uD800-\uDFFF escapes that don't form a valid pair
// (Go would silently replace them; JS and Java keep them).
func checkSurrogates(b []byte) error {
	hex4 := func(i int) (int, bool) {
		if i+6 > len(b) || b[i] != '\\' || b[i+1] != 'u' {
			return 0, false
		}
		v, err := strconv.ParseUint(string(b[i+2:i+6]), 16, 16)
		return int(v), err == nil
	}
	inString := false
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '"':
			inString = !inString
		case inString && b[i] == '\\':
			if v, ok := hex4(i); ok {
				switch {
				case v >= 0xD800 && v <= 0xDBFF:
					if lo, ok := hex4(i + 6); !ok || lo < 0xDC00 || lo > 0xDFFF {
						return malformed("unpaired surrogate escape")
					}
					i += 11
				case v >= 0xDC00 && v <= 0xDFFF:
					return malformed("unpaired surrogate escape")
				default:
					i += 5
				}
			} else {
				i++ // skip the escaped character
			}
		}
	}
	return nil
}

// object decodes a JSON object with exact-case keys, rejecting duplicate keys.
// top requires nothing but whitespace after the object.
func object(raw []byte, top bool) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, malformed("expected a JSON object")
	}
	m := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, malformed("%v", err)
		}
		key, _ := tok.(string) // object keys are always strings
		if _, dup := m[key]; dup {
			return nil, malformed("duplicate key %q", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, malformed("%v", err)
		}
		m[key] = v
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, malformed("%v", err)
	}
	if top {
		if _, err := dec.Token(); err != io.EOF {
			return nil, malformed("trailing data after payload object")
		}
	}
	return m, nil
}

func isNull(raw json.RawMessage) bool { return bytes.Equal(raw, []byte("null")) }

func stringValue(raw json.RawMessage, key string) (string, error) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", malformed("%s must be a string", key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", malformed("%s: %v", key, err)
	}
	return s, nil
}

func optString(m map[string]json.RawMessage, key string) (string, bool, error) {
	raw, ok := m[key]
	if !ok {
		return "", false, nil
	}
	s, err := stringValue(raw, key)
	return s, true, err
}

func reqString(m map[string]json.RawMessage, key string) (string, error) {
	s, ok, err := optString(m, key)
	if err == nil && (!ok || s == "") {
		err = malformed("missing or empty %s", key)
	}
	return s, err
}

func optObject(m map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool, error) {
	raw, ok := m[key]
	if !ok {
		return nil, false, nil
	}
	if isNull(raw) {
		return nil, false, malformed("%s is null", key)
	}
	obj, err := object(raw, false)
	return obj, true, err
}

func intToken(raw json.RawMessage, key string) (string, error) {
	tok := string(raw)
	if !intTokenRE.MatchString(tok) {
		return "", malformed("%s must be an integer", key)
	}
	return tok, nil
}

func optTime(m map[string]json.RawMessage, key string) (*time.Time, error) {
	s, ok, err := optString(m, key)
	if err != nil || !ok {
		return nil, err
	}
	t, err := parseTime(s)
	return &t, err
}

func optDuration(m map[string]json.RawMessage, key string) (*time.Duration, error) {
	s, ok, err := optString(m, key)
	if err != nil || !ok {
		return nil, err
	}
	d, err := parseDuration(s)
	return &d, err
}

// parseTime accepts exactly YYYY-MM-DDTHH:MM:SSZ with a real date, year 1970-9999.
func parseTime(s string) (time.Time, error) {
	if !timeRE.MatchString(s) {
		return time.Time{}, malformed("timestamp %q", s)
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil || t.Format(timeLayout) != s || t.Year() < 1970 {
		return time.Time{}, malformed("timestamp %q", s)
	}
	return t, nil
}

// parseDuration accepts P[nD][T[nH][nM][nS]], at most 100 years in total.
func parseDuration(s string) (time.Duration, error) {
	m := durationRE.FindStringSubmatch(s)
	if m == nil || s == "P" || s[len(s)-1] == 'T' {
		return 0, malformed("duration %q", s)
	}
	var secs int64 // each part <= 999999, so the sum fits easily in int64 seconds
	for i, unit := range []int64{86400, 3600, 60, 1} {
		if m[i+1] != "" {
			n, _ := strconv.ParseInt(m[i+1], 10, 64)
			secs += n * unit
		}
	}
	if secs > maxDurationSeconds {
		return 0, malformed("duration %q exceeds 36500 days", s)
	}
	return time.Duration(secs) * time.Second, nil
}

// CheckOptions are the local facts a license is checked against.
type CheckOptions struct {
	Now            time.Time
	Product        string
	Fingerprint    string         // local machine or cluster fingerprint
	BuildDate      time.Time      // zero = unknown, updates_until not checked
	ClockTolerance *time.Duration // nil = DefaultClockTolerance; 0 = strict; negative is invalid
}

// Check applies the spec's claim checks in order. It returns StatusValid or
// StatusGrace for a usable license, or one of the Err* claim errors.
func (c *Claims) Check(o CheckOptions) (Status, error) {
	tol := DefaultClockTolerance
	if o.Now.IsZero() {
		return "", fmt.Errorf("%w: Now is not set", ErrInvalidOptions)
	}
	if o.ClockTolerance != nil {
		if *o.ClockTolerance < 0 {
			return "", fmt.Errorf("%w: negative clock tolerance", ErrInvalidOptions)
		}
		tol = *o.ClockTolerance
	}
	switch {
	case c.Product != o.Product:
		return "", ErrWrongProduct
	case c.Binding.Type != BindNone && (c.Binding.Fingerprint == "" || c.Binding.Fingerprint != o.Fingerprint):
		return "", ErrBindingMismatch
	case c.IssuedAt.After(o.Now.Add(tol)):
		return "", ErrClockSkew
	case c.NotBefore != nil && o.Now.Before(*c.NotBefore):
		return "", ErrNotYetValid
	case c.MaxOffline != nil && o.Now.After(c.IssuedAt.Add(*c.MaxOffline)):
		return "", ErrOfflineExceeded
	case c.Expires != nil && o.Now.After(c.Expires.Add(c.Grace)):
		return "", ErrExpired
	case c.UpdatesUntil != nil && !o.BuildDate.IsZero() && o.BuildDate.After(*c.UpdatesUntil):
		return "", ErrUpdatesExpired
	case c.Expires != nil && o.Now.After(*c.Expires):
		return StatusGrace, nil
	}
	return StatusValid, nil
}

// Open verifies a license's signature, parses its claims and checks them.
// It is the usual entry point for applications. Claims are returned whenever
// the payload parsed, including when Check failed (e.g. to show the expiry
// date); they are nil on signature or parse errors. Treat the license as
// unusable whenever err is non-nil.
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
