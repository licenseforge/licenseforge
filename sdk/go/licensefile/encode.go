package licensefile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"time"
)

// Encode returns the lf1 payload for c (spec: Payload), for Sign. It parses
// its own output with ParseClaims and fails unless that gives back exactly c,
// so an issuer can't produce a license that verifiers reject or read
// differently. Nothing is rounded: times and durations must be whole seconds.
func Encode(c Claims) ([]byte, error) {
	type customer struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	}
	type bind struct {
		Type string `json:"type"`
		FP   string `json:"fp,omitempty"`
	}
	type entitlements struct {
		Features []string         `json:"features,omitempty"`
		Limits   map[string]int64 `json:"limits,omitempty"`
	}
	p := struct {
		V            int           `json:"v"`
		LID          string        `json:"lid"`
		Tenant       string        `json:"tenant,omitempty"`
		Product      string        `json:"product"`
		Plan         string        `json:"plan,omitempty"`
		Customer     *customer     `json:"customer,omitempty"`
		IAT          string        `json:"iat"`
		NBF          string        `json:"nbf,omitempty"`
		Exp          string        `json:"exp,omitempty"`
		Grace        string        `json:"grace,omitempty"`
		MaxOffline   string        `json:"max_offline,omitempty"`
		RefreshAfter string        `json:"refresh_after,omitempty"`
		UpdatesUntil string        `json:"updates_until,omitempty"`
		Bind         *bind         `json:"bind,omitempty"`
		Entitlements *entitlements `json:"entitlements,omitempty"`
	}{V: 1, LID: c.LicenseID, Tenant: c.Tenant, Product: c.Product, Plan: c.Plan}

	ts := func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(timeLayout) // sub-second times fail the round trip
	}
	p.IAT = ts(&c.IssuedAt)
	p.NBF, p.Exp = ts(c.NotBefore), ts(c.Expires)
	p.RefreshAfter, p.UpdatesUntil = ts(c.RefreshAfter), ts(c.UpdatesUntil)
	if c.Grace != 0 {
		p.Grace = encodeDuration(c.Grace)
	}
	if c.MaxOffline != nil {
		p.MaxOffline = encodeDuration(*c.MaxOffline)
	}
	if c.CustomerID != "" || c.CustomerName != "" {
		p.Customer = &customer{c.CustomerID, c.CustomerName}
	}
	if c.Binding.Type != "" && c.Binding.Type != BindNone || c.Binding.Fingerprint != "" {
		p.Bind = &bind{string(c.Binding.Type), c.Binding.Fingerprint}
	}
	if len(c.Entitlements.Features) > 0 || len(c.Entitlements.Limits) > 0 {
		p.Entitlements = &entitlements{c.Entitlements.Features, c.Entitlements.Limits}
	}

	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(p); err != nil {
		return nil, fmt.Errorf("licensefile: encode: %w", err)
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

	got, err := ParseClaims(out)
	if err != nil {
		return nil, err
	}
	if want := normalized(c); !reflect.DeepEqual(*got, want) {
		return nil, fmt.Errorf("%w: claims don't survive encoding (empty required field, empty fingerprint, or an invalid value)", ErrMalformed)
	}
	return out, nil
}

// encodeDuration writes d as P[nD][T[nH][nM][nS]] (zero is PT0S).
// Negative, sub-second or too long durations fail the round trip.
func encodeDuration(d time.Duration) string {
	s := int64(d / time.Second)
	out := "P"
	if days := s / 86400; days > 0 {
		out += strconv.FormatInt(days, 10) + "D"
	}
	h, m, sec := s%86400/3600, s%3600/60, s%60
	if h+m+sec == 0 && s > 0 {
		return out
	}
	out += "T"
	if h > 0 {
		out += strconv.FormatInt(h, 10) + "H"
	}
	if m > 0 {
		out += strconv.FormatInt(m, 10) + "M"
	}
	if sec > 0 || s == 0 {
		out += strconv.FormatInt(sec, 10) + "S"
	}
	return out
}

// normalized is c as ParseClaims returns it: UTC times, none binding by
// default, nil for empty entitlements.
func normalized(c Claims) Claims {
	utc := func(t *time.Time) *time.Time {
		if t == nil {
			return nil
		}
		u := t.UTC()
		return &u
	}
	c.IssuedAt = c.IssuedAt.UTC()
	c.NotBefore, c.Expires = utc(c.NotBefore), utc(c.Expires)
	c.RefreshAfter, c.UpdatesUntil = utc(c.RefreshAfter), utc(c.UpdatesUntil)
	if c.Binding.Type == "" {
		c.Binding.Type = BindNone
	}
	if len(c.Entitlements.Features) == 0 {
		c.Entitlements.Features = nil
	}
	if len(c.Entitlements.Limits) == 0 {
		c.Entitlements.Limits = nil
	}
	return c
}
