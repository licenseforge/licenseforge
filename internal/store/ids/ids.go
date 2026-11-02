// Package ids generates prefixed random IDs. It is separate from package store
// so ent schemas can use it without an import cycle.
package ids

import (
	"crypto/rand"
	"encoding/base32"
)

var enc = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// New returns prefix + "_" + 26 lowercase base32 characters (128 random bits).
// Prefixes make IDs readable in logs and licenses and stop IDs of different
// kinds being mixed up.
func New(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	return prefix + "_" + enc.EncodeToString(b[:])
}

// Generators for each entity, used as ent default functions.
func Tenant() string      { return New("tnt") }
func Product() string     { return New("prd") }
func Feature() string     { return New("ftr") }
func Plan() string        { return New("pln") }
func PlanFeature() string { return New("plf") }
func Customer() string    { return New("cus") }
func License() string     { return New("lic") }
func Activation() string  { return New("act") }
