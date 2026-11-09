// Package ids generates prefixed random IDs. It is separate from package store
// so ent schemas can use it without an import cycle.
package ids

import (
	"crypto/rand"
	"encoding/base32"
	"regexp"
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

var body = regexp.MustCompile(`^[a-z2-7]{26}$`)

// Valid reports whether id is prefix + "_" + 26 base32 characters, the form
// New produces (and the *_id_format CHECKs enforce). Check untrusted IDs with
// it before they reach a query or an audit entry.
func Valid(prefix, id string) bool {
	return len(id) == len(prefix)+27 && id[:len(prefix)+1] == prefix+"_" && body.MatchString(id[len(prefix)+1:])
}

// Generators for each entity, used as ent default functions.
func Tenant() string            { return New("tnt") }
func Product() string           { return New("prd") }
func Feature() string           { return New("ftr") }
func Plan() string              { return New("pln") }
func PlanFeature() string       { return New("plf") }
func Customer() string          { return New("cus") }
func License() string           { return New("lic") }
func Activation() string        { return New("act") }
func SigningKey() string        { return New("sk") }
func User() string              { return New("usr") }
func Invitation() string        { return New("inv") }
func InvitationProduct() string { return New("ivp") }
func Membership() string        { return New("mem") }
func MembershipProduct() string { return New("mbp") }
func APIToken() string          { return New("tok") }
func APITokenProduct() string   { return New("tkp") }
func Session() string           { return New("ses") }
func PlatformAdmin() string     { return New("pad") }
func AuditEvent() string        { return New("aud") }
func AuditExportCursor() string { return New("aec") }
func AuditAnchor() string       { return New("anc") }
func IdempotencyKey() string    { return New("idk") }
func WebhookEndpoint() string   { return New("whe") }
func WebhookCursor() string     { return New("whc") }
func WebhookDelivery() string   { return New("whd") }
