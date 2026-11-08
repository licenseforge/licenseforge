package licensefile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Offline activation artifacts (ADR-0043, spec "Offline activation"): an
// activation request the app writes on an air-gapped machine, and the
// deactivation receipt it writes when it returns its seat. Both are unsigned
// (the machine has no key the vendor trusts) and carried by hand; the
// server checks them against what it issued. Same strictness as lf1 claims:
// canonical base64url, the JSON well-formedness rules, every field typed,
// and here also no unknown fields (both sides are ours).
const (
	RequestVersion = "lfreq1"
	ReceiptVersion = "lfrcpt1"
	// MaxOfflineSize bounds a request or receipt, raw UTF-8 bytes.
	MaxOfflineSize = 4096
	nonceSize      = 16
)

// Request asks the vendor's LicenseForge for an offline license file for
// this machine. Key is the license key: the request is as sensitive as it.
type Request struct {
	Tenant, Product, Key string
	Binding              Binding // machine or cluster, with its fingerprint
	FPSource             string  // where the fingerprint came from: machine-id, kubernetes, env or override
	Nonce                []byte  // 16 random bytes
	Created              time.Time
	Hostname, AppVersion string // optional
	SDKVersion           string // optional
}

// Receipt returns an offline seat: the SDK deleted the license file whose
// FileSHA256 is FileSHA256 on the machine with Fingerprint.
type Receipt struct {
	Tenant, LicenseID, Fingerprint, FileSHA256 string
	Nonce                                      []byte
	Created                                    time.Time
}

var (
	fpRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hexRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// The online activation's metadata rules, so a request carries nothing
	// the server would refuse there.
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,253}$`)
	versionRE  = regexp.MustCompile(`^[ -~]{1,64}$`)
)

// EncodeRequest returns r as an lfreq1 token, after the checks ParseRequest
// applies, so an SDK can't write a request the server refuses.
func EncodeRequest(r Request) (string, error) {
	m := map[string]any{"v": 1, "tenant": r.Tenant, "product": r.Product, "key": r.Key,
		"bind":      map[string]string{"type": string(r.Binding.Type), "fp": r.Binding.Fingerprint},
		"fp_source": r.FPSource, "nonce": b64.EncodeToString(r.Nonce), "created": r.Created.UTC().Format(timeLayout)}
	for k, v := range map[string]string{"hostname": r.Hostname, "app_version": r.AppVersion, "sdk_version": r.SDKVersion} {
		if v != "" {
			m[k] = v
		}
	}
	return encodeOffline(RequestVersion, m, func(s string) error { _, err := ParseRequest(s); return err })
}

// ParseRequest reads an lfreq1 token. Errors wrap ErrMalformed, or
// ErrUnsupportedVersion for a well-formed request with v other than 1.
func ParseRequest(s string) (*Request, error) {
	m, err := decodeOffline(RequestVersion, s, []string{"v", "tenant", "product", "key", "bind", "fp_source", "nonce", "created", "hostname", "app_version", "sdk_version"})
	if err != nil {
		return nil, err
	}
	r := &Request{}
	if r.Tenant, err = name(m, "tenant", 256); err != nil {
		return nil, err
	}
	if r.Product, err = name(m, "product", 256); err != nil {
		return nil, err
	}
	if r.Key, err = reqString(m, "key"); err != nil {
		return nil, err
	}
	if len(r.Key) > 128 || strings.ContainsFunc(r.Key, func(c rune) bool { return c < 0x21 || c > 0x7e }) {
		return nil, malformed("key must be up to 128 printable ASCII characters")
	}
	b, err := offlineBinding(m)
	if err != nil {
		return nil, err
	}
	r.Binding = b
	if r.FPSource, err = reqString(m, "fp_source"); err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"machine-id", "kubernetes", "env", "override"}, r.FPSource) {
		return nil, malformed("fp_source must be machine-id, kubernetes, env or override")
	}
	if (r.FPSource == "kubernetes") != (b.Type == BindCluster) {
		return nil, malformed("a cluster binding comes from kubernetes, and only it")
	}
	if r.Nonce, r.Created, err = nonceAndCreated(m); err != nil {
		return nil, err
	}
	for _, f := range []struct {
		key string
		dst *string
		re  *regexp.Regexp
	}{{"hostname", &r.Hostname, hostnameRE}, {"app_version", &r.AppVersion, versionRE}, {"sdk_version", &r.SDKVersion, versionRE}} {
		v, ok, err := optString(m, f.key)
		if err != nil {
			return nil, err
		}
		if ok && !f.re.MatchString(v) {
			return nil, malformed("%s %q", f.key, v)
		}
		*f.dst = v
	}
	return r, nil
}

// EncodeReceipt returns r as an lfrcpt1 token, after ParseReceipt's checks.
func EncodeReceipt(r Receipt) (string, error) {
	m := map[string]any{"v": 1, "tenant": r.Tenant, "license_id": r.LicenseID, "fp": r.Fingerprint,
		"file_sha256": r.FileSHA256, "nonce": b64.EncodeToString(r.Nonce), "created": r.Created.UTC().Format(timeLayout)}
	return encodeOffline(ReceiptVersion, m, func(s string) error { _, err := ParseReceipt(s); return err })
}

// ParseReceipt reads an lfrcpt1 token, with ParseRequest's error classes.
func ParseReceipt(s string) (*Receipt, error) {
	m, err := decodeOffline(ReceiptVersion, s, []string{"v", "tenant", "license_id", "fp", "file_sha256", "nonce", "created"})
	if err != nil {
		return nil, err
	}
	r := &Receipt{}
	if r.Tenant, err = name(m, "tenant", 256); err != nil {
		return nil, err
	}
	if r.LicenseID, err = name(m, "license_id", 128); err != nil {
		return nil, err
	}
	if r.Fingerprint, err = reqString(m, "fp"); err != nil {
		return nil, err
	}
	if !fpRE.MatchString(r.Fingerprint) {
		return nil, malformed("fp must be sha256: and 64 lowercase hex digits")
	}
	if r.FileSHA256, err = reqString(m, "file_sha256"); err != nil {
		return nil, err
	}
	if !hexRE.MatchString(r.FileSHA256) {
		return nil, malformed("file_sha256 must be 64 lowercase hex digits")
	}
	if r.Nonce, r.Created, err = nonceAndCreated(m); err != nil {
		return nil, err
	}
	return r, nil
}

// FileSHA256 is the receipt's file_sha256 of a license file: SHA-256 of its
// token (lf1.<kid>.<payload>.<signature>, armor, BOM and whitespace removed,
// as Verify reads it), lowercase hex. Line endings or a trailing newline an
// editor or a transfer adds don't change it. A file that isn't an lf1 token
// has none.
func FileSHA256(file string) (string, error) {
	if len(file) > MaxSize {
		return "", fmt.Errorf("%w: too large", ErrMalformed)
	}
	token, err := unarmor(file)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(token, Version+".") {
		return "", ErrMalformed
	}
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:]), nil
}

// decodeOffline checks the envelope (size, BOM and whitespace as for lf1,
// version prefix, canonical base64url), the JSON well-formedness rules, v,
// and that every key is one of known.
func decodeOffline(version, s string, known []string) (map[string]json.RawMessage, error) {
	if len(s) > MaxOfflineSize {
		return nil, malformed("larger than %d bytes", MaxOfflineSize)
	}
	token, err := unarmor(s)
	if err != nil {
		return nil, err
	}
	body, ok := strings.CutPrefix(token, version+".")
	if !ok || body == "" {
		return nil, malformed("not an %s token", version)
	}
	payload, err := b64.DecodeString(body)
	if err != nil {
		return nil, malformed("payload encoding")
	}
	if err := wellFormed(payload); err != nil {
		return nil, err
	}
	m, err := object(payload, true)
	if err != nil {
		return nil, err
	}
	raw, ok := m["v"]
	if !ok {
		return nil, malformed("missing v")
	}
	v, err := intToken(raw, "v")
	if err != nil {
		return nil, err
	}
	if v != "1" {
		return nil, fmt.Errorf("%w: %s v %s", ErrUnsupportedVersion, version, v)
	}
	for k := range m { // null and wrong types fail each field's own check
		if !slices.Contains(known, k) {
			return nil, malformed("unknown field %q", k)
		}
	}
	return m, nil
}

func encodeOffline(version string, m map[string]any, check func(string) error) (string, error) {
	payload, err := json.Marshal(m) // keys sorted: one encoding per artifact
	if err != nil {
		return "", fmt.Errorf("licensefile: %s: %w", version, err)
	}
	s := version + "." + b64.EncodeToString(payload)
	if err := check(s); err != nil {
		return "", err
	}
	return s, nil
}

// name is a required, non-empty string of at most max bytes without NUL.
func name(m map[string]json.RawMessage, key string, max int) (string, error) {
	s, err := reqString(m, key)
	if err == nil && (len(s) > max || strings.ContainsRune(s, 0)) {
		err = malformed("%s must be at most %d bytes without NUL", key, max)
	}
	return s, err
}

// offlineBinding is a machine or cluster binding with a well-formed fp (an
// offline request always binds; a site license needs no request).
func offlineBinding(m map[string]json.RawMessage) (Binding, error) {
	b, err := parseBinding(m) // absent: none, refused below
	if err != nil {
		return Binding{}, err
	}
	if b.Type != BindMachine && b.Type != BindCluster {
		return Binding{}, malformed("bind type must be machine or cluster")
	}
	if !fpRE.MatchString(b.Fingerprint) {
		return Binding{}, malformed("fp must be sha256: and 64 lowercase hex digits")
	}
	if bm, _, _ := optObject(m, "bind"); len(bm) != 2 {
		return Binding{}, malformed("bind has unknown fields")
	}
	return b, nil
}

func nonceAndCreated(m map[string]json.RawMessage) ([]byte, time.Time, error) {
	n, err := reqString(m, "nonce")
	if err != nil {
		return nil, time.Time{}, err
	}
	nonce, err := b64.DecodeString(n)
	if err != nil || len(nonce) != nonceSize {
		return nil, time.Time{}, malformed("nonce must be %d bytes, base64url", nonceSize)
	}
	c, err := reqString(m, "created")
	if err != nil {
		return nil, time.Time{}, err
	}
	created, err := parseTime(c)
	return nonce, created, err
}
