//go:build e2e

package e2e

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"licenseforge.io/licenseforge/sdk/go/clock"
	"licenseforge.io/licenseforge/sdk/go/fingerprint"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
	"licenseforge.io/licenseforge/sdk/go/offline"
	"licenseforge.io/licenseforge/sdk/go/online"
)

// An air-gapped machine with the Go SDK (ADR-0043): it writes an activation
// request, the vendor answers it with a license file, the machine installs
// it; the offline seat counts against the plan's seats; a renewal is a new
// request; returning the seat is a deactivation receipt the vendor posts,
// after which the file can't be installed again. A plan without offline use
// refuses requests.
func TestOfflineJourney(t *testing.T) {
	e := loadEnv(t)
	ctx := context.Background()
	b, tn := owner(t, e)
	api := "/api/v1/tenants/" + tn.Slug
	keys := trustedKeys(t, b, tn.Slug)
	// A 12-month license with grace: the file ends at iat + max_offline_seconds,
	// without grace (the cap, not the license's expiry, ends it).
	product, lic, run := newLicense(t, b, tn, map[string]any{"offline_allowed": true, "max_offline_seconds": 30 * 86400, "grace_seconds": 3600})
	dir := t.TempDir()

	fp := func(machine, slug string) fingerprint.Result {
		t.Helper()
		r, err := fingerprint.Compute(ctx, tn.ID, slug, fingerprint.Options{Override: func() (string, error) { return machine, nil }})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	airGapped := func(machine, licenseKey, slug string) *offline.Client {
		t.Helper()
		c, err := offline.New(offline.Config{TenantID: tn.ID, Product: slug, LicenseKey: licenseKey, Keys: keys, Fingerprint: fp(machine, slug),
			Hostname: machine, AppVersion: "1.0.0", Store: clock.FileStore{Path: filepath.Join(dir, machine+".state")}})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// The vendor answers a request carried in.
	type answered struct {
		LicenseFile  string `json:"license_file"`
		ActivationID string `json:"activation_id"`
	}
	answer := func(request string) answered {
		t.Helper()
		var a answered
		b.do("POST", api+"/activation-requests", map[string]string{"request": request}, 201, &a)
		return a
	}
	connected := func(machine string) *online.Client {
		t.Helper()
		c, err := online.New(online.Config{BaseURL: e.BaseURL, TenantID: tn.ID, Product: product.Slug, LicenseKey: lic.Key, Keys: keys,
			Fingerprint: fp(machine, product.Slug), Hostname: machine, AppVersion: "1.0.0", HTTPClient: e.httpClient(t, nil, false)})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	m1, m2 := "e2e-offline-1-"+run, "e2e-offline-2-"+run
	a := airGapped(m1, lic.Key, product.Slug)
	if _, _, err := a.Current(); !errors.Is(err, offline.ErrNoLicense) {
		t.Fatalf("before install: %v", err)
	}
	req, err := a.Request()
	if err != nil {
		t.Fatal(err)
	}
	const firstKey = "e2e-offline-first-request"
	b.idem = firstKey + "-" + run
	first := answer(req)
	file := first.LicenseFile
	claims, status, err := a.Install(file)
	if err != nil || status != licensefile.StatusValid || claims.LicenseID != lic.ID || claims.Binding.Fingerprint != fp(m1, product.Slug).Fingerprint || !claims.Entitlements.HasFeature("sso") {
		t.Fatalf("install: %+v %v %v", claims, status, err)
	}
	if claims.Expires == nil || !claims.Expires.Equal(claims.IssuedAt.Add(30*24*time.Hour)) || claims.Grace != 0 {
		t.Errorf("the file ends at iat + max_offline_seconds, without grace: iat %v, exp %v, grace %v", claims.IssuedAt, claims.Expires, claims.Grace)
	}

	// The offline seat is one of the plan's: a second machine online is
	// refused, and the machine itself can't go online over its offline seat.
	if _, err := connected(m2).Activate(ctx); !errors.Is(err, online.ErrActivationLimit) {
		t.Errorf("second machine online: %v, want the activation limit", err)
	}
	if _, err := connected(m1).Activate(ctx); !errors.Is(err, online.ErrOfflineSeat) {
		t.Errorf("the offline machine online: %v, want offline_seat", err)
	}

	// Renewal: a new request from the same machine, the same seat.
	req2, err := a.Request()
	if err != nil {
		t.Fatal(err)
	}
	renewed := answer(req2).LicenseFile
	if _, _, err := a.Install(renewed); err != nil {
		t.Fatalf("install the renewal: %v", err)
	}
	if _, _, err := a.Install(file); !errors.Is(err, offline.ErrOlderFile) {
		t.Errorf("the older file over the renewal: %v, want ErrOlderFile", err)
	}

	// Returning the seat: the receipt frees it; the file can't come back.
	receipt, err := a.Deactivate()
	if err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	var act struct {
		ID, Hostname, Mode string
		DeactivatedAt      *string `json:"deactivated_at"`
	}
	b.do("POST", api+"/deactivation-receipts", map[string]string{"receipt": receipt}, 200, &act)
	if act.ID != first.ActivationID || act.DeactivatedAt == nil || act.Mode != "offline" || act.Hostname != m1 {
		t.Errorf("returned seat %+v", act)
	}
	if _, _, err := a.Current(); !errors.Is(err, offline.ErrNoLicense) {
		t.Errorf("after deactivate: %v", err)
	}
	b.do("POST", api+"/deactivation-receipts", map[string]string{"receipt": receipt}, 200, nil) // the same receipt again: unchanged, not audited
	// The first request replayed with its Idempotency-Key gets no file: its
	// seat was returned since.
	b.idem = firstKey + "-" + run
	b.refused("POST", api+"/activation-requests", map[string]string{"request": req}, 404, "not_activated")
	if _, _, err := a.Install(renewed); !errors.Is(err, offline.ErrReturned) {
		t.Errorf("reinstalling the returned file: %v, want ErrReturned", err)
	}
	if _, err := connected(m2).Activate(ctx); err != nil {
		t.Errorf("second machine after the offline seat was returned: %v", err)
	}
	// Online and offline seats stay apart the other way too.
	rm2, err := airGapped(m2, lic.Key, product.Slug).Request()
	if err != nil {
		t.Fatal(err)
	}
	b.refused("POST", api+"/activation-requests", map[string]string{"request": rm2}, 409, "online_seat")

	// A receipt naming an older file of a seat renewed since is refused: the
	// seat stays out with the newer file.
	other, lic2, _ := newLicense(t, b, tn, map[string]any{"offline_allowed": true, "max_offline_seconds": 86400})
	m3 := "e2e-offline-3-" + run
	c := airGapped(m3, lic2.Key, other.Slug)
	r1, err := c.Request()
	if err != nil {
		t.Fatal(err)
	}
	older := answer(r1).LicenseFile
	r2, err := c.Request()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Install(answer(r2).LicenseFile); err != nil {
		t.Fatal(err)
	}
	h, err := licensefile.FileSHA256(older)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := licensefile.EncodeReceipt(licensefile.Receipt{Tenant: tn.ID, LicenseID: lic2.ID, Fingerprint: fp(m3, other.Slug).Fingerprint,
		FileSHA256: h, Nonce: []byte("0123456789abcdef"), Created: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	b.refused("POST", api+"/deactivation-receipts", map[string]string{"receipt": stale}, 409, "receipt_superseded")
	current, err := c.Deactivate() // the current file's receipt frees it
	if err != nil {
		t.Fatal(err)
	}
	b.do("POST", api+"/deactivation-receipts", map[string]string{"receipt": current}, 200, nil)

	// The vendor's lever over offline files: a suspended or revoked license
	// gets none. This request goes without an Idempotency-Key, as the CLI sends it.
	r4, err := c.Request()
	if err != nil {
		t.Fatal(err)
	}
	b.do("POST", api+"/licenses/"+lic2.ID+"/suspend", nil, 200, nil)
	b.idem = "-"
	b.refused("POST", api+"/activation-requests", map[string]string{"request": r4}, 403, "license_suspended")
	b.do("POST", api+"/licenses/"+lic2.ID+"/reinstate", nil, 200, nil)
	b.idem = "-"
	if _, _, err := c.Install(answer(r4).LicenseFile); err != nil { // without a key
		t.Fatal(err)
	}
	b.do("POST", api+"/licenses/"+lic2.ID+"/revoke", nil, 200, nil)
	r5, err := c.Request()
	if err != nil {
		t.Fatal(err)
	}
	b.refused("POST", api+"/activation-requests", map[string]string{"request": r5}, 403, "license_revoked")

	// A plan without offline use refuses requests.
	plain, lic3, _ := newLicense(t, b, tn, nil)
	r3, err := airGapped("e2e-offline-4-"+run, lic3.Key, plain.Slug).Request()
	if err != nil {
		t.Fatal(err)
	}
	b.refused("POST", api+"/activation-requests", map[string]string{"request": r3}, 409, "offline_not_allowed")

	// The audit chain has this run's offline activation and its return,
	// as successes, once each (the second post of the receipt isn't audited).
	type entry struct {
		Action, Outcome string
		ObjectID        *string `json:"object_id"`
	}
	var audit struct{ Items []entry }
	b.do("GET", api+"/audit-events?limit=100", nil, 200, &audit)
	for _, want := range []string{"activation.offline", "activation.offline_return"} {
		n := 0
		for _, x := range audit.Items {
			if x.Action == want && x.Outcome == "success" && x.ObjectID != nil && *x.ObjectID == first.ActivationID {
				n++
			}
		}
		if want == "activation.offline" && n != 2 || want == "activation.offline_return" && n != 1 { // the first file and the renewal
			t.Errorf("%d successful %s for %s", n, want, first.ActivationID)
		}
	}
}
