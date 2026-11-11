//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"licenseforge.io/licenseforge/sdk/go/fingerprint"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
	"licenseforge.io/licenseforge/sdk/go/online"
)

type tenant struct {
	ID   string `json:"tenant_id"`
	Slug string `json:"slug"`
	Role string `json:"role"`
}

// owner signs in as the test tenant's owner, accepting the invitation up.sh
// made with licenseforge tenant create on the first run.
func owner(t *testing.T, e env) (*browser, tenant) {
	t.Helper()
	b := login(t, e, "admin", "licenseforge")
	find := func() *tenant {
		var page struct{ Items []tenant }
		b.do("GET", "/api/v1/me/tenants", nil, 200, &page)
		for _, tn := range page.Items {
			if tn.Slug == e.Tenant {
				return &tn
			}
		}
		return nil
	}
	tn := find()
	if tn == nil {
		token, err := os.ReadFile(e.InviteTokenFile)
		if err != nil {
			t.Fatalf("not a member of %q and no invitation from up.sh: %v", e.Tenant, err)
		}
		b.do("POST", "/api/v1/invitations/accept", map[string]string{"token": strings.TrimSpace(string(token))}, 200, nil)
		if tn = find(); tn == nil {
			t.Fatalf("accepted the invitation from up.sh, still not a member of %q", e.Tenant)
		}
	}
	if tn.Role != "owner" {
		t.Fatalf("role in %q is %s, want owner", e.Tenant, tn.Role)
	}
	return b, *tn
}

// trustedKeys is what a vendor embeds in a build: the tenant's public
// signing keys, from the signing keys API; one is created on a fresh tenant.
func trustedKeys(t *testing.T, b *browser, tenant string) licensefile.KeySet {
	t.Helper()
	type key struct {
		KID, Alg, Status string
		PublicKey        string `json:"public_key"`
	}
	var page struct{ Items []key }
	b.do("GET", "/api/v1/tenants/"+tenant+"/signing-keys", nil, 200, &page)
	if !slices.ContainsFunc(page.Items, func(k key) bool { return k.Status == "active" }) {
		b.do("POST", "/api/v1/tenants/"+tenant+"/signing-keys", map[string]any{}, 201, nil)
		b.do("GET", "/api/v1/tenants/"+tenant+"/signing-keys", nil, 200, &page)
	}
	var ks licensefile.KeySet
	for _, k := range page.Items {
		raw, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
		if err != nil {
			t.Fatalf("key %s: %v", k.KID, err)
		}
		ks = append(ks, licensefile.PublicKey{KID: k.KID, Alg: k.Alg, Key: raw})
	}
	return ks
}

type issued struct{ ID, Key string }

type catalog struct{ ID, Slug string }

// newLicense makes this run's catalog and a license: a product, an on/off
// feature and a limit, a machine-bound plan with one seat that grants both.
// terms are added to the plan's. run names this run's objects: runs never
// depend on each other.
func newLicense(t *testing.T, b *browser, tn tenant, terms map[string]any) (product catalog, lic issued, run string) {
	t.Helper()
	api := "/api/v1/tenants/" + tn.Slug
	run = strings.ToLower(rand.Text()[:8])
	b.do("POST", api+"/products", map[string]string{"slug": "e2e-" + run, "name": "E2E " + run}, 201, &product)
	for _, f := range []map[string]string{{"key": "sso", "name": "SSO", "type": "boolean"}, {"key": "seats", "name": "Seats", "type": "limit"}} {
		f["product_id"] = product.ID
		b.do("POST", api+"/features", f, 201, nil)
	}
	var plan struct{ ID string }
	p := map[string]any{"product_id": product.ID, "slug": "pro", "name": "Pro", "duration_months": 12, "max_activations": 1}
	maps.Copy(p, terms)
	b.do("POST", api+"/plans", p, 201, &plan)
	b.do("PATCH", api+"/plans/"+plan.ID+"/features", map[string]any{"sso": true, "seats": 25}, 200, nil)
	var customer struct{ ID string }
	b.do("POST", api+"/customers", map[string]string{"name": "Customer " + run}, 201, &customer)

	// Issue: the key is shown once.
	b.do("POST", api+"/licenses", map[string]string{"product_id": product.ID, "plan_id": plan.ID, "customer_id": customer.ID, "type": "paid"}, 201, &lic)
	if lic.Key == "" {
		t.Fatal("issued without a key")
	}
	return product, lic, run
}

// The vendor's journey and its customer's app: a catalog, a license, a
// machine that activates and checks entitlements offline from a verified
// lease, the seat limit, a refresh, then revocation ending the license.
func TestLicenseJourney(t *testing.T) {
	e := loadEnv(t)
	ctx := context.Background()
	b, tn := owner(t, e)
	api := "/api/v1/tenants/" + tn.Slug
	keys := trustedKeys(t, b, tn.Slug)
	product, lic, run := newLicense(t, b, tn, nil)

	// The customer's app: the SDK as a vendor configures it.
	app := func(machine string) *online.Client {
		t.Helper()
		fp, err := fingerprint.Compute(ctx, tn.ID, product.Slug, fingerprint.Options{Override: func() (string, error) { return machine, nil }})
		if err != nil {
			t.Fatal(err)
		}
		c, err := online.New(online.Config{
			BaseURL: e.BaseURL, TenantID: tn.ID, Product: product.Slug, LicenseKey: lic.Key, Keys: keys,
			Fingerprint: fp, Hostname: machine, AppVersion: "1.0.0", HTTPClient: e.httpClient(t, nil, false),
		})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	first := app("e2e-machine-1-" + run)
	if _, err := first.Activate(ctx); err != nil {
		t.Fatalf("activate: %v", err)
	}
	claims, status, err := first.Current()
	if err != nil || status != licensefile.StatusValid {
		t.Fatalf("lease: %v, %v", status, err)
	}
	if claims.LicenseID != lic.ID || claims.Tenant != tn.ID || claims.Product != product.Slug || claims.Plan != "pro" {
		t.Errorf("claims %+v", claims)
	}
	if !claims.Entitlements.HasFeature("sso") || claims.Entitlements.Limit("seats") != 25 || claims.Entitlements.HasFeature("nope") {
		t.Errorf("entitlements %+v", claims.Entitlements)
	}

	// One seat: a second machine is refused until the first frees it.
	second := app("e2e-machine-2-" + run)
	if _, err := second.Activate(ctx); !errors.Is(err, online.ErrActivationLimit) {
		t.Errorf("second machine: %v, want the activation limit", err)
	}
	if _, err := first.Refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := first.Deactivate(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, err := second.Activate(ctx); err != nil {
		t.Fatalf("second machine after the first freed its seat: %v", err)
	}

	// The dashboard sees both machines, one deactivated; revoking ends the
	// license at the next refresh.
	type activation struct {
		ID, Hostname  string
		DeactivatedAt *string `json:"deactivated_at"`
	}
	var acts struct{ Items []activation }
	b.do("GET", api+"/licenses/"+lic.ID+"/activations", nil, 200, &acts)
	active := slices.IndexFunc(acts.Items, func(a activation) bool { return a.DeactivatedAt == nil })
	if len(acts.Items) != 2 || active < 0 || acts.Items[active].Hostname != "e2e-machine-2-"+run {
		t.Errorf("activations %+v", acts.Items)
	}
	b.do("POST", api+"/licenses/"+lic.ID+"/revoke", nil, 200, nil)
	if _, err := second.Refresh(ctx); !errors.Is(err, online.ErrRevoked) {
		t.Errorf("refresh after revoke: %v, want revoked", err)
	}

	// Every step of this run is on the tenant's audit chain: entries for this
	// license and its activations, not an earlier run's.
	type entry struct {
		Action   string
		ObjectID *string `json:"object_id"`
	}
	var audit struct{ Items []entry }
	b.do("GET", api+"/audit-events?limit=100", nil, 200, &audit)
	ours := func(action, object string) bool {
		return slices.ContainsFunc(audit.Items, func(a entry) bool { return a.Action == action && a.ObjectID != nil && *a.ObjectID == object })
	}
	for _, a := range acts.Items {
		if !ours("activation.create", a.ID) {
			t.Errorf("no activation.create for %s", a.ID)
		}
	}
	for _, action := range []string{"license.issue", "license.revoke"} {
		if !ours(action, lic.ID) {
			t.Errorf("no %s for %s", action, lic.ID)
		}
	}
}

// The invite flow, and roles enforced by the server: the owner invites the
// viewer, who accepts, can read the catalog, but can't change it.
func TestInvitedViewerCannotWrite(t *testing.T) {
	e := loadEnv(t)
	own, tn := owner(t, e)
	viewer := login(t, e, "viewer", "licenseforge")
	api := "/api/v1/tenants/" + tn.Slug
	type member struct{ ID, Email string }
	removeViewer := func() {
		var members struct{ Items []member }
		own.do("GET", api+"/members", nil, 200, &members)
		for _, m := range members.Items {
			if m.Email == "viewer@licenseforge.local" {
				own.do("DELETE", api+"/members/"+m.ID, nil, 204, nil)
			}
		}
	}
	// Removed after the test too, so every run goes through the invite.
	removeViewer()
	t.Cleanup(removeViewer)
	var inv struct{ Token string }
	own.do("POST", api+"/invitations", map[string]any{"email": "viewer@licenseforge.local", "role": "viewer", "all_products": true}, 201, &inv)
	viewer.do("POST", "/api/v1/invitations/accept", map[string]string{"token": inv.Token}, 200, nil)
	if !slices.ContainsFunc(memberships(viewer), func(x tenant) bool { return x.Slug == tn.Slug && x.Role == "viewer" }) {
		t.Fatal("accepted, but not a viewer of the tenant")
	}
	viewer.do("GET", api+"/products", nil, 200, nil)
	// Refused by the role, not by anything else (a CSRF refusal is 403 too).
	viewer.refused("POST", api+"/products", map[string]string{"slug": "nope", "name": "Nope"}, http.StatusForbidden, "forbidden")
	viewer.refused("POST", api+"/signing-keys", map[string]any{}, http.StatusForbidden, "forbidden")
}

func memberships(b *browser) []tenant {
	var page struct{ Items []tenant }
	b.do("GET", "/api/v1/me/tenants", nil, 200, &page)
	return page.Items
}

// Tenant onboarding (ADR-0042): the platform admin (admin, the bootstrap
// admin) creates a tenant with an owner invitation for viewer, without
// joining it; viewer accepts and owns it. viewer, not a platform admin,
// is refused the platform API. Each run makes a new tenant.
func TestPlatformAdminOnboardsTenant(t *testing.T) {
	e := loadEnv(t)
	admin, _ := owner(t, e) // signed in at least once: the bootstrap grant
	viewer := login(t, e, "viewer", "licenseforge")
	viewer.refused("GET", "/api/v1/platform/tenants", nil, http.StatusForbidden, "forbidden")
	viewer.refused("POST", "/api/v1/platform/tenants", map[string]string{"slug": "nope-" + strings.ToLower(rand.Text()[:8]), "name": "Nope", "owner_email": "viewer@licenseforge.local"}, http.StatusForbidden, "forbidden")

	slug := "onboard-" + strings.ToLower(rand.Text()[:10])
	var created struct {
		Tenant     struct{ ID, Slug string }
		Invitation struct{ Email, Role, Token string }
	}
	admin.do("POST", "/api/v1/platform/tenants", map[string]string{"slug": slug, "name": "Onboarded " + slug, "owner_email": "viewer@licenseforge.local"}, 201, &created)
	if created.Tenant.Slug != slug || created.Invitation.Role != "owner" || created.Invitation.Token == "" {
		t.Fatalf("created %+v", created)
	}
	var page struct{ Items []struct{ Slug string } }
	admin.do("GET", "/api/v1/platform/tenants?limit=200", nil, 200, &page)
	if !slices.ContainsFunc(page.Items, func(x struct{ Slug string }) bool { return x.Slug == slug }) {
		t.Errorf("%s isn't in the platform list", slug)
	}
	if slices.ContainsFunc(memberships(admin), func(x tenant) bool { return x.Slug == slug }) {
		t.Error("the platform admin joined the tenant")
	}
	admin.refused("POST", "/api/v1/platform/tenants", map[string]string{"slug": slug, "name": "Again", "owner_email": "viewer@licenseforge.local"}, http.StatusConflict, "conflict")

	// The accept's answer, not viewer's tenant list: that list is capped and
	// grows by one tenant per run.
	var joined struct {
		TenantID string `json:"tenant_id"`
		Role     string
	}
	viewer.do("POST", "/api/v1/invitations/accept", map[string]string{"token": created.Invitation.Token}, 200, &joined)
	if joined.TenantID != created.Tenant.ID || joined.Role != "owner" {
		t.Fatalf("accepted: %+v", joined)
	}
	viewer.do("POST", "/api/v1/tenants/"+slug+"/products", map[string]string{"slug": "first", "name": "First product"}, 201, nil)
}
