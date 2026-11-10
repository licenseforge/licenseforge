package webhooks

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/invitation"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db                     *store.DB
	s                      Service
	a, b                   string // tenants
	ownerA, ownerB, viewer string
}

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	kr, err := secrets.ParseKeyring("k1=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{db: d, s: Service{DB: d, Keys: kr}}
	if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
		for _, tn := range []*string{&f.a, &f.b} {
			t, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
			if err != nil {
				return err
			}
			*tn = t.ID
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f.ownerA = f.join(t, f.a, invitation.RoleOwner, "")
	f.ownerB = f.join(t, f.b, invitation.RoleOwner, "")
	f.viewer = f.join(t, f.a, invitation.RoleViewer, f.ownerA)
	return f
}

// join makes a user a member through an invitation (the real path).
func (f fixture) join(t *testing.T, tenant string, role invitation.Role, inviter string) string {
	t.Helper()
	ctx := context.Background()
	email := strings.ToLower(ids.New("u")[2:14]) + "@example.com"
	tok := rand.Text()
	create := func(tx *ent.Tx) error {
		c := tx.Invitation.Create().SetTenantID(tenant).SetEmail(email).SetRole(role).SetScopeAll(true).
			SetTokenHash(store.InvitationTokenHash(tok)).SetExpiresAt(time.Now().Add(time.Hour))
		if inviter != "" {
			c.SetInvitedBy(inviter)
		}
		_, err := c.Save(ctx)
		return err
	}
	var err error
	if inviter == "" {
		err = f.db.WithPlatform(ctx, create)
	} else {
		err = f.db.WithTenant(ctx, tenant, create)
	}
	if err != nil {
		t.Fatal(err)
	}
	var uid string
	if err := f.db.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		u, err := tx.User.Create().SetIssuer("https://idp.example").SetSubject(ids.New("sub")).SetEmail(email).SetEmailVerified(true).Save(ctx)
		if err == nil {
			uid = u.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.AcceptInvitation(ctx, tok, uid, func(*ent.Tx, *ent.Membership) error { return nil }); err != nil {
		t.Fatal(err)
	}
	return uid
}

func (f fixture) as(tenant, user string, role authz.Role) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.User, ID: user, TenantID: tenant, Role: role, Scope: authz.Scope{All: true}})
}

// events returns the tenant's audit entries of action, newest first.
func (f fixture) events(t *testing.T, tenant, action string) []*ent.AuditEvent {
	t.Helper()
	var out []*ent.AuditEvent
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		var err error
		out, err = tx.AuditEvent.Query().Where(auditevent.Action(action)).Order(ent.Desc(auditevent.FieldSeq)).All(context.Background())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// raw reads an endpoint's stored row (tenant pool).
func (f fixture) raw(t *testing.T, tenant, id string) *ent.WebhookEndpoint {
	t.Helper()
	var row *ent.WebhookEndpoint
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		var err error
		row, err = tx.WebhookEndpoint.Get(context.Background(), id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return row
}

// scanOne runs a one-row, one-column query in tx.
func scanOne(ctx context.Context, tx *ent.Tx, dst any, q string, args ...any) error {
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return errors.Join(errors.New("no row"), rows.Err())
	}
	return rows.Scan(dst)
}

const hookURL = "https://hooks.example.com/services/T000/B000/s3cr3tTokenInPath?key=alsoSecret"

func TestCreate(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	// History the new endpoint must not get.
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		for range 3 {
			if _, err := audit.Record(ctx, tx, f.a, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "license.issue", Outcome: auditevent.OutcomeSuccess}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var head int64
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		return scanOne(ctx, tx, &head, `SELECT COALESCE(max(seq), 0) FROM audit_events WHERE tenant_id = $1`, f.a)
	}); err != nil {
		t.Fatal(err)
	}
	c, err := f.s.Create(ctx, hookURL, []string{"license.revoked", "license.issued"})
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c.Secret, "whsec_")); err != nil || len(raw) != 32 || !strings.HasPrefix(c.Secret, "whsec_") {
		t.Errorf("secret %q: %d bytes, %v", c.Secret, len(raw), err)
	}
	if c.URL != "https://hooks.example.com:443" || !c.Enabled || strings.Join(c.Events, ",") != "license.issued,license.revoked" {
		t.Errorf("created %+v", c.Endpoint)
	}
	if head < 3 || c.Seq != head || c.Attempts != 0 || c.InFlight { // from the chain's end: no history
		t.Errorf("cursor %d/%d (head %d)", c.Seq, c.Attempts, head)
	}
	// Stored encrypted, bound to tenant and row: never in the clear, and
	// useless on another row or under another purpose.
	row := f.raw(t, f.a, c.ID)
	if bytes.Contains(row.URLCiphertext, []byte("s3cr3t")) || bytes.Contains(row.SecretCiphertext, []byte(c.Secret)) {
		t.Error("stored in the clear")
	}
	if got, err := f.s.decrypt(secrets.PurposeWebhookURL, f.a, c.ID, row.URLCiphertext); err != nil || got != hookURL {
		t.Errorf("URL decrypts to %q, %v", got, err)
	}
	if got, err := f.s.decrypt(secrets.PurposeWebhookSecret, f.a, c.ID, row.SecretCiphertext); err != nil || got != c.Secret {
		t.Errorf("secret decrypts to %q, %v", got, err)
	}
	for _, b := range []secrets.Binding{{Purpose: secrets.PurposeWebhookURL, TenantID: f.b, RowID: c.ID},
		{Purpose: secrets.PurposeWebhookURL, TenantID: f.a, RowID: ids.WebhookEndpoint()}, {Purpose: secrets.PurposeWebhookSecret, TenantID: f.a, RowID: c.ID}} {
		if _, err := f.s.decrypt(b.Purpose, b.TenantID, b.RowID, row.URLCiphertext); err == nil {
			t.Errorf("URL decrypts under %+v", b)
		}
	}
	// Audited with what may be shown: never the path, query or secret.
	ev := f.events(t, f.a, "webhook.create")
	if len(ev) != 1 || ev[0].Outcome != auditevent.OutcomeSuccess || ev[0].ObjectID == nil || *ev[0].ObjectID != c.ID {
		t.Fatalf("audit %+v", ev)
	}
	if d, _ := json.Marshal(ev[0].Details); bytes.Contains(d, []byte("s3cr3t")) || bytes.Contains(d, []byte("alsoSecret")) || bytes.Contains(d, []byte("whsec_")) ||
		!bytes.Contains(d, []byte("https://hooks.example.com:443")) {
		t.Errorf("audit details %s", d)
	}
	// Reads show the same masked view, to viewers too; not to another tenant.
	got, err := f.s.Get(f.as(f.a, f.viewer, authz.Viewer), c.ID)
	if err != nil || got.URL != c.URL || got.ID != c.ID {
		t.Errorf("Get = %+v, %v", got, err)
	}
	if list, err := f.s.List(f.as(f.a, f.viewer, authz.Viewer)); err != nil || len(list) != 1 {
		t.Errorf("List = %v, %v", list, err)
	}
	if _, err := f.s.Get(f.as(f.b, f.ownerB, authz.Owner), c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another tenant's Get: %v", err)
	}
	if list, err := f.s.List(f.as(f.b, f.ownerB, authz.Owner)); err != nil || len(list) != 0 {
		t.Errorf("another tenant's List = %v, %v", list, err)
	}
}

func TestCreateRefusals(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	for name, c := range map[string]struct {
		url    string
		events []string
	}{
		"http":            {"http://hooks.example.com/x", []string{"license.issued"}},
		"credentials":     {"https://user:pw@hooks.example.com/x", []string{"license.issued"}},
		"fragment":        {"https://hooks.example.com/x#frag", []string{"license.issued"}},
		"no host":         {"https:///x", []string{"license.issued"}},
		"not a URL":       {"https://exa mple.com/", []string{"license.issued"}},
		"too long":        {"https://hooks.example.com/" + strings.Repeat("a", MaxURL), []string{"license.issued"}},
		"long host":       {"https://" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + "." + strings.Repeat("e", 60) + ".com/", []string{"license.issued"}},
		"empty fragment":  {"https://hooks.example.com/x?#", []string{"license.issued"}},
		"port too big":    {"https://hooks.example.com:99999/x", []string{"license.issued"}},
		"port zero":       {"https://hooks.example.com:0/x", []string{"license.issued"}},
		"odd host":        {"https://host;tok/x", []string{"license.issued"}},
		"unicode host":    {"https://éxample.com/x", []string{"license.issued"}},
		"no events":       {"https://hooks.example.com/x", nil},
		"unknown event":   {"https://hooks.example.com/x", []string{"license.issued", "license.bogus"}},
		"duplicate event": {"https://hooks.example.com/x", []string{"license.issued", "license.issued"}},
	} {
		if _, err := f.s.Create(ctx, c.url, c.events); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if ev := f.events(t, f.a, "webhook.create"); len(ev) != 15 || ev[0].Outcome != auditevent.OutcomeFailure {
		t.Errorf("refusals audited: %d", len(ev))
	}
	// A viewer may read but not create: denied (and audited) before its
	// input is looked at.
	if _, err := f.s.Create(f.as(f.a, f.viewer, authz.Viewer), "http://bad", nil); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer: %v", err)
	}
	if ev := f.events(t, f.a, "webhook.create"); ev[0].Outcome != auditevent.OutcomeDenied {
		t.Errorf("viewer's attempt: %s", ev[0].Outcome)
	}
	// Endpoints are tenant-wide: a product-scoped admin can't create one.
	scoped := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.New("tok"), TenantID: f.a, Role: authz.Admin,
		Scope: authz.Scope{Products: []string{ids.New("prd")}}})
	if _, err := f.s.Create(scoped, "https://hooks.example.com/x", []string{"license.issued"}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("product-scoped: %v", err)
	}
	if _, err := f.s.Create(ctx, "https://hooks.example.com/x", []string{"license.issued"}); err != nil {
		t.Fatal(err)
	}
	if list, err := f.s.List(scoped); err != nil || len(list) != 0 {
		t.Errorf("product-scoped List = %d, %v", len(list), err)
	}
}

// At most MaxEndpoints per tenant, also when creates race.
func TestEndpointLimit(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	for range MaxEndpoints - 2 {
		if _, err := f.s.Create(ctx, "https://hooks.example.com/x", []string{"license.issued"}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Go(func() { _, errs[i] = f.s.Create(ctx, "https://hooks.example.com/x", []string{"license.issued"}) })
	}
	wg.Wait()
	var ok, limited int
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrLimit):
			limited++
		default:
			t.Error(err)
		}
	}
	if list, _ := f.s.List(ctx); ok != 2 || limited != 2 || len(list) != MaxEndpoints {
		t.Errorf("%d created, %d refused, %d endpoints", ok, limited, len(list))
	}
}

func TestUpdateRotateDelete(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	c, err := f.s.Create(ctx, hookURL, []string{"license.issued"})
	if err != nil {
		t.Fatal(err)
	}
	next := "https://other.example.net:8443/new?token=t2"
	e, err := f.s.Update(ctx, c.ID, &next, []string{"activation.created"})
	if err != nil || e.URL != "https://other.example.net:8443" || strings.Join(e.Events, ",") != "activation.created" {
		t.Fatalf("Update = %+v, %v", e, err)
	}
	if got, err := f.s.decrypt(secrets.PurposeWebhookURL, f.a, c.ID, f.raw(t, f.a, c.ID).URLCiphertext); err != nil || got != next {
		t.Errorf("new URL decrypts to %q, %v", got, err)
	}
	if e, err := f.s.Update(ctx, c.ID, nil, []string{"license.bogus"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad events: %+v, %v", e, err)
	}
	if _, err := f.s.Update(f.as(f.a, f.viewer, authz.Viewer), c.ID, nil, []string{"license.issued"}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer update: %v", err)
	}
	if _, err := f.s.Update(f.as(f.b, f.ownerB, authz.Owner), c.ID, nil, []string{"license.issued"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("another tenant's update: %v", err)
	}
	// Rotation: a new secret; the old one kept, bound to its own purpose,
	// for PreviousSecretTTL.
	_, secret, err := f.s.RotateSecret(ctx, c.ID)
	if err != nil || secret == c.Secret || !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("rotate: %q, %v", secret, err)
	}
	row := f.raw(t, f.a, c.ID)
	if got, err := f.s.decrypt(secrets.PurposeWebhookSecret, f.a, c.ID, row.SecretCiphertext); err != nil || got != secret {
		t.Errorf("current secret %q, %v", got, err)
	}
	if got, err := f.s.decrypt(secrets.PurposeWebhookPrevious, f.a, c.ID, *row.PreviousSecretCiphertext); err != nil || got != c.Secret {
		t.Errorf("previous secret %q, %v", got, err)
	}
	if _, err := f.s.decrypt(secrets.PurposeWebhookSecret, f.a, c.ID, *row.PreviousSecretCiphertext); err == nil {
		t.Error("previous secret decrypts as the current one: the two can be swapped")
	}
	if row.PreviousSecretUntil == nil || time.Until(*row.PreviousSecretUntil) < PreviousSecretTTL-time.Minute {
		t.Errorf("previous until %v", row.PreviousSecretUntil)
	}
	// Delete takes the cursor and the delivery log along.
	if err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome, category, duration_ms, attempted_at)
			VALUES ($1, $2, $3, 1, $4, 'license.issued', 1, 'failure', 'timeout', 1, now())`, ids.WebhookDelivery(), f.a, c.ID, ids.AuditEvent())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Delete(f.as(f.b, f.ownerB, authz.Owner), c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another tenant's delete: %v", err)
	}
	if err := f.s.Delete(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Get(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
	var left int
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		return scanOne(ctx, tx, &left, `SELECT (SELECT count(*) FROM webhook_cursors WHERE endpoint_id = $1) + (SELECT count(*) FROM webhook_deliveries WHERE endpoint_id = $1)`, c.ID)
	}); err != nil || left != 0 {
		t.Errorf("left behind: %d, %v", left, err)
	}
	for _, action := range []string{"webhook.update", "webhook.rotate_secret", "webhook.delete"} {
		var ok *ent.AuditEvent
		for _, e := range f.events(t, f.a, action) {
			if e.Outcome == auditevent.OutcomeSuccess {
				ok = e
			}
		}
		if ok == nil {
			t.Errorf("%s not audited", action)
			continue
		}
		if d, _ := json.Marshal(ok.Details); bytes.Contains(d, []byte("token=")) || bytes.Contains(d, []byte("whsec_")) || bytes.Contains(d, []byte("s3cr3t")) {
			t.Errorf("%s details %s", action, d)
		}
	}
}

// What the display shows is what will be dialled: lower case, no trailing
// dot, the port normalized; every catalog event can be subscribed.
func TestDisplay(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	for raw, want := range map[string]string{
		"https://Hooks.Example.COM./x":    "https://hooks.example.com:443",
		"https://hooks.example.com:0443/": "https://hooks.example.com:443",
		"https://[2001:DB8::1]:8443/x":    "https://[2001:db8::1]:8443",
		"https://xn--bcher-kva.example/":  "https://xn--bcher-kva.example:443",
		"https://hooks.example.com:/x":    "https://hooks.example.com:443",
	} {
		c, err := f.s.Create(ctx, raw, Events)
		if err != nil || c.URL != want {
			t.Errorf("%s: %q, %v", raw, c.URL, err)
		}
		if err == nil {
			if err := f.s.Delete(ctx, c.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// ADR-0032: an endpoint a caller can't see is "not found", existing or not,
// so its ID can't be probed; a stale principal is refused.
func TestNotFoundBeforeDenied(t *testing.T) {
	f := setup(t)
	c, err := f.s.Create(f.as(f.a, f.ownerA, authz.Owner), hookURL, []string{"license.issued"})
	if err != nil {
		t.Fatal(err)
	}
	scoped := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.New("tok"), TenantID: f.a, Role: authz.Admin,
		Scope: authz.Scope{Products: []string{ids.New("prd")}}})
	ev := []string{"license.issued"}
	for _, id := range []string{c.ID, ids.WebhookEndpoint()} {
		if _, err := f.s.Get(scoped, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get %s: %v", id, err)
		}
		if _, err := f.s.Update(scoped, id, nil, ev); !errors.Is(err, ErrNotFound) {
			t.Errorf("Update %s: %v", id, err)
		}
		if _, _, err := f.s.RotateSecret(scoped, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Rotate %s: %v", id, err)
		}
		if err := f.s.Delete(scoped, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("Delete %s: %v", id, err)
		}
	}
	// Not a member (any more): refused in the transaction.
	gone := f.as(f.a, ids.New("usr"), authz.Owner)
	if _, err := f.s.Create(gone, hookURL, ev); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("non-member create: %v", err)
	}
	if _, err := f.s.Update(gone, c.ID, nil, ev); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("non-member update: %v", err)
	}
	if _, err := f.s.Update(f.as(f.a, f.ownerA, authz.Owner), c.ID, nil, nil); err != nil { // a merge patch with nothing in it
		t.Errorf("empty update: %v", err)
	}
	var inv *InvalidError
	if _, err := f.s.Update(f.as(f.a, f.ownerA, authz.Owner), c.ID, nil, nil, "url"); !errors.As(err, &inv) || inv.Field != "/url" {
		t.Errorf("null url: %v", err)
	}
	if _, err := f.s.Update(scoped, c.ID, nil, nil, "url"); !errors.Is(err, ErrNotFound) { // null checked after not found
		t.Errorf("null url from a caller who can't see it: %v", err)
	}
}

// Changes of one endpoint take turns: two rotations hand out two secrets,
// the later current and the earlier previous; an update racing a delete
// finds nothing.
func TestConcurrentChanges(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	c, err := f.s.Create(ctx, hookURL, []string{"license.issued"})
	if err != nil {
		t.Fatal(err)
	}
	// Both would read the same secret here without the locks.
	testHookRead = func() { time.Sleep(200 * time.Millisecond) }
	t.Cleanup(func() { testHookRead = nil })
	var wg sync.WaitGroup
	got := make([]string, 2)
	for i := range got {
		wg.Go(func() {
			var err error
			if _, got[i], err = f.s.RotateSecret(ctx, c.ID); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	row := f.raw(t, f.a, c.ID)
	cur, _ := f.s.decrypt(secrets.PurposeWebhookSecret, f.a, c.ID, row.SecretCiphertext)
	prev, _ := f.s.decrypt(secrets.PurposeWebhookPrevious, f.a, c.ID, *row.PreviousSecretCiphertext)
	if ok := (cur == got[0] && prev == got[1]) || (cur == got[1] && prev == got[0]); !ok {
		t.Errorf("after two rotations: current %q previous %q, handed out %q", cur, prev, got)
	}
	testHookRead = nil
	errs := make([]error, 2)
	wg.Go(func() { errs[0] = f.s.Delete(ctx, c.ID) })
	wg.Go(func() { _, errs[1] = f.s.Update(ctx, c.ID, nil, []string{"license.revoked"}) })
	wg.Wait()
	if errs[0] != nil || (errs[1] != nil && !errors.Is(errs[1], ErrNotFound)) {
		t.Errorf("delete and update: %v", errs)
	}
}

// A secret that can't be decrypted any more (another master key, or not
// bound to this row) is replaced, and no previous secret is kept.
func TestRotateUnreadableSecret(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	other, err := secrets.ParseKeyring("k9=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	for name, lost := range map[string]func(id string) (string, error){
		"unknown key": func(id string) (string, error) {
			return other.Encrypt([]byte("whsec_x"), secrets.Binding{Purpose: secrets.PurposeWebhookSecret, TenantID: f.a, RowID: id})
		},
		"wrong binding": func(string) (string, error) {
			return f.s.Keys.Encrypt([]byte("whsec_x"), secrets.Binding{Purpose: secrets.PurposeWebhookSecret, TenantID: f.a, RowID: ids.WebhookEndpoint()})
		},
	} {
		c, err := f.s.Create(ctx, hookURL, []string{"license.issued"})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.s.RotateSecret(ctx, c.ID); err != nil { // a previous secret to drop
			t.Fatal(err)
		}
		bad, err := lost(c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
			return tx.WebhookEndpoint.UpdateOneID(c.ID).SetSecretCiphertext([]byte(bad)).Exec(ctx)
		}); err != nil {
			t.Fatal(err)
		}
		_, secret, err := f.s.RotateSecret(ctx, c.ID)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		row := f.raw(t, f.a, c.ID)
		if got, err := f.s.decrypt(secrets.PurposeWebhookSecret, f.a, c.ID, row.SecretCiphertext); err != nil || got != secret ||
			(row.PreviousSecretCiphertext != nil && len(*row.PreviousSecretCiphertext) > 0) || row.PreviousSecretUntil != nil {
			t.Errorf("%s: after rotating: %q, %v, previous until %v", name, got, err, row.PreviousSecretUntil)
		}
		var d map[string]any
		ev := f.events(t, f.a, "webhook.rotate_secret")
		if err := json.Unmarshal([]byte(ev[0].Details), &d); err != nil || d["previous_kept"] != false {
			t.Errorf("%s: audit details %s, %v", name, ev[0].Details, err)
		}
	}
}

// Delete locks the cursor first, as the dispatcher's result transaction
// does: one recording a delivery or disabling the endpoint meanwhile
// finishes, then the delete goes ahead; no deadlock.
func TestDeleteWhileRecording(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	platform, err := sql.Open("pgx", env.PlatformURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = platform.Close() }()
	for name, q := range map[string]string{
		"record": `INSERT INTO webhook_deliveries (id, tenant_id, endpoint_id, seq, event_id, event_type, attempt, outcome, category, duration_ms, attempted_at)
			VALUES ($2, $3, $1, 1, $4, 'license.issued', 1, 'failure', 'timeout', 1, now())`,
		"disable": `UPDATE webhook_endpoints SET enabled = false, disabled_reason = 'failing', updated_at = now()
			WHERE id = $1 AND $2::text IS NOT NULL AND $3::text IS NOT NULL AND $4::text IS NOT NULL`,
	} {
		c, err := f.s.Create(ctx, hookURL, []string{"license.issued"})
		if err != nil {
			t.Fatal(err)
		}
		tx, err := platform.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE webhook_cursors SET attempts = attempts WHERE endpoint_id = $1`, c.ID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- f.s.Delete(ctx, c.ID) }()
		storetest.WaitForLockWaiter(t, env)
		if _, err := tx.Exec(q, c.ID, ids.WebhookDelivery(), f.a, ids.AuditEvent()); err != nil {
			t.Fatalf("%s while a delete waits: %v", name, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Errorf("%s: delete: %v", name, err)
		}
		if _, err := f.s.Get(ctx, c.ID); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: after delete: %v", name, err)
		}
	}
}
