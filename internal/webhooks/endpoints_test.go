package webhooks

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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
	if c.Seq != head || c.Attempts != 0 || c.InFlight { // from the chain's end: no history
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
		"no events":       {"https://hooks.example.com/x", nil},
		"unknown event":   {"https://hooks.example.com/x", []string{"license.issued", "license.bogus"}},
		"duplicate event": {"https://hooks.example.com/x", []string{"license.issued", "license.issued"}},
	} {
		if _, err := f.s.Create(ctx, c.url, c.events); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if ev := f.events(t, f.a, "webhook.create"); len(ev) != 9 || ev[0].Outcome != auditevent.OutcomeFailure {
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
