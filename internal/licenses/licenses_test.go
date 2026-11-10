package licenses

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/licensekey"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/internal/store/ent/planfeature"
	storeids "licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/schema"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

// tenantData is one tenant's catalog: product P with plan "pro" (12 months,
// sso, seats=10), a second product Q with its own plan, and a customer.
type tenantData struct {
	id, prodP, prodQ string
	pro, planQ       *ent.Plan
	customer         string
	seats, sso       string // plan feature IDs on pro
}

type fixture struct {
	db   *store.DB
	kr   *secrets.Keyring
	s    Service
	a, b tenantData
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
	f := fixture{db: d, kr: kr, s: Service{DB: d, Keys: kr}}
	for _, td := range []*tenantData{&f.a, &f.b} {
		if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
			tn, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
			if err == nil {
				td.id = tn.ID
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := d.WithTenant(ctx, td.id, func(tx *ent.Tx) error {
			p, err := tx.Product.Create().SetTenantID(td.id).SetSlug("db").SetName("DB").Save(ctx)
			if err != nil {
				return err
			}
			q, err := tx.Product.Create().SetTenantID(td.id).SetSlug("other").SetName("Other").Save(ctx)
			if err != nil {
				return err
			}
			td.prodP, td.prodQ = p.ID, q.ID
			if td.pro, err = tx.Plan.Create().SetTenantID(td.id).SetProductID(p.ID).SetSlug("pro").SetName("Pro").
				SetDurationMonths(12).SetMaxActivations(3).SetMaxRehosts(2).SetOfflineAllowed(true).
				SetLeaseSeconds(3600).SetMaxOfflineSeconds(7200).SetGraceSeconds(60).Save(ctx); err != nil {
				return err
			}
			if td.planQ, err = tx.Plan.Create().SetTenantID(td.id).SetProductID(q.ID).SetSlug("q").SetName("Q").Save(ctx); err != nil {
				return err
			}
			for _, ft := range []struct {
				key   string
				typ   feature.Type
				limit *int64
				id    *string
			}{{"sso", feature.TypeBoolean, nil, &td.sso}, {"seats", feature.TypeLimit, ptr[int64](10), &td.seats}, {"export", feature.TypeBoolean, nil, nil}, {"nodes", feature.TypeLimit, nil, nil}} {
				fe, err := tx.Feature.Create().SetTenantID(td.id).SetProductID(p.ID).SetKey(ft.key).SetName(ft.key).SetType(ft.typ).Save(ctx)
				if err != nil {
					return err
				}
				if ft.id == nil {
					continue
				}
				pf, err := tx.PlanFeature.Create().SetTenantID(td.id).SetProductID(p.ID).SetPlanID(td.pro.ID).SetFeatureID(fe.ID).
					SetFeatureType(planfeature.FeatureType(ft.typ)).SetNillableLimitValue(ft.limit).Save(ctx)
				if err != nil {
					return err
				}
				*ft.id = pf.ID
			}
			// Features of other states, for override checks.
			// Inserted unarchived (insert_unarchived), then archived.
			for key, typ := range map[string]feature.Type{"legacy": feature.TypeBoolean, "legacy_seats": feature.TypeLimit} {
				fe, err := tx.Feature.Create().SetTenantID(td.id).SetProductID(p.ID).SetKey(key).SetName(key).SetType(typ).Save(ctx)
				if err != nil {
					return err
				}
				if err := tx.Feature.UpdateOne(fe).SetArchivedAt(time.Now()).Exec(ctx); err != nil {
					return err
				}
			}
			if _, err := tx.Feature.Create().SetTenantID(td.id).SetProductID(q.ID).SetKey("q_only").SetName("Q only").
				SetType(feature.TypeBoolean).Save(ctx); err != nil {
				return err
			}
			c, err := tx.Customer.Create().SetTenantID(td.id).SetName("Contoso").Save(ctx)
			td.customer = c.ID
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func ptr[T any](v T) *T { return &v }

func as(tenant string, role authz.Role, scope authz.Scope) authz.Principal {
	return authz.Principal{Kind: authz.User, ID: "usr_test", TenantID: tenant, Role: role, Scope: scope}
}

var all = authz.Scope{All: true}

func (f fixture) req(td tenantData) IssueRequest {
	return IssueRequest{ProductID: td.prodP, PlanID: td.pro.ID, CustomerID: td.customer}
}

func (f fixture) tx(t *testing.T, tenant string, fn func(tx *ent.Tx) error) {
	t.Helper()
	if err := f.db.WithTenant(context.Background(), tenant, fn); err != nil {
		t.Fatal(err)
	}
}

// lastEvent returns the newest audit entry of the tenant and checks the chain.
func (f fixture) lastEvent(t *testing.T, tenant string) *ent.AuditEvent {
	t.Helper()
	var e *ent.AuditEvent
	if _, err := audit.Verify(context.Background(), func(ctx context.Context, snap bool, fn func(*ent.Tx) error) error {
		return f.db.ReadTenant(ctx, tenant, snap, fn)
	}, tenant, audit.Head{}); err != nil {
		t.Fatal(err)
	}
	f.tx(t, tenant, func(tx *ent.Tx) error {
		var err error
		e, err = tx.AuditEvent.Query().Order(ent.Desc(auditevent.FieldSeq)).First(context.Background())
		return err
	})
	return e
}

func (f fixture) count(t *testing.T, tenant string) (licenses, events int) {
	t.Helper()
	f.tx(t, tenant, func(tx *ent.Tx) error {
		var err error
		if licenses, err = tx.License.Query().Count(context.Background()); err != nil {
			return err
		}
		events, err = tx.AuditEvent.Query().Count(context.Background())
		return err
	})
	return
}

func (f fixture) get(t *testing.T, tenant, id string) *ent.License {
	t.Helper()
	var l *ent.License
	f.tx(t, tenant, func(tx *ent.Tx) (err error) { l, err = tx.License.Get(context.Background(), id); return })
	return l
}

func TestIssueCopiesPlanAndKey(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	req := f.req(f.a)
	req.Type, req.ExternalRefs = license.TypeTrial, map[string]string{"order": "SO-1"}
	req.Overrides = map[string]Override{"seats": {Limit: ptr[int64](25)}, "sso": {Remove: true}, "export": {}}
	var dbBefore time.Time
	f.tx(t, f.a.id, func(tx *ent.Tx) (err error) { dbBefore, err = DBNow(ctx, tx); return })
	got, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, all), req)
	if err != nil {
		t.Fatal(err)
	}
	l := f.get(t, f.a.id, got.License.ID)
	want := schema.LicenseEntitlements{Features: []string{"export"}, Limits: map[string]int64{"seats": 25}}
	if l.ProductID != f.a.prodP || l.PlanID != f.a.pro.ID || l.PlanSlug != "pro" || l.CustomerID != f.a.customer ||
		l.Type != license.TypeTrial || l.Status != license.StatusActive || l.ExpiryBasis != license.ExpiryBasisFromIssue ||
		*l.DurationMonths != 12 || l.DurationSeconds != nil || *l.MaxActivations != 3 || *l.MaxRehosts != 2 ||
		l.BindType != license.BindTypeMachine || !l.OfflineAllowed || l.LeaseSeconds != 3600 || *l.MaxOfflineSeconds != 7200 ||
		l.GraceSeconds != 60 || !reflect.DeepEqual(l.Entitlements, want) || l.ExternalRefs["order"] != "SO-1" ||
		l.IssuedAt.Before(dbBefore) || l.IssuedAt.After(dbBefore.Add(time.Minute)) || !l.ExpiresAt.Equal(*Expiry(l.IssuedAt, ptr(12), nil)) {
		t.Errorf("license = %+v, entitlements %+v", l, l.Entitlements)
	}

	// The key: canonical, returned once, stored only encrypted with its lookup hash and hint.
	if k, err := licensekey.Normalize(got.Key); err != nil || k != got.Key {
		t.Fatalf("key %q not canonical: %v", got.Key, err)
	}
	pt, err := f.kr.Decrypt(l.KeyCiphertext, secrets.Binding{Purpose: secrets.PurposeLicenseKey, TenantID: f.a.id, RowID: l.ID})
	if err != nil || string(pt) != got.Key {
		t.Errorf("ciphertext decrypts to %q, %v", pt, err)
	}
	if h, _ := f.kr.LookupHash(secrets.PurposeLicenseKey, []byte(got.Key)); l.KeyLookup != h || l.KeyHint != got.Key[len(got.Key)-6:] {
		t.Errorf("lookup %s hint %s", l.KeyLookup, l.KeyHint)
	}
	var row string
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT row_to_json(l)::text FROM licenses l WHERE id = $1`, l.ID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		rows.Next()
		return rows.Scan(&row)
	})
	body := strings.ReplaceAll(strings.TrimPrefix(got.Key, "LF-"), "-", "")
	if row == "" || strings.Contains(row, got.Key) || strings.Contains(row, body) || strings.Contains(row, body[:20]) {
		t.Errorf("plaintext key stored: %s", row)
	}

	e := f.lastEvent(t, f.a.id)
	if e.Action != "license.issue" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != l.ID || *e.ActorID != "usr_test" ||
		strings.Contains(e.Details, body[:20]) || strings.Contains(e.Details, l.KeyHint) || strings.Contains(e.Details, l.KeyLookup) {
		t.Errorf("audit = %+v", e)
	}
	// The entry records what was granted.
	for _, w := range []string{`"plan_id":"` + f.a.pro.ID + `"`, `"plan_slug":"pro"`, `"customer_id":"` + f.a.customer + `"`,
		`"type":"trial"`, `"expires_at":"` + l.ExpiresAt.UTC().Format(time.RFC3339Nano) + `"`,
		`"overrides":{"export":"granted","seats":25,"sso":"removed"}`} {
		if !strings.Contains(e.Details, w) {
			t.Errorf("details %s lack %s", e.Details, w)
		}
	}
}

func TestPlanEditsDontTouchSoldLicenses(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	got, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, all), f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	before := f.get(t, f.a.id, got.License.ID)
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		if err := tx.Plan.UpdateOneID(f.a.pro.ID).SetDurationMonths(1).SetMaxActivations(99).SetLeaseSeconds(10).
			SetOfflineAllowed(false).SetExpiryBasis(plan.ExpiryBasisFromFirstActivation).Exec(ctx); err != nil {
			return err
		}
		if err := tx.PlanFeature.UpdateOneID(f.a.seats).SetLimitValue(500).Exec(ctx); err != nil {
			return err
		}
		return tx.PlanFeature.DeleteOneID(f.a.sso).Exec(ctx)
	})
	after := f.get(t, f.a.id, got.License.ID)
	if before.String() != after.String() || before.KeyCiphertext != after.KeyCiphertext { // String has every other field
		t.Errorf("license changed by a plan edit:\n%+v\n%+v", before, after)
	}
	// A new license gets the edited plan.
	got2, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, all), f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	if l := got2.License; *l.MaxActivations != 99 || len(l.Entitlements.Features) != 0 || l.Entitlements.Limits["seats"] != 500 {
		t.Errorf("new license = %+v %+v", l, l.Entitlements)
	}
}

func TestOverrides(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	p := as(f.a.id, authz.Manager, all)
	req := f.req(f.a)
	req.Overrides = map[string]Override{"sso": {Remove: true}, "export": {}, "seats": {Limit: ptr[int64](-1)}, "nodes": {Limit: ptr[int64](1<<53 - 1)}}
	got, err := f.s.Issue(ctx, p, req)
	if err != nil {
		t.Fatal(err)
	}
	want := schema.LicenseEntitlements{Features: []string{"export"}, Limits: map[string]int64{"seats": -1, "nodes": 1<<53 - 1}}
	if l := f.get(t, f.a.id, got.License.ID); !reflect.DeepEqual(l.Entitlements, want) {
		t.Errorf("entitlements = %+v", l.Entitlements)
	}
	if e := f.lastEvent(t, f.a.id); !strings.Contains(e.Details, `"overrides":{"export":"granted","nodes":9007199254740991,"seats":-1,"sso":"removed"}`) {
		t.Errorf("details = %s", e.Details)
	}

	for name, o := range map[string]map[string]Override{
		"unknown feature":          {"nope": {}},
		"another product's":        {"q_only": {}},
		"limit on a boolean":       {"sso": {Limit: ptr[int64](1)}},
		"limit feature, no limit":  {"seats": {}},
		"limit below -1":           {"seats": {Limit: ptr[int64](-2)}},
		"limit above 2^53-1":       {"seats": {Limit: ptr[int64](1 << 53)}},
		"remove with a limit":      {"seats": {Remove: true, Limit: ptr[int64](1)}},
		"archived feature granted": {"legacy": {}},
		"archived limit changed":   {"legacy_seats": {Limit: ptr[int64](5)}},
	} {
		t.Run(name, func(t *testing.T) {
			lic, ev := f.count(t, f.a.id)
			req := f.req(f.a)
			req.Overrides = o
			if _, err := f.s.Issue(ctx, p, req); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v", err)
			}
			lic2, ev2 := f.count(t, f.a.id)
			e := f.lastEvent(t, f.a.id)
			if lic2 != lic || ev2 != ev+1 || e.Action != "license.issue" || e.Outcome != auditevent.OutcomeFailure || e.ObjectID != nil {
				t.Errorf("licenses %d→%d, events %d→%d, last %+v", lic, lic2, ev, ev2, e)
			}
		})
	}
	// Errors are deterministic: the first bad key in sorted order.
	for range 5 {
		req := f.req(f.a)
		req.Overrides = map[string]Override{"zz_nope": {}, "aa_nope": {}, "mm_nope": {}}
		var inv *InvalidError
		if _, err := f.s.Issue(ctx, p, req); !errors.As(err, &inv) || inv.Field != "/overrides/aa_nope" {
			t.Fatalf("err = %v", err)
		}
	}
	// Removing an archived feature is allowed (a no-op: it isn't granted).
	req.Overrides = map[string]Override{"legacy": {Remove: true}}
	if _, err := f.s.Issue(ctx, p, req); err != nil {
		t.Error(err)
	}
}

func TestIssueRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mgr := as(f.a.id, authz.Manager, all)
	var archivedPlan, archivedCustomer string
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		// Inserted unarchived (insert_unarchived), then archived.
		pl, err := tx.Plan.Create().SetTenantID(f.a.id).SetProductID(f.a.prodP).SetSlug("old").SetName("Old").Save(ctx)
		if err != nil {
			return err
		}
		if err := tx.Plan.UpdateOne(pl).SetArchivedAt(time.Now()).Exec(ctx); err != nil {
			return err
		}
		c, err := tx.Customer.Create().SetTenantID(f.a.id).SetName("Gone").Save(ctx)
		if err != nil {
			return err
		}
		archivedPlan, archivedCustomer = pl.ID, c.ID
		return tx.Customer.UpdateOne(c).SetArchivedAt(time.Now()).Exec(ctx)
	})
	for _, tc := range []struct {
		name    string
		p       authz.Principal
		change  func(*IssueRequest)
		want    error
		outcome auditevent.Outcome
	}{
		{"another tenant's plan", mgr, func(r *IssueRequest) { r.PlanID = f.b.pro.ID }, ErrInvalid, auditevent.OutcomeFailure},
		{"another tenant's customer", mgr, func(r *IssueRequest) { r.CustomerID = f.b.customer }, ErrInvalid, auditevent.OutcomeFailure},
		{"another tenant's product", mgr, func(r *IssueRequest) { r.ProductID = f.b.prodP }, ErrInvalid, auditevent.OutcomeFailure},
		{"another tenant's product and plan", mgr, func(r *IssueRequest) { r.ProductID, r.PlanID = f.b.prodP, f.b.pro.ID }, ErrInvalid, auditevent.OutcomeFailure},
		{"plan of another product", mgr, func(r *IssueRequest) { r.PlanID = f.a.planQ.ID }, ErrInvalid, auditevent.OutcomeFailure},
		{"archived plan", mgr, func(r *IssueRequest) { r.PlanID = archivedPlan }, ErrInvalid, auditevent.OutcomeFailure},
		{"archived customer", mgr, func(r *IssueRequest) { r.CustomerID = archivedCustomer }, ErrInvalid, auditevent.OutcomeFailure},
		{"malformed plan ID", mgr, func(r *IssueRequest) { r.PlanID = "pln_x" }, ErrInvalid, auditevent.OutcomeFailure},
		{"unknown type", mgr, func(r *IssueRequest) { r.Type = "gold" }, ErrInvalid, auditevent.OutcomeFailure},
		{"unknown product", mgr, func(r *IssueRequest) { r.ProductID = "prd_00000000000000000000000000" }, ErrInvalid, auditevent.OutcomeFailure},
		{"outside product scope", as(f.a.id, authz.Manager, authz.Scope{Products: []string{f.a.prodQ}}), nil, ErrInvalid, auditevent.OutcomeDenied},
		{"malformed product ID", mgr, func(r *IssueRequest) { r.ProductID = "x" }, ErrInvalid, auditevent.OutcomeFailure},
		{"too many external refs", mgr, func(r *IssueRequest) {
			r.ExternalRefs = map[string]string{}
			for i := range 21 {
				r.ExternalRefs[fmt.Sprint("k", i)] = "v"
			}
		}, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref key uppercase", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"Order": "1"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref key empty", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"": "1"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref key too long", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{strings.Repeat("k", 65): "1"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref value too long", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"order": strings.Repeat("v", 256)} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref value NUL", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"order": "a\x00b"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref value newline", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"order": "a\nb"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref value zero-width", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"order": "SO\u200b1"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref value bidi override", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"order": "\u202eSO1"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref value line separator", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"order": "SO\u20281"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"external ref value not UTF-8", mgr, func(r *IssueRequest) { r.ExternalRefs = map[string]string{"order": "a\xffb"} }, ErrInvalid, auditevent.OutcomeFailure},
		{"support", as(f.a.id, authz.Support, all), nil, authz.ErrDenied, auditevent.OutcomeDenied},
		{"viewer", as(f.a.id, authz.Viewer, all), nil, authz.ErrDenied, auditevent.OutcomeDenied},
		{"sdk token", authz.Principal{Kind: authz.Token, ID: "tok_x", TenantID: f.a.id, Role: authz.SDK, Scope: all}, nil, ErrInvalid, auditevent.OutcomeDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := f.req(f.a)
			if tc.change != nil {
				tc.change(&req)
			}
			lic, ev := f.count(t, f.a.id)
			_, err := f.s.Issue(ctx, tc.p, req)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			lic2, ev2 := f.count(t, f.a.id)
			e := f.lastEvent(t, f.a.id)
			if lic2 != lic || ev2 != ev+1 || e.Action != "license.issue" || e.Outcome != tc.outcome || e.ObjectID != nil || *e.ActorID != tc.p.ID {
				t.Errorf("licenses %d→%d, events %d→%d, last %+v", lic, lic2, ev, ev2, e)
			}
		})
	}
	// A hidden product answers exactly like a missing one (ADR-0032).
	hiddenReq, missingReq := f.req(f.a), f.req(f.a)
	missingReq.ProductID = "prd_00000000000000000000000000"
	_, errHidden := f.s.Issue(ctx, as(f.a.id, authz.Manager, authz.Scope{Products: []string{f.a.prodQ}}), hiddenReq)
	_, errMissing := f.s.Issue(ctx, mgr, missingReq)
	_, errOther := f.s.Issue(ctx, mgr, IssueRequest{ProductID: f.b.prodP, PlanID: f.b.pro.ID, CustomerID: f.b.customer})
	if errHidden == nil || errHidden.Error() != errMissing.Error() || errOther.Error() != errMissing.Error() {
		t.Errorf("hidden %v, missing %v, another tenant's %v", errHidden, errMissing, errOther)
	}
	// Refusals name the well-formed IDs the caller sent.
	_, _ = f.s.Issue(ctx, mgr, IssueRequest{ProductID: f.a.prodP, PlanID: f.b.pro.ID, CustomerID: "x"})
	if e := f.lastEvent(t, f.a.id); !strings.Contains(e.Details, `"product_id":"`+f.a.prodP+`"`) ||
		!strings.Contains(e.Details, `"plan_id":"`+f.b.pro.ID+`"`) || strings.Contains(e.Details, "customer_id") {
		t.Errorf("refusal details = %s", e.Details)
	}
	_, _ = f.s.Issue(ctx, mgr, IssueRequest{ProductID: f.a.prodP, PlanID: f.b.pro.ID, CustomerID: f.a.customer}) // refused in the transaction
	if e := f.lastEvent(t, f.a.id); !strings.Contains(e.Details, `"plan_id":"`+f.b.pro.ID+`"`) || !strings.Contains(e.Details, `"customer_id":"`+f.a.customer+`"`) {
		t.Errorf("in-transaction refusal details = %s", e.Details)
	}
	// A valid external ref is stored.
	okReq := f.req(f.a)
	okReq.ExternalRefs = map[string]string{"crm.deal-id_1": strings.Repeat("é", 127)}
	if _, err := f.s.Issue(ctx, mgr, okReq); err != nil {
		t.Errorf("valid refs: %v", err)
	}
	// Nothing reached tenant B.
	if lic, ev := f.count(t, f.b.id); lic != 0 || ev != 0 {
		t.Errorf("tenant B: %d licenses, %d events", lic, ev)
	}
	// Every role that may issue can, within its scope.
	for _, p := range []authz.Principal{as(f.a.id, authz.Owner, all), as(f.a.id, authz.Admin, all), as(f.a.id, authz.Manager, authz.Scope{Products: []string{f.a.prodP}})} {
		if _, err := f.s.Issue(ctx, p, f.req(f.a)); err != nil {
			t.Errorf("%s: %v", p.Role, err)
		}
	}
	// A malformed principal gets no tenant: refused, nothing recorded anywhere.
	if _, err := f.s.Issue(ctx, authz.Principal{Kind: authz.User, ID: "usr_x", TenantID: f.a.id, Role: authz.Manager}, f.req(f.a)); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("zero scope: %v", err)
	}
}

func TestExpiryBasis(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var firstAct, perpetual, secs string
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		mk := func(slug string, c func(*ent.PlanCreate)) string {
			pc := tx.Plan.Create().SetTenantID(f.a.id).SetProductID(f.a.prodP).SetSlug(slug).SetName(slug)
			c(pc)
			pl, err := pc.Save(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return pl.ID
		}
		firstAct = mk("presold", func(c *ent.PlanCreate) {
			c.SetDurationMonths(12).SetExpiryBasis(plan.ExpiryBasisFromFirstActivation)
		})
		perpetual = mk("forever", func(*ent.PlanCreate) {})
		secs = mk("trial", func(c *ent.PlanCreate) { c.SetDurationSeconds(14 * 86400) })
		return nil
	})
	for planID, term := range map[string]time.Duration{firstAct: 0, perpetual: 0, secs: 14 * 24 * time.Hour} {
		got, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, all), IssueRequest{ProductID: f.a.prodP, PlanID: planID, CustomerID: f.a.customer})
		if err != nil {
			t.Fatal(err)
		}
		var want *time.Time
		if term != 0 {
			want = ptr(got.License.IssuedAt.Add(term))
		}
		if l := got.License; (want == nil) != (l.ExpiresAt == nil) || want != nil && !want.Equal(*l.ExpiresAt) {
			t.Errorf("plan %s: expires %v, want %v (basis %s)", planID, l.ExpiresAt, want, l.ExpiryBasis)
		}
	}
}

func TestCalendarMonths(t *testing.T) {
	d := func(y int, m time.Month, day int) time.Time { return time.Date(y, m, day, 9, 30, 0, 0, time.UTC) }
	for _, tc := range []struct {
		start  time.Time
		months int
		want   time.Time
	}{
		{d(2026, 1, 31), 1, d(2026, 2, 28)},
		{d(2028, 1, 31), 1, d(2028, 2, 29)},
		{d(2026, 1, 15), 1, d(2026, 2, 15)},
		{d(2026, 3, 31), 1, d(2026, 4, 30)},
		{d(2026, 11, 30), 3, d(2027, 2, 28)},
		{d(2028, 2, 29), 12, d(2029, 2, 28)},
		{d(2026, 5, 31), 1200, d(2126, 5, 31)},
	} {
		if got := Expiry(tc.start, &tc.months, nil); !got.Equal(tc.want) {
			t.Errorf("%v + %d months = %v, want %v", tc.start, tc.months, got, tc.want)
		}
	}
}

func TestStateMachine(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	p := as(f.a.id, authz.Manager, all)
	got, err := f.s.Issue(ctx, p, f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	id := got.License.ID
	type op func(context.Context, authz.Principal, string) (Changed, error)
	steps := []struct {
		name   string
		op     op
		action string
		want   license.Status // "" = refused with ErrState, status unchanged
	}{
		{"reinstate active", f.s.Reinstate, "license.reinstate", ""},
		{"suspend", f.s.Suspend, "license.suspend", license.StatusSuspended},
		{"suspend twice", f.s.Suspend, "license.suspend", ""},
		{"reinstate", f.s.Reinstate, "license.reinstate", license.StatusActive},
		{"reinstate twice", f.s.Reinstate, "license.reinstate", ""},
		{"suspend again", f.s.Suspend, "license.suspend", license.StatusSuspended},
		{"revoke suspended", f.s.Revoke, "license.revoke", license.StatusRevoked},
		{"reinstate revoked", f.s.Reinstate, "license.reinstate", ""},
		{"suspend revoked", f.s.Suspend, "license.suspend", ""},
		{"revoke twice", f.s.Revoke, "license.revoke", ""},
	}
	status := license.StatusActive
	for _, st := range steps {
		l, err := st.op(ctx, p, id)
		e := f.lastEvent(t, f.a.id)
		row := f.get(t, f.a.id, id)
		if st.want == "" {
			if !errors.Is(err, ErrState) || l.License != nil || e.Outcome != auditevent.OutcomeFailure || row.Status != status {
				t.Errorf("%s: err %v, license %v, event %+v, status %s", st.name, err, l, e, row.Status)
			}
		} else {
			status = st.want
			if err != nil || l.Status != st.want || e.Outcome != auditevent.OutcomeSuccess ||
				!strings.Contains(e.Details, `"to":"`+string(st.want)+`"`) || row.Status != st.want ||
				// what a webhook payload needs (ADR-0044)
				!strings.Contains(e.Details, `"customer_id":"`+row.CustomerID+`"`) || !strings.Contains(e.Details, `"plan_slug":"`+row.PlanSlug+`"`) ||
				!strings.Contains(e.Details, `"plan_id":"`+row.PlanID+`"`) || !strings.Contains(e.Details, expiresJSON(row.ExpiresAt)) ||
				!strings.Contains(e.Details, `"product_id":"`+row.ProductID+`"`) {
				t.Errorf("%s: err %v, license %v, event %+v", st.name, err, l, e)
			}
		}
		if e.Action != st.action || e.ObjectID == nil || *e.ObjectID != id {
			t.Errorf("%s: event %+v", st.name, e)
		}
		if (row.Status == license.StatusSuspended) != (row.SuspendedAt != nil) || (row.Status == license.StatusRevoked) != (row.RevokedAt != nil) {
			t.Errorf("%s: times %+v", st.name, row)
		}
	}
	// Revoking an active license works too.
	got2, err := f.s.Issue(ctx, p, f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	if l, err := f.s.Revoke(ctx, p, got2.License.ID); err != nil || l.Status != license.StatusRevoked {
		t.Errorf("revoke active: %v %v", l, err)
	}
}

func TestTransitionRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mine, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, all), f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := f.s.Issue(ctx, as(f.b.id, authz.Manager, all), f.req(f.b))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		p        authz.Principal
		id       string
		want     error
		outcome  auditevent.Outcome
		objectID bool
	}{
		{"another tenant's license", as(f.a.id, authz.Manager, all), theirs.License.ID, ErrNotFound, auditevent.OutcomeFailure, false},
		{"unknown license", as(f.a.id, authz.Manager, all), "lic_00000000000000000000000000", ErrNotFound, auditevent.OutcomeFailure, false},
		{"malformed ID", as(f.a.id, authz.Manager, all), "lic_'; --", ErrNotFound, auditevent.OutcomeFailure, false},
		// Hidden: answered as not found, recorded as denied with the license ID.
		{"outside product scope", as(f.a.id, authz.Manager, authz.Scope{Products: []string{f.a.prodQ}}), mine.License.ID, ErrNotFound, auditevent.OutcomeDenied, true},
		// Visible but the role can't change it: denied after the lookup.
		{"support", as(f.a.id, authz.Support, all), mine.License.ID, authz.ErrDenied, auditevent.OutcomeDenied, true},
		{"viewer, visible license", as(f.a.id, authz.Viewer, all), mine.License.ID, authz.ErrDenied, auditevent.OutcomeDenied, true},
		// The lookup comes first (ADR-0032): a missing license is not found for every role.
		{"viewer, unknown license", as(f.a.id, authz.Viewer, all), "lic_00000000000000000000000000", ErrNotFound, auditevent.OutcomeFailure, false},
		{"sdk token", authz.Principal{Kind: authz.Token, ID: "tok_x", TenantID: f.a.id, Role: authz.SDK, Scope: all}, mine.License.ID, ErrNotFound, auditevent.OutcomeDenied, true},
	} {
		for name, op := range map[string]func(context.Context, authz.Principal, string) (Changed, error){
			"suspend": f.s.Suspend, "reinstate": f.s.Reinstate, "revoke": f.s.Revoke,
			// A bad value: refused for access before it is checked (ADR-0032), so
			// a hidden license's existence or issue time doesn't leak.
			"updates_until": func(ctx context.Context, p authz.Principal, id string) (Changed, error) {
				bad := time.Unix(0, 0)
				return f.s.SetUpdatesUntil(ctx, p, id, &bad)
			},
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				if _, err := op(ctx, tc.p, tc.id); !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				e := f.lastEvent(t, f.a.id)
				if e.Action != "license."+name || e.Outcome != tc.outcome || (e.ObjectID != nil) != tc.objectID || tc.objectID && *e.ObjectID != tc.id {
					t.Errorf("event %+v", e)
				}
			})
		}
	}
	// Both licenses are untouched; tenant B's log has only its own issue.
	if a, b := f.get(t, f.a.id, mine.License.ID), f.get(t, f.b.id, theirs.License.ID); a.Status != license.StatusActive || b.Status != license.StatusActive {
		t.Errorf("statuses %s %s", a.Status, b.Status)
	}
	if _, ev := f.count(t, f.b.id); ev != 1 {
		t.Errorf("tenant B has %d events", ev)
	}
	// Admins and owners may change licenses; a manager scoped to the product too.
	for _, p := range []authz.Principal{as(f.a.id, authz.Owner, all), as(f.a.id, authz.Admin, all), as(f.a.id, authz.Manager, authz.Scope{Products: []string{f.a.prodP}})} {
		if _, err := f.s.Suspend(ctx, p, mine.License.ID); err != nil {
			t.Errorf("%s suspend: %v", p.Role, err)
		}
		if _, err := f.s.Reinstate(ctx, p, mine.License.ID); err != nil {
			t.Errorf("%s reinstate: %v", p.Role, err)
		}
	}
}

// One clock for the row: created_at and updated_at are issued_at (database
// clock), so lists ordered by created_at agree across instances.
func TestIssueTimestampsUseOneClock(t *testing.T) {
	f := setup(t)
	got, err := f.s.Issue(context.Background(), as(f.a.id, authz.Manager, all), f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	l := f.get(t, f.a.id, got.License.ID)
	if !l.CreatedAt.Equal(l.IssuedAt) || !l.UpdatedAt.Equal(l.IssuedAt) {
		t.Errorf("issued %v, created %v, updated %v", l.IssuedAt, l.CreatedAt, l.UpdatedAt)
	}
}

// A state change doesn't wait for a key-share lock (what an activation's
// foreign-key check takes), so suspending never stalls activations.
func TestTransitionDoesNotBlockKeyShare(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	p := as(f.a.id, authz.Manager, all)
	got, err := f.s.Issue(ctx, p, f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	hold, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- f.db.WithTenant(ctx, f.a.id, func(tx *ent.Tx) error {
			if _, err := tx.ExecContext(ctx, `SELECT 1 FROM licenses WHERE id = $1 FOR KEY SHARE`, got.License.ID); err != nil {
				return err
			}
			close(hold)
			<-release
			return nil
		})
	}()
	select { // fail fast if the lock holder couldn't take its lock
	case <-hold:
	case err := <-done:
		t.Fatalf("key-share holder: %v", err)
	}
	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	_, err = f.s.Suspend(sctx, p, got.License.ID)
	cancel()
	close(release)
	if err != nil {
		t.Errorf("suspend while a key-share lock is held: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Refusals name the request field (ADR-0032), and come after the product
// and permission checks.
func TestIssueFieldErrors(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mgr := as(f.a.id, authz.Manager, all)
	for name, c := range map[string]struct {
		change func(*IssueRequest)
		field  string
	}{
		"malformed product":         {func(r *IssueRequest) { r.ProductID = "x" }, "/product_id"},
		"another tenant's":          {func(r *IssueRequest) { r.ProductID = f.b.prodP }, "/product_id"},
		"malformed plan":            {func(r *IssueRequest) { r.PlanID = "x" }, "/plan_id"},
		"another product's plan":    {func(r *IssueRequest) { r.PlanID = f.a.planQ.ID }, "/plan_id"},
		"malformed customer":        {func(r *IssueRequest) { r.CustomerID = "x" }, "/customer_id"},
		"another tenant's customer": {func(r *IssueRequest) { r.CustomerID = f.b.customer }, "/customer_id"},
		"type":                      {func(r *IssueRequest) { r.Type = "gold" }, "/type"},
		"external refs":             {func(r *IssueRequest) { r.ExternalRefs = map[string]string{"A": "1"} }, "/external_refs"},
		"override, escaped key":     {func(r *IssueRequest) { r.Overrides = map[string]Override{"a/b~c": {}} }, "/overrides/a~1b~0c"},
	} {
		req := f.req(f.a)
		c.change(&req)
		var inv *InvalidError
		if _, err := f.s.Issue(ctx, mgr, req); !errors.As(err, &inv) || inv.Field != c.field {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A viewer sending invalid values is refused for its role first.
	req := f.req(f.a)
	req.PlanID, req.Type = "x", "gold"
	if _, err := f.s.Issue(ctx, as(f.a.id, authz.Viewer, all), req); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer, invalid values: %v", err)
	}
}

// IssueTx records its refusal in the caller's transaction (it commits with
// it), and RecheckIssue repeats the product and permission checks.
func TestIssueTxAndRecheck(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mgr := as(f.a.id, authz.Manager, all)
	lic, ev := f.count(t, f.a.id)
	req := f.req(f.a)
	req.Type = "gold"
	var refused error
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		_, refused = f.s.IssueTx(ctx, tx, mgr, req)
		return nil // commit, as idempotency.Store.Do does for a 4xx
	})
	if !errors.Is(refused, ErrInvalid) {
		t.Fatalf("refused = %v", refused)
	}
	if lic2, ev2 := f.count(t, f.a.id); lic2 != lic || ev2 != ev+1 || f.lastEvent(t, f.a.id).Outcome != auditevent.OutcomeFailure {
		t.Errorf("licenses %d→%d, events %d→%d", lic, lic2, ev, ev2)
	}
	var got Issued
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		var err error
		got, err = f.s.IssueTx(ctx, tx, mgr, f.req(f.a))
		return err
	})
	if got.Key == "" || f.get(t, f.a.id, got.License.ID) == nil {
		t.Fatalf("issued %+v", got)
	}
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		for name, c := range map[string]struct {
			p    authz.Principal
			want error
		}{
			"manager":               {mgr, nil},
			"viewer":                {as(f.a.id, authz.Viewer, all), authz.ErrDenied},
			"outside product scope": {as(f.a.id, authz.Manager, authz.Scope{Products: []string{f.a.prodQ}}), ErrInvalid},
		} {
			if err := f.s.RecheckIssue(ctx, tx, c.p, f.a.prodP); !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Errorf("recheck %s: %v", name, err)
			}
		}
		return nil
	})
}

func TestListAndGet(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mgr := as(f.a.id, authz.Manager, all)
	var made []*ent.License
	for range 3 {
		got, err := f.s.Issue(ctx, mgr, f.req(f.a))
		if err != nil {
			t.Fatal(err)
		}
		made = append(made, got.License)
	}
	if _, err := f.s.Suspend(ctx, mgr, made[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Issue(ctx, as(f.b.id, authz.Manager, all), f.req(f.b)); err != nil {
		t.Fatal(err)
	}
	ids := func(ls []*ent.License) (out []string) {
		for _, l := range ls {
			out = append(out, l.ID)
		}
		return out
	}
	p1, err := f.s.List(ctx, mgr, Filter{}, 2, time.Time{}, "")
	if err != nil || !slices.Equal(ids(p1), []string{made[2].ID, made[1].ID}) {
		t.Fatalf("page 1 = %v, %v", ids(p1), err)
	}
	p2, err := f.s.List(ctx, mgr, Filter{}, 2, p1[1].CreatedAt, p1[1].ID)
	if err != nil || !slices.Equal(ids(p2), []string{made[0].ID}) {
		t.Fatalf("page 2 = %v, %v", ids(p2), err)
	}
	// Ties on created_at page by ID: give two licenses the same time (the
	// migrator, exempt), then walk them one per page.
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	if _, err := owner.ExecContext(ctx, `UPDATE licenses SET created_at = (SELECT created_at FROM licenses WHERE id = $1) WHERE id = $2`, made[2].ID, made[1].ID); err != nil {
		t.Fatal(err)
	}
	var walked []string
	at, after := time.Time{}, ""
	for range 4 {
		pg, err := f.s.List(ctx, mgr, Filter{}, 1, at, after)
		if err != nil {
			t.Fatal(err)
		}
		if len(pg) == 0 {
			break
		}
		walked = append(walked, pg[0].ID)
		at, after = pg[0].CreatedAt, pg[0].ID
	}
	if want := []string{max(made[2].ID, made[1].ID), min(made[2].ID, made[1].ID), made[0].ID}; !slices.Equal(walked, want) {
		t.Errorf("one per page with a tie = %v, want %v", walked, want)
	}
	if _, err := owner.ExecContext(ctx, `UPDATE licenses SET created_at = $1 WHERE id = $2`, made[1].CreatedAt, made[1].ID); err != nil {
		t.Fatal(err) // back as it was, for the cases below
	}
	now := time.Now()
	for name, c := range map[string]struct {
		p    authz.Principal
		f    Filter
		want []string
	}{
		"suspended":              {mgr, Filter{Status: license.StatusSuspended}, []string{made[0].ID}},
		"product":                {mgr, Filter{ProductID: f.a.prodP}, []string{made[2].ID, made[1].ID, made[0].ID}},
		"other product":          {mgr, Filter{ProductID: f.a.prodQ}, nil},
		"customer":               {mgr, Filter{CustomerID: f.a.customer}, []string{made[2].ID, made[1].ID, made[0].ID}},
		"another customer":       {mgr, Filter{CustomerID: f.b.customer}, nil},
		"created after":          {mgr, Filter{CreatedAfter: &made[1].CreatedAt}, []string{made[2].ID}},
		"created before":         {mgr, Filter{CreatedBefore: &made[1].CreatedAt}, []string{made[0].ID}},
		"future":                 {mgr, Filter{CreatedAfter: &now}, nil},
		"scoped elsewhere":       {as(f.a.id, authz.Viewer, authz.Scope{Products: []string{f.a.prodQ}}), Filter{}, nil},
		"scoped, filter outside": {as(f.a.id, authz.Viewer, authz.Scope{Products: []string{f.a.prodQ}}), Filter{ProductID: f.a.prodP}, nil},
	} {
		got, err := f.s.List(ctx, c.p, c.f, 10, time.Time{}, "")
		if err != nil || !slices.Equal(ids(got), c.want) {
			t.Errorf("%s: %v, %v", name, ids(got), err)
		}
	}
	if l, err := f.s.Get(ctx, as(f.a.id, authz.Viewer, all), made[0].ID); err != nil || l.ID != made[0].ID {
		t.Errorf("get: %v, %v", l, err)
	}
	for name, c := range map[string]struct {
		p  authz.Principal
		id string
	}{
		"missing":        {mgr, newLicenseID()},
		"malformed":      {mgr, "x"},
		"another tenant": {as(f.b.id, authz.Manager, all), made[0].ID},
		"out of scope":   {as(f.a.id, authz.Viewer, authz.Scope{Products: []string{f.a.prodQ}}), made[0].ID},
	} {
		if _, err := f.s.Get(ctx, c.p, c.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("get %s: %v", name, err)
		}
	}
}

func newLicenseID() string { return storeids.License() }

func TestRecordKeyRevealRefusesMalformedIDs(t *testing.T) {
	f := setup(t)
	mgr := as(f.a.id, authz.Manager, all)
	for _, c := range [][2]string{{"", f.a.prodP}, {"lic_x", f.a.prodP}, {newLicenseID(), ""}, {newLicenseID(), "x"}} {
		if err := f.s.RecordKeyReveal(context.Background(), mgr, c[0], c[1]); err == nil {
			t.Errorf("reveal %q/%q recorded", c[0], c[1])
		}
	}
	if err := f.s.RecordKeyReveal(context.Background(), mgr, newLicenseID(), f.a.prodP); err != nil {
		t.Error(err)
	}
	if e := f.lastEvent(t, f.a.id); e.Action != "license.key_reveal" || !strings.Contains(e.Details, f.a.prodP) {
		t.Errorf("audit = %+v", e)
	}
}

// Counts are exact per status, within the caller's product scope and tenant;
// every status is present (zero included); no license:read is ErrDenied.
func TestCounts(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mgr := as(f.a.id, authz.Manager, all)
	var onP []*ent.License
	for range 4 {
		got, err := f.s.Issue(ctx, mgr, f.req(f.a))
		if err != nil {
			t.Fatal(err)
		}
		onP = append(onP, got.License)
	}
	if _, err := f.s.Suspend(ctx, mgr, onP[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Revoke(ctx, mgr, onP[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Issue(ctx, mgr, IssueRequest{ProductID: f.a.prodQ, PlanID: f.a.planQ.ID, CustomerID: f.a.customer}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Issue(ctx, as(f.b.id, authz.Manager, all), f.req(f.b)); err != nil {
		t.Fatal(err)
	}
	type counts = map[license.Status]int
	for name, c := range map[string]struct {
		p    authz.Principal
		want counts
	}{
		"every product":                     {as(f.a.id, authz.Viewer, all), counts{license.StatusActive: 3, license.StatusSuspended: 1, license.StatusRevoked: 1}},
		"scoped to Q":                       {as(f.a.id, authz.Viewer, authz.Scope{Products: []string{f.a.prodQ}}), counts{license.StatusActive: 1, license.StatusSuspended: 0, license.StatusRevoked: 0}},
		"scoped to P":                       {as(f.a.id, authz.Support, authz.Scope{Products: []string{f.a.prodP}}), counts{license.StatusActive: 2, license.StatusSuspended: 1, license.StatusRevoked: 1}},
		"other tenant":                      {as(f.b.id, authz.Viewer, all), counts{license.StatusActive: 1, license.StatusSuspended: 0, license.StatusRevoked: 0}},
		"another tenant's product in scope": {as(f.b.id, authz.Viewer, authz.Scope{Products: []string{f.a.prodP}}), counts{license.StatusActive: 0, license.StatusSuspended: 0, license.StatusRevoked: 0}},
	} {
		got, err := f.s.Counts(ctx, c.p)
		if err != nil || !maps.Equal(got, c.want) {
			t.Errorf("%s: %v, %v; want %v", name, got, err, c.want)
		}
	}
	// A well-formed principal without license:read: an sdk token.
	sdk := authz.Principal{Kind: authz.Token, ID: "tok_test", TenantID: f.a.id, Role: authz.SDK, Scope: all}
	if _, err := f.s.Counts(ctx, sdk); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("sdk token (no license:read): %v", err)
	}
}

// No new license on an archived product (ADR-0015); existing ones can still
// be suspended, reinstated and revoked, and listed.
func TestArchivedProduct(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mgr := as(f.a.id, authz.Manager, all)
	existing, err := f.s.Issue(ctx, mgr, f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE products SET archived_at = clock_timestamp() WHERE id = $1`, f.a.prodP)
		return err
	})
	var inv *InvalidError
	if _, err := f.s.Issue(ctx, mgr, f.req(f.a)); !errors.As(err, &inv) || inv.Field != "/product_id" || !strings.Contains(inv.Message, "archived") {
		t.Errorf("issue on an archived product: %v", err)
	}
	// Rights come first: a viewer is still refused for its role.
	if _, err := f.s.Issue(ctx, as(f.a.id, authz.Viewer, all), f.req(f.a)); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer: %v", err)
	}
	// A hidden archived product answers like a missing one, never "archived".
	if _, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, authz.Scope{Products: []string{f.a.prodQ}}), f.req(f.a)); !errors.As(err, &inv) || strings.Contains(inv.Message, "archived") {
		t.Errorf("hidden archived product: %v", err)
	}
	for _, step := range []func(context.Context, authz.Principal, string) (Changed, error){f.s.Suspend, f.s.Reinstate, f.s.Revoke} {
		if _, err := step(ctx, mgr, existing.License.ID); err != nil {
			t.Errorf("transition on an archived product's license: %v", err)
		}
	}
}

// An issue racing an archive: the issue waits for the archive's row lock and
// then sees the product archived (it locks the product FOR SHARE).
func TestIssueWaitsForArchive(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	done := make(chan error, 1)
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT id FROM products WHERE id = $1 FOR UPDATE`, f.a.prodP); err != nil {
			return err
		}
		go func() {
			_, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, all), f.req(f.a))
			done <- err
		}()
		for i := 0; ; i++ {
			var n int
			if err := admin.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				break
			}
			if i == 100 {
				return errors.New("the issue never waited")
			}
			time.Sleep(20 * time.Millisecond)
		}
		_, err := tx.ExecContext(ctx, `UPDATE products SET archived_at = clock_timestamp() WHERE id = $1`, f.a.prodP)
		return err
	})
	select {
	case err := <-done:
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("issue after a concurrent archive: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("issue didn't finish")
	}
}

// An override of a feature racing that feature's archive: the issue waits
// for the archive and then refuses the feature as archived (it looks again
// after archive_once filters the row it waited for), not as unknown.
func TestOverrideWaitsForFeatureArchive(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	done := make(chan error, 1)
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE features SET archived_at = clock_timestamp() WHERE product_id = $1 AND key = 'export'`, f.a.prodP); err != nil {
			return err
		}
		go func() {
			req := f.req(f.a)
			req.Overrides = map[string]Override{"export": {}}
			_, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, all), req)
			done <- err
		}()
		for i := 0; ; i++ {
			var n int
			if err := admin.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			if i == 100 {
				return errors.New("the issue never waited")
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	select {
	case err := <-done:
		var inv *InvalidError
		if !errors.As(err, &inv) || inv.Field != "/overrides/export" || !strings.Contains(inv.Message, "archived") {
			t.Errorf("override after a concurrent archive: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("issue didn't finish")
	}
}

// A suspend that waits for a concurrent revoke answers the state error: the
// revoked license can't be locked (license_transitions), so change reads it
// unlocked rather than reporting it missing.
func TestChangeWaitsForConcurrentRevoke(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	m := as(f.a.id, authz.Manager, all)
	is, err := f.s.Issue(ctx, m, f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE licenses SET status = 'revoked', revoked_at = clock_timestamp() WHERE id = $1`, is.License.ID); err != nil {
			return err
		}
		go func() {
			_, err := f.s.Suspend(ctx, m, is.License.ID)
			done <- err
		}()
		for i := 0; ; i++ {
			var n int
			if err := admin.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			if i == 100 {
				return errors.New("the suspend never waited")
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
	if err := <-done; !errors.Is(err, ErrState) {
		t.Errorf("suspend after a concurrent revoke: %v, want ErrState", err)
	}
}

// expiresJSON is how an entry's details carry expires_at.
func expiresJSON(t *time.Time) string {
	if t == nil {
		return `"expires_at":null`
	}
	return `"expires_at":"` + t.UTC().Format(time.RFC3339Nano) + `"`
}

// A transition records the license as it is when the change happens: a
// first activation that set expires_at while the transition waited for the
// lock is in the entry (what a webhook payload is built from, ADR-0044).
func TestTransitionRecordsExpiryAtTheChange(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var planID string
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		pl, err := tx.Plan.Create().SetTenantID(f.a.id).SetProductID(f.a.prodP).SetSlug("presold").SetName("p").
			SetDurationMonths(12).SetExpiryBasis(plan.ExpiryBasisFromFirstActivation).Save(ctx)
		planID = pl.ID
		return err
	})
	m := as(f.a.id, authz.Manager, all)
	is, err := f.s.Issue(ctx, m, IssueRequest{ProductID: f.a.prodP, PlanID: planID, CustomerID: f.a.customer})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	f.tx(t, f.a.id, func(tx *ent.Tx) error { // as a first activation does, under the license's lock
		if _, err := tx.ExecContext(ctx, `UPDATE licenses SET first_activated_at = clock_timestamp(), expires_at = clock_timestamp() + interval '1 year' WHERE id = $1`, is.License.ID); err != nil {
			return err
		}
		go func() { _, err := f.s.Suspend(ctx, m, is.License.ID); done <- err }()
		storetest.WaitForLockWaiter(t, env)
		return nil
	})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	e := f.lastEvent(t, f.a.id)
	row := f.get(t, f.a.id, is.License.ID)
	if row.ExpiresAt == nil || !strings.Contains(e.Details, expiresJSON(row.ExpiresAt)) {
		t.Errorf("entry %s, license expires %v", e.Details, row.ExpiresAt)
	}
}

// Maintenance counts from issue whatever the expiry basis, in whole seconds;
// a plan without it covers every build (ADR-0045).
func TestUpdatesUntil(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var monthly, presold, none string
	f.tx(t, f.a.id, func(tx *ent.Tx) error {
		mk := func(slug string, c func(*ent.PlanCreate)) string {
			pc := tx.Plan.Create().SetTenantID(f.a.id).SetProductID(f.a.prodP).SetSlug(slug).SetName(slug)
			c(pc)
			pl, err := pc.Save(ctx)
			if err != nil {
				t.Fatal(err)
			}
			return pl.ID
		}
		monthly = mk("maint", func(c *ent.PlanCreate) { c.SetUpdatesMonths(12) })
		presold = mk("maint-presold", func(c *ent.PlanCreate) {
			c.SetDurationMonths(24).SetExpiryBasis(plan.ExpiryBasisFromFirstActivation).SetUpdatesMonths(1)
		})
		none = mk("no-maint", func(c *ent.PlanCreate) {})
		return nil
	})
	for planID, months := range map[string]int{monthly: 12, presold: 1, none: 0} {
		got, err := f.s.Issue(ctx, as(f.a.id, authz.Manager, all), IssueRequest{ProductID: f.a.prodP, PlanID: planID, CustomerID: f.a.customer})
		if err != nil {
			t.Fatal(err)
		}
		l := f.get(t, f.a.id, got.License.ID) // as stored
		if months == 0 {
			if l.UpdatesUntil != nil {
				t.Errorf("no maintenance: updates_until %v", l.UpdatesUntil)
			}
			continue
		}
		want := Expiry(l.IssuedAt, &months, nil).Truncate(time.Second)
		if l.UpdatesUntil == nil || !l.UpdatesUntil.Equal(want) || l.UpdatesUntil.Nanosecond() != 0 {
			t.Errorf("%d months: updates_until %v, want %v (issued %v)", months, l.UpdatesUntil, want, l.IssuedAt)
		}
		// The issue entry records it: the start of its audit trail.
		if e := f.lastEvent(t, f.a.id); !strings.Contains(e.Details, `"updates_until":"`+want.UTC().Format(time.RFC3339Nano)+`"`) {
			t.Errorf("%d months: issue entry %s", months, e.Details)
		}
	}
}

// Maintenance is renewed or corrected like a status change (ADR-0045):
// values after the rights and before the state, whole seconds, audited
// with the previous value; a revoked license keeps it.
func TestSetUpdatesUntil(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	m := as(f.a.id, authz.Manager, all)
	got, err := f.s.Issue(ctx, m, f.req(f.a))
	if err != nil {
		t.Fatal(err)
	}
	l := got.License
	until := l.IssuedAt.Add(400*24*time.Hour + 1500*time.Millisecond)
	c, err := f.s.SetUpdatesUntil(ctx, m, l.ID, &until)
	if err != nil || c.UpdatesUntil == nil || !c.UpdatesUntil.Equal(until.Truncate(time.Second)) {
		t.Fatalf("set = %v, %v", c.UpdatesUntil, err)
	}
	if s := f.get(t, f.a.id, l.ID); s.UpdatesUntil == nil || !s.UpdatesUntil.Equal(until.Truncate(time.Second)) {
		t.Errorf("stored %v", s.UpdatesUntil)
	}
	e := f.lastEvent(t, f.a.id)
	if d := details(t, e); e.Action != "license.updates_until" || e.Outcome != auditevent.OutcomeSuccess || d["previous"] != nil ||
		d["updates_until"] != until.UTC().Truncate(time.Second).Format(time.RFC3339Nano) || d["product_id"] != f.a.prodP {
		t.Errorf("event %+v", e)
	}
	// Cleared: every build covered; the entry names what it was.
	if c, err := f.s.SetUpdatesUntil(ctx, m, l.ID, nil); err != nil || c.UpdatesUntil != nil {
		t.Fatalf("clear = %v, %v", c.UpdatesUntil, err)
	}
	if d := details(t, f.lastEvent(t, f.a.id)); d["previous"] == nil || d["updates_until"] != nil {
		t.Errorf("clear event %+v", d)
	}
	for name, v := range map[string]time.Time{
		"at issue":           l.IssuedAt,
		"issue second":       l.IssuedAt.Truncate(time.Second), // at or before issue once truncated
		"before issue":       l.IssuedAt.Add(-time.Hour),
		"past year 9999 UTC": time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("", -5*3600)),
	} {
		var inv *InvalidError
		if _, err := f.s.SetUpdatesUntil(ctx, m, l.ID, &v); !errors.As(err, &inv) || inv.Field != "/updates_until" {
			t.Errorf("%s: %v", name, err)
		}
		if e := f.lastEvent(t, f.a.id); e.Outcome != auditevent.OutcomeFailure || e.Action != "license.updates_until" {
			t.Errorf("%s: event %+v", name, e)
		}
	}
	// A suspended license can be renewed; a revoked one can't, and a bad
	// value is refused as a value first (ADR-0032).
	if _, err := f.s.Suspend(ctx, m, l.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SetUpdatesUntil(ctx, m, l.ID, &until); err != nil {
		t.Errorf("suspended: %v", err)
	}
	if _, err := f.s.Revoke(ctx, m, l.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SetUpdatesUntil(ctx, m, l.ID, nil); !errors.Is(err, ErrState) {
		t.Errorf("revoked: %v", err)
	}
	past := l.IssuedAt.Add(-time.Hour)
	if _, err := f.s.SetUpdatesUntil(ctx, m, l.ID, &past); !errors.Is(err, ErrInvalid) {
		t.Errorf("revoked, bad value: %v", err)
	}
	if s := f.get(t, f.a.id, l.ID); s.UpdatesUntil == nil || !s.UpdatesUntil.Equal(until.Truncate(time.Second)) {
		t.Errorf("revoked license changed: %v", s.UpdatesUntil)
	}
}

// An explicit maintenance end at issue replaces the plan's term (ADR-0045).
func TestIssueUpdatesUntil(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	m := as(f.a.id, authz.Manager, all)
	until := time.Now().Add(1000*24*time.Hour + 300*time.Millisecond)
	req := f.req(f.a)
	req.UpdatesUntil = &until
	got, err := f.s.Issue(ctx, m, req)
	if err != nil {
		t.Fatal(err)
	}
	if s := f.get(t, f.a.id, got.License.ID); s.UpdatesUntil == nil || !s.UpdatesUntil.Equal(until.Truncate(time.Second)) {
		t.Errorf("stored %v, want %v", s.UpdatesUntil, until.Truncate(time.Second))
	}
	if d := details(t, f.lastEvent(t, f.a.id)); d["updates_until"] != until.UTC().Truncate(time.Second).Format(time.RFC3339Nano) {
		t.Errorf("issue event %+v", d)
	}
	before, _ := f.count(t, f.a.id)
	past := time.Now().Add(-time.Minute)
	req.UpdatesUntil = &past
	var inv *InvalidError
	if _, err := f.s.Issue(ctx, m, req); !errors.As(err, &inv) || inv.Field != "/updates_until" {
		t.Errorf("past: %v", err)
	}
	if after, _ := f.count(t, f.a.id); after != before {
		t.Errorf("refused issue stored a license")
	}
}

func details(t *testing.T, e *ent.AuditEvent) map[string]any {
	t.Helper()
	var d map[string]any
	if err := json.Unmarshal([]byte(e.Details), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

// Exactly at issue is refused (the CHECK's strict "after"); a second later passes.
func TestValidUpdatesUntil(t *testing.T) {
	issued := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	if _, err := validUpdatesUntil(issued, issued); !errors.Is(err, ErrInvalid) {
		t.Errorf("at issue: %v", err)
	}
	if u, err := validUpdatesUntil(issued.Add(time.Second+time.Millisecond), issued); err != nil || !u.Equal(issued.Add(time.Second)) {
		t.Errorf("a second later: %v, %v", u, err)
	}
	if _, err := validUpdatesUntil(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), issued); err != nil {
		t.Errorf("year 9999: %v", err)
	}
}
