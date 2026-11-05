package tenants

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db    *store.DB
	s     Service
	a, b  string
	owner *sql.DB
}

func setup(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	d, err := store.Open(ctx, store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	f := fixture{db: d, s: Service{DB: d}, owner: owner}
	for _, tn := range []*string{&f.a, &f.b} {
		if err := d.WithPlatform(ctx, func(tx *ent.Tx) error {
			x, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(ctx)
			if err == nil {
				*tn = x.ID
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func as(tenant string, kind authz.PrincipalKind, role authz.Role, a authz.Assurance) context.Context {
	id := "usr_" + strings.Repeat("a", 26)
	if kind == authz.Token {
		id = ids.New("tok")
	}
	return authz.WithPrincipal(context.Background(), authz.Principal{Kind: kind, ID: id, TenantID: tenant, Role: role, Scope: authz.Scope{All: true}, Assurance: a})
}

func (f fixture) policy(t *testing.T, tenant string) authz.Assurance {
	t.Helper()
	var p string
	if err := f.owner.QueryRow(`SELECT mfa_policy FROM tenants WHERE id = $1`, tenant).Scan(&p); err != nil {
		t.Fatal(err)
	}
	return authz.Assurance(p)
}

func (f fixture) events(t *testing.T, tenant string) []*ent.AuditEvent {
	t.Helper()
	var es []*ent.AuditEvent
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) (err error) {
		es, err = tx.AuditEvent.Query().Order(ent.Asc(auditevent.FieldSeq)).All(context.Background())
		return
	}); err != nil {
		t.Fatal(err)
	}
	return es
}

const (
	none = authz.AssuranceNone
	mfa  = authz.AssuranceMFA
	pr   = authz.AssurancePhishingResistant
)

func TestSetMFAPolicy(t *testing.T) {
	f := setup(t)
	// Active, revoked and expired tokens: only the active one is reported.
	for _, q := range []string{
		`INSERT INTO api_tokens (id, tenant_id, name, role, scope_all, token_hash, display, expires_at, created_at, updated_at) VALUES ($1, $2, 'ci', 'sdk', true, sha256(random()::text::bytea), 'lf_live_abcdefgh…', now() + interval '1 day', now(), now())`,
		`INSERT INTO api_tokens (id, tenant_id, name, role, scope_all, token_hash, display, expires_at, created_at, updated_at, revoked_at) VALUES ($1, $2, 'old', 'sdk', true, sha256(random()::text::bytea), 'lf_live_abcdefgh…', now() + interval '1 day', now(), now(), now())`,
	} {
		if _, err := f.owner.Exec(q, ids.New("tok"), f.a); err != nil {
			t.Fatal(err)
		}
	}
	steps := []struct {
		name    string
		ctx     context.Context
		to      authz.Assurance
		want    error
		policy  authz.Assurance // after
		outcome auditevent.Outcome
	}{
		{"raise above a password session", as(f.a, authz.User, authz.Owner, none), mfa, ErrPolicyUnmet, none, auditevent.OutcomeFailure},
		{"raise to what the session meets", as(f.a, authz.User, authz.Owner, mfa), mfa, nil, mfa, auditevent.OutcomeSuccess},
		{"raise above an MFA session", as(f.a, authz.User, authz.Owner, mfa), pr, ErrPolicyUnmet, mfa, auditevent.OutcomeFailure},
		{"raise with a security key", as(f.a, authz.User, authz.Owner, pr), pr, nil, pr, auditevent.OutcomeSuccess},
		{"lower from a password session", as(f.a, authz.User, authz.Owner, none), mfa, nil, mfa, auditevent.OutcomeSuccess},
		{"lower from a weaker session", as(f.a, authz.User, authz.Owner, mfa), none, nil, none, auditevent.OutcomeSuccess},
		{"admin", as(f.a, authz.User, authz.Admin, pr), mfa, authz.ErrDenied, none, auditevent.OutcomeDenied},
		{"owner token", as(f.a, authz.Token, authz.Owner, ""), mfa, authz.ErrDenied, none, auditevent.OutcomeDenied},
		{"unknown level", as(f.a, authz.User, authz.Owner, pr), "strong", ErrInvalid, none, auditevent.OutcomeFailure},
		{"empty level", as(f.a, authz.User, authz.Owner, pr), "", ErrInvalid, none, auditevent.OutcomeFailure},
	}
	for _, st := range steps {
		before := len(f.events(t, f.a))
		got, err := f.s.SetMFAPolicy(st.ctx, &st.to)
		if !errors.Is(err, st.want) {
			t.Fatalf("%s: err %v, want %v", st.name, err, st.want)
		}
		if p := f.policy(t, f.a); p != st.policy {
			t.Errorf("%s: policy %s, want %s", st.name, p, st.policy)
		}
		es := f.events(t, f.a)
		if len(es) != before+1 {
			t.Fatalf("%s: %d new events", st.name, len(es)-before)
		}
		e := es[len(es)-1]
		if e.Action != "tenant.mfa_policy.update" || e.Outcome != st.outcome || *e.ObjectID != f.a {
			t.Errorf("%s: event %+v", st.name, e)
		}
		if err == nil && (string(got.Tenant.MfaPolicy) != string(st.to) || got.ActiveTokens != 1 ||
			!strings.Contains(e.Details, `"to":"`+string(st.to)+`"`) || !strings.Contains(e.Details, `"active_tokens":1`)) {
			t.Errorf("%s: result %+v, details %s", st.name, got, e.Details)
		}
	}
	// Setting the current policy changes and records nothing.
	before := len(f.events(t, f.a))
	n0 := none
	if got, err := f.s.SetMFAPolicy(as(f.a, authz.User, authz.Owner, none), &n0); err != nil || got.From != none {
		t.Errorf("same policy: %+v %v", got, err)
	}
	if n := len(f.events(t, f.a)); n != before {
		t.Errorf("no-op audited: %d", n-before)
	}
	// The other tenant was never touched.
	if p := f.policy(t, f.b); p != none || len(f.events(t, f.b)) != 0 {
		t.Errorf("tenant b: %s", p)
	}
}

// The tenant pool can change only its own tenant's MFA policy, and no other
// column of the tenant row.
func TestTenantPoolUpdate(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	exec := func(tenant, q string, args ...any) (int64, error) {
		var n int64
		err := f.db.WithTenant(ctx, tenant, func(tx *ent.Tx) error {
			res, err := tx.ExecContext(ctx, q, args...)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		return n, err
	}
	if n, err := exec(f.a, `UPDATE tenants SET mfa_policy = 'mfa' WHERE id = $1`, f.b); err != nil || n != 0 {
		t.Errorf("other tenant: %d %v", n, err)
	}
	// No WHERE: only the UPDATE policy decides which rows (SELECT policies
	// apply only to rows a statement reads).
	if n, err := exec(f.a, `UPDATE tenants SET mfa_policy = 'none'`); err != nil || n != 1 {
		t.Errorf("unqualified update: %d rows, %v", n, err)
	}
	if n, err := exec(f.a, `UPDATE tenants SET mfa_policy = 'mfa' WHERE id = $1`, f.a); err != nil || n != 1 {
		t.Errorf("own tenant: %d %v", n, err)
	}
	if _, err := exec(f.a, `UPDATE tenants SET name = 'x' WHERE id = $1`, f.a); err == nil || !strings.Contains(err.Error(), "42501") {
		t.Errorf("name: %v", err)
	}
	if _, err := exec(f.a, `UPDATE tenants SET mfa_policy = 'strong' WHERE id = $1`, f.a); err == nil {
		t.Error("unknown level stored")
	}
	if p := f.policy(t, f.b); p != none {
		t.Errorf("tenant b: %s", p)
	}
}
