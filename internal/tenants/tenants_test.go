package tenants

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
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
	db             *store.DB
	s              Service
	a, b           string
	owner          *sql.DB
	ownerA, adminA string // members of a
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
	f.ownerA = f.join(t, f.a, invitation.RoleOwner, "")
	f.adminA = f.join(t, f.a, invitation.RoleAdmin, f.ownerA)
	return f
}

// join creates a user and makes them a member through an invitation (the
// real path): by the platform for the first owner, else by inviter.
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

func (f fixture) as(tenant string, kind authz.PrincipalKind, role authz.Role, a authz.Assurance) context.Context {
	id := f.ownerA
	switch {
	case kind == authz.Token:
		id = ids.New("tok")
	case role == authz.Admin:
		id = f.adminA
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
		{"raise above a password session", f.as(f.a, authz.User, authz.Owner, none), mfa, ErrPolicyUnmet, none, auditevent.OutcomeFailure},
		{"raise to what the session meets", f.as(f.a, authz.User, authz.Owner, mfa), mfa, nil, mfa, auditevent.OutcomeSuccess},
		{"raise above an MFA session", f.as(f.a, authz.User, authz.Owner, mfa), pr, ErrPolicyUnmet, mfa, auditevent.OutcomeFailure},
		{"raise with a security key", f.as(f.a, authz.User, authz.Owner, pr), pr, nil, pr, auditevent.OutcomeSuccess},
		{"lower from a password session", f.as(f.a, authz.User, authz.Owner, none), mfa, nil, mfa, auditevent.OutcomeSuccess},
		{"lower from a weaker session", f.as(f.a, authz.User, authz.Owner, mfa), none, nil, none, auditevent.OutcomeSuccess},
		{"admin", f.as(f.a, authz.User, authz.Admin, pr), mfa, authz.ErrDenied, none, auditevent.OutcomeDenied},
		{"owner token", f.as(f.a, authz.Token, authz.Owner, ""), mfa, authz.ErrDenied, none, auditevent.OutcomeDenied},
		{"unknown level", f.as(f.a, authz.User, authz.Owner, pr), "strong", ErrInvalid, none, auditevent.OutcomeFailure},
		{"empty level", f.as(f.a, authz.User, authz.Owner, pr), "", ErrInvalid, none, auditevent.OutcomeFailure},
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
	if got, err := f.s.SetMFAPolicy(f.as(f.a, authz.User, authz.Owner, none), &n0); err != nil || got.From != none {
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

// The caller is rechecked in the transaction: a demoted owner's earlier
// principal can't change the policy.
func TestSetMFAPolicyRechecksCaller(t *testing.T) {
	f := setup(t)
	if _, err := f.owner.Exec(`UPDATE memberships SET role = 'admin' WHERE user_id = $1`, f.ownerA); err != nil {
		t.Fatal(err)
	}
	mfa := authz.AssuranceMFA
	if _, err := f.s.SetMFAPolicy(f.as(f.a, authz.User, authz.Owner, authz.AssurancePhishingResistant), &mfa); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("demoted owner: %v", err)
	}
	if p := f.policy(t, f.a); p != none {
		t.Errorf("policy %s", p)
	}
}

// SetMFAPolicy and another audited write in the tenant don't deadlock: the
// tenant row is locked FOR NO KEY UPDATE, which doesn't block the audit
// insert's foreign-key check (KEY SHARE).
func TestSetMFAPolicyNoDeadlock(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	locked, release := make(chan struct{}), make(chan struct{})
	writer := make(chan error, 1)
	go func() {
		writer <- f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
			if err := audit.Lock(ctx, tx, f.a); err != nil {
				return err
			}
			close(locked)
			<-release // SetMFAPolicy now holds the row lock and waits for the chain
			_, err := audit.Record(ctx, tx, f.a, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "test.write", Outcome: auditevent.OutcomeSuccess})
			return err
		})
	}()
	<-locked
	setter := make(chan error, 1)
	mfa := authz.AssuranceMFA
	go func() {
		_, err := f.s.SetMFAPolicy(f.as(f.a, authz.User, authz.Owner, authz.AssuranceMFA), &mfa)
		setter <- err
	}()
	// Wait until SetMFAPolicy holds the row lock (it then waits on the chain).
	for {
		var n int
		if err := f.owner.QueryRow(`SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation WHERE c.relname = 'tenants' AND l.mode = 'RowShareLock' AND l.granted
			AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 || ctx.Err() != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	if err := <-writer; err != nil {
		t.Fatalf("audited write: %v", err)
	}
	if err := <-setter; err != nil {
		t.Fatalf("SetMFAPolicy: %v", err)
	}
	if p := f.policy(t, f.a); p != mfa {
		t.Errorf("policy %s", p)
	}
}
