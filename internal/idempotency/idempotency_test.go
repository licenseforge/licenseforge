package idempotency

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

type fixture struct {
	db    *store.DB
	s     Store
	a, b  string // tenants
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
	kr, err := secrets.ParseKeyring("k1=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{db: d, s: Store{DB: d, Keys: kr, Wait: 300 * time.Millisecond}, owner: owner}
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

var (
	tok1 = ids.New("tok")
	tok2 = ids.New("tok")
)

func (f fixture) req(tenant, cred, key, body string) Request {
	return Request{TenantID: tenant, Credential: cred, Key: key, Operation: "createLicense", Body: []byte(body)}
}

func noCheck(context.Context, *ent.Tx) error { return nil }

// counter is an operation that counts its runs and answers status with the
// run number, writing a row it can be seen by (a product) in the same transaction.
type counter struct {
	runs   atomic.Int32
	status int
	err    error
	tenant string
}

func (c *counter) op(ctx context.Context, tx *ent.Tx) (Outcome, error) {
	n := c.runs.Add(1)
	if _, err := tx.Product.Create().SetTenantID(c.tenant).SetSlug("p-" + storetest.Suffix()).SetName("P").Save(ctx); err != nil {
		return Outcome{}, err
	}
	if c.err != nil {
		return Outcome{}, c.err
	}
	return Outcome{Status: c.status, Body: []byte{byte('0' + n)}}, nil
}

func (f fixture) count(t *testing.T, tenant, table string) int {
	t.Helper()
	var n int
	if err := f.owner.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestReplay(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := &counter{status: 201, tenant: f.a}
	r := f.req(f.a, tok1, "order-1", `{"plan":"pro"}`)
	out, replayed, err := f.s.Do(ctx, r, noCheck, c.op)
	if err != nil || replayed || out.Status != 201 || string(out.Body) != "1" {
		t.Fatalf("first: %+v %v %v", out, replayed, err)
	}
	checks := 0
	check := func(context.Context, *ent.Tx) error { checks++; return nil }
	out, replayed, err = f.s.Do(ctx, r, check, c.op)
	if err != nil || !replayed || out.Status != 201 || string(out.Body) != "1" || c.runs.Load() != 1 || checks != 1 {
		t.Fatalf("replay: %+v %v %v, runs %d, checks %d", out, replayed, err, c.runs.Load(), checks)
	}
	if n := f.count(t, f.a, "products"); n != 1 {
		t.Errorf("%d products", n)
	}
	// A replay whose recheck refuses answers the refusal, not the stored outcome.
	refused := errors.New("not found")
	if _, _, err := f.s.Do(ctx, r, func(context.Context, *ent.Tx) error { return refused }, c.op); !errors.Is(err, refused) {
		t.Errorf("recheck refusal: %v", err)
	}
	// A 4xx is stored too.
	c4 := &counter{status: 422, tenant: f.a}
	r4 := f.req(f.a, tok1, "order-2", `{}`)
	for range 2 {
		if out, _, err := f.s.Do(ctx, r4, noCheck, c4.op); err != nil || out.Status != 422 {
			t.Fatalf("4xx: %+v %v", out, err)
		}
	}
	if c4.runs.Load() != 1 {
		t.Errorf("4xx ran %d times", c4.runs.Load())
	}
}

func TestKeyReused(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := &counter{status: 201, tenant: f.a}
	if _, _, err := f.s.Do(ctx, f.req(f.a, tok1, "k", `{"plan":"pro"}`), noCheck, c.op); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]Request{
		"other body":           f.req(f.a, tok1, "k", `{"plan":"enterprise"}`),
		"other operation":      {TenantID: f.a, Credential: tok1, Key: "k", Operation: "createActivation", Body: []byte(`{"plan":"pro"}`)},
		"other path parameter": {TenantID: f.a, Credential: tok1, Key: "k", Operation: "createLicense", Params: []string{"lic_other"}, Body: []byte(`{"plan":"pro"}`)},
		// Fields are length-prefixed: moving a byte from operation to body is another request.
		"shifted boundary": {TenantID: f.a, Credential: tok1, Key: "k", Operation: "createLicens", Body: []byte(`e{"plan":"pro"}`)},
	} {
		if _, _, err := f.s.Do(ctx, r, noCheck, c.op); !errors.Is(err, ErrKeyReused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if c.runs.Load() != 1 {
		t.Errorf("ran %d times", c.runs.Load())
	}
}

func TestScope(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	ca, cb := &counter{status: 201, tenant: f.a}, &counter{status: 201, tenant: f.b}
	if _, _, err := f.s.Do(ctx, f.req(f.a, tok1, "k", `{}`), noCheck, ca.op); err != nil {
		t.Fatal(err)
	}
	// The same key from another credential, or in another tenant, is independent.
	if out, replayed, err := f.s.Do(ctx, f.req(f.a, tok2, "k", `{}`), noCheck, ca.op); err != nil || replayed || string(out.Body) != "2" {
		t.Errorf("other credential: %+v %v %v", out, replayed, err)
	}
	if out, replayed, err := f.s.Do(ctx, f.req(f.b, tok1, "k", `{}`), noCheck, cb.op); err != nil || replayed || string(out.Body) != "1" {
		t.Errorf("other tenant: %+v %v %v", out, replayed, err)
	}
	if f.count(t, f.a, "idempotency_keys") != 2 || f.count(t, f.b, "idempotency_keys") != 1 {
		t.Error("key rows")
	}
	// With both credentials' rows stored, each replays its own outcome.
	runs := ca.runs.Load()
	for cred, want := range map[string]string{tok1: "1", tok2: "2"} {
		if out, replayed, err := f.s.Do(ctx, f.req(f.a, cred, "k", `{}`), noCheck, ca.op); err != nil || !replayed || string(out.Body) != want {
			t.Errorf("replay for %s: %+v %v %v", cred, out, replayed, err)
		}
	}
	if ca.runs.Load() != runs {
		t.Errorf("replays ran the operation")
	}
	// Tenant b's pool can't see or delete tenant a's keys.
	if err := f.db.WithTenant(ctx, f.b, func(tx *ent.Tx) error {
		n, err := tx.IdempotencyKey.Query().Count(ctx)
		if n != 1 {
			t.Errorf("tenant b sees %d keys", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidKey(t *testing.T) {
	f := setup(t)
	c := &counter{status: 201, tenant: f.a}
	for name, r := range map[string]Request{
		"empty":          f.req(f.a, tok1, "", `{}`),
		"too long":       f.req(f.a, tok1, strings.Repeat("k", 256), `{}`),
		"control":        f.req(f.a, tok1, "a\tb", `{}`),
		"non-ASCII":      f.req(f.a, tok1, "clé", `{}`),
		"bad credential": f.req(f.a, "admin", "k", `{}`),
		"bad tenant":     f.req("acme", tok1, "k", `{}`),
		"no operation":   {TenantID: f.a, Credential: tok1, Key: "k"},
		"session ID":     f.req(f.a, ids.New("ses"), "k", `{}`),
	} {
		if _, _, err := f.s.Do(context.Background(), r, noCheck, c.op); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if c.runs.Load() != 0 {
		t.Errorf("ran %d times", c.runs.Load())
	}
	if _, _, err := f.s.Do(context.Background(), f.req(f.a, ids.New("usr"), strings.Repeat("~", 255), `{}`), noCheck, c.op); err != nil {
		t.Errorf("user, 255 printable: %v", err)
	}
}

func TestNotStored(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// 5xx: answered, but rolled back with the operation, so a retry runs again.
	c := &counter{status: 503, tenant: f.a}
	r := f.req(f.a, tok1, "k", `{}`)
	for i := range 2 {
		out, replayed, err := f.s.Do(ctx, r, noCheck, c.op)
		if err != nil || replayed || out.Status != 503 {
			t.Fatalf("try %d: %+v %v %v", i, out, replayed, err)
		}
	}
	// An error (a crash) leaves no key and none of the operation's writes.
	boom := errors.New("boom")
	ce := &counter{err: boom, tenant: f.a}
	if _, _, err := f.s.Do(ctx, f.req(f.a, tok1, "k2", `{}`), noCheck, ce.op); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	// Statuses that are neither stored nor 5xx are refused, also rolled back.
	c3 := &counter{status: 302, tenant: f.a}
	if _, _, err := f.s.Do(ctx, f.req(f.a, tok1, "k3", `{}`), noCheck, c3.op); err == nil {
		t.Error("302 accepted")
	}
	if c.runs.Load() != 2 || f.count(t, f.a, "idempotency_keys") != 0 || f.count(t, f.a, "products") != 0 {
		t.Errorf("runs %d, keys %d, products %d", c.runs.Load(), f.count(t, f.a, "idempotency_keys"), f.count(t, f.a, "products"))
	}
	// After the failure the key is free.
	ok := &counter{status: 201, tenant: f.a}
	if _, replayed, err := f.s.Do(ctx, f.req(f.a, tok1, "k2", `{}`), noCheck, ok.op); err != nil || replayed {
		t.Errorf("retry: %v %v", replayed, err)
	}
}

func TestConcurrentSameKey(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.s.Wait = 5 * time.Second
	c := &counter{status: 201, tenant: f.a}
	slow := func(ctx context.Context, tx *ent.Tx) (Outcome, error) {
		time.Sleep(200 * time.Millisecond) // hold the claim while the others arrive
		return c.op(ctx, tx)
	}
	r := f.req(f.a, tok1, "k", `{}`)
	const n = 8
	var wg sync.WaitGroup
	outs := make([]Outcome, n)
	errs := make([]error, n)
	replays := make([]bool, n)
	for i := range n {
		wg.Go(func() { outs[i], replays[i], errs[i] = f.s.Do(ctx, r, noCheck, slow) })
	}
	wg.Wait()
	nReplayed := 0
	for i := range n {
		if errs[i] != nil || outs[i].Status != 201 || string(outs[i].Body) != "1" {
			t.Errorf("%d: %+v %v", i, outs[i], errs[i])
		}
		if replays[i] {
			nReplayed++
		}
	}
	if c.runs.Load() != 1 || nReplayed != n-1 {
		t.Errorf("runs %d, replayed %d", c.runs.Load(), nReplayed)
	}

	// Past the wait: ErrInProgress, and the operation doesn't run.
	f.s.Wait = 100 * time.Millisecond
	started, release := make(chan struct{}), make(chan struct{})
	held := &counter{status: 201, tenant: f.a}
	done := make(chan error, 1)
	r2 := f.req(f.a, tok1, "k2", `{}`)
	go func() {
		_, _, err := f.s.Do(ctx, r2, noCheck, func(ctx context.Context, tx *ent.Tx) (Outcome, error) {
			close(started)
			<-release
			return held.op(ctx, tx)
		})
		done <- err
	}()
	<-started
	if _, _, err := f.s.Do(ctx, r2, noCheck, held.op); !errors.Is(err, ErrInProgress) {
		t.Errorf("in flight: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if held.runs.Load() != 1 {
		t.Errorf("held ran %d times", held.runs.Load())
	}
}

func TestExpiryAndCleanup(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := &counter{status: 201, tenant: f.a}
	for _, k := range []string{"old", "older", "fresh"} {
		if _, _, err := f.s.Do(ctx, f.req(f.a, tok1, k, `{}`), noCheck, c.op); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.owner.Exec(`UPDATE idempotency_keys SET created_at = created_at - interval '25 hours' WHERE tenant_id = $1 AND key <> 'fresh'`, f.a); err != nil {
		t.Fatal(err)
	}
	// The pools can't delete live keys.
	for name, run := range map[string]func(func(*ent.Tx) error) error{
		"tenant":   func(fn func(*ent.Tx) error) error { return f.db.WithTenant(ctx, f.a, fn) },
		"platform": func(fn func(*ent.Tx) error) error { return f.db.WithPlatform(ctx, fn) },
	} {
		if err := run(func(tx *ent.Tx) error {
			res, err := tx.ExecContext(ctx, `DELETE FROM idempotency_keys WHERE created_at > clock_timestamp() - interval '1 hour'`) // the live key
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n != 0 {
				t.Errorf("%s deleted a live key", name)
			}
			return errors.New("rollback")
		}); err == nil || err.Error() != "rollback" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An expired key is claimed anew: the request runs again, even with another body.
	if out, replayed, err := f.s.Do(ctx, f.req(f.a, tok1, "old", `{"other":1}`), noCheck, c.op); err != nil || replayed || string(out.Body) != "4" {
		t.Errorf("expired key: %+v %v %v", out, replayed, err)
	}
	n, err := Cleanup(ctx, f.db)
	if err != nil || n < 1 {
		t.Fatalf("cleanup = %d, %v", n, err)
	}
	var keys []string
	rows, err := f.owner.Query(`SELECT key FROM idempotency_keys WHERE tenant_id = $1 ORDER BY key`, f.a)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var k string
		_ = rows.Scan(&k)
		keys = append(keys, k)
	}
	if strings.Join(keys, ",") != "fresh,old" {
		t.Errorf("keys after cleanup: %v", keys)
	}
	// The tenant pool can't plant a backdated (deletable) or pre-completed key.
	for name, q := range map[string]string{
		"backdated": `INSERT INTO idempotency_keys (id, tenant_id, credential, key, request_hash, created_at) VALUES ($1, $2, $3, 'x', sha256('x'), clock_timestamp() - interval '2 days')`,
		"completed": `INSERT INTO idempotency_keys (id, tenant_id, credential, key, request_hash, created_at, status, body) VALUES ($1, $2, $3, 'y', sha256('y'), clock_timestamp(), 200, '')`,
	} {
		if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
			_, err := tx.ExecContext(ctx, q, ids.IdempotencyKey(), f.a, tok1)
			return err
		}); err == nil || !strings.Contains(err.Error(), "42501") { // RLS or the column grants
			t.Errorf("%s: %v", name, err)
		}
	}
	// Stored outcomes are immutable, even for the tenant pool.
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE idempotency_keys SET status = 200, body = '\x00' WHERE key = 'fresh'`)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 0 {
			t.Error("stored outcome changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The wait bound covers only the claim: the operation itself may wait on
// locks longer than Wait.
func TestOperationNotBoundByWait(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	conn, err := f.owner.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock(4242)`); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(3 * f.s.Wait)
		_, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock(4242)`)
	}()
	op := func(ctx context.Context, tx *ent.Tx) (Outcome, error) {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(4242)`); err != nil {
			return Outcome{}, err
		}
		return Outcome{Status: 201, Body: []byte("ok")}, nil
	}
	if out, _, err := f.s.Do(ctx, f.req(f.a, tok1, "k", `{}`), noCheck, op); err != nil || out.Status != 201 {
		t.Errorf("Do = %+v, %v", out, err)
	}
}

// Path parameters are part of the request: the same key on another object is
// another request.
func TestParams(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := &counter{status: 201, tenant: f.a}
	r := f.req(f.a, tok1, "k", `{}`)
	r.Params = []string{"lic_one"}
	if _, _, err := f.s.Do(ctx, r, noCheck, c.op); err != nil {
		t.Fatal(err)
	}
	for _, params := range [][]string{{"lic_two"}, nil, {"lic_one", ""}, {"lic_", "one"}} {
		r.Params = params
		if _, _, err := f.s.Do(ctx, r, noCheck, c.op); !errors.Is(err, ErrKeyReused) {
			t.Errorf("params %q: %v", params, err)
		}
	}
	r.Params = []string{"lic_one"}
	if _, replayed, err := f.s.Do(ctx, r, noCheck, c.op); err != nil || !replayed {
		t.Errorf("same params: %v %v", replayed, err)
	}
}

// Response bodies are encrypted at rest, bound to their row, and the
// platform pool sees neither requests nor responses.
func TestEncryptedAtRest(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	secret := "LF-SECRET-LICENSE-KEY"
	op := func(context.Context, *ent.Tx) (Outcome, error) {
		return Outcome{Status: 201, Body: []byte(secret)}, nil
	}
	r := f.req(f.a, tok1, "k", `{}`)
	if _, _, err := f.s.Do(ctx, r, noCheck, op); err != nil {
		t.Fatal(err)
	}
	var id string
	var body []byte
	if err := f.owner.QueryRow(`SELECT id, body FROM idempotency_keys WHERE tenant_id = $1`, f.a).Scan(&id, &body); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(secret)) || !bytes.HasPrefix(body, []byte("v1.k1.")) {
		t.Fatalf("body stored as %q", body)
	}
	if out, replayed, err := f.s.Do(ctx, r, noCheck, op); err != nil || !replayed || string(out.Body) != secret {
		t.Errorf("replay: %q %v %v", out.Body, replayed, err)
	}
	// A ciphertext moved to another row doesn't decrypt.
	r2 := f.req(f.a, tok1, "k2", `{}`)
	if _, _, err := f.s.Do(ctx, r2, noCheck, op); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`UPDATE idempotency_keys SET body = $1 WHERE tenant_id = $2 AND key = 'k2'`, body, f.a); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.s.Do(ctx, r2, noCheck, op); !errors.Is(err, secrets.ErrDecrypt) {
		t.Errorf("swapped ciphertext: %v", err)
	}
	// The platform pool may only see id and created_at.
	for _, col := range []string{"body", "request_hash", "key", "credential"} {
		err := f.db.WithPlatform(ctx, func(tx *ent.Tx) error {
			rows, err := tx.QueryContext(ctx, `SELECT `+col+` FROM idempotency_keys LIMIT 1`)
			if err == nil {
				_ = rows.Close()
			}
			return err
		})
		if err == nil || !strings.Contains(err.Error(), "42501") {
			t.Errorf("platform reads %s: %v", col, err)
		}
	}
}
