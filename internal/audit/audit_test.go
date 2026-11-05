package audit

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/storetest"
)

var env storetest.Env

func TestMain(m *testing.M) { os.Exit(storetest.Main(m, &env, store.Migrate)) }

func openDB(t *testing.T) *store.DB {
	t.Helper()
	d, err := store.Open(context.Background(), store.Logins{Tenant: env.TenantURL, Platform: env.PlatformURL, Identity: env.IdentityURL})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func sqlDB(t *testing.T, url string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTenant(t *testing.T, d *store.DB) string {
	t.Helper()
	var id string
	if err := d.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		tn, err := tx.Tenant.Create().SetSlug("t-" + storetest.Suffix()).SetName("T").Save(context.Background())
		if err == nil {
			id = tn.ID
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}

var ev = Event{
	ActorType: auditevent.ActorTypeUser, ActorID: "usr_1", Action: "signing_key.promote",
	ObjectType: "signing_key", ObjectID: "sk_1", Outcome: auditevent.OutcomeSuccess,
	SourceIP: "::ffff:10.0.0.1", UserAgent: "lf-cli/0.1",
	// Unsorted keys, a fraction, non-ASCII and HTML characters: the stored json
	// text must be exactly the hashed text.
	Details: map[string]any{"z": 1.5, "a": "é <b>", "nested": map[string]any{"k": []any{1, true}}},
}

func record(t *testing.T, d *store.DB, tenantID string, e Event) *ent.AuditEvent {
	t.Helper()
	var r *ent.AuditEvent
	if err := d.WithTenant(context.Background(), tenantID, func(tx *ent.Tx) error {
		var err error
		r, err = Record(context.Background(), tx, tenantID, e)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

func verify(d *store.DB, tenantID string) error {
	_, err := verifyHead(d, tenantID)
	return err
}

func verifyHead(d *store.DB, tenantID string) (Head, error) {
	return Verify(context.Background(), tenantRunner(d, tenantID), tenantID, Head{})
}

func tenantRunner(d *store.DB, tenantID string) Runner {
	return func(ctx context.Context, snap bool, fn func(*ent.Tx) error) error {
		return d.ReadTenant(ctx, tenantID, snap, fn)
	}
}

func TestChain(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	first := record(t, d, tn, ev)
	second := record(t, d, tn, Event{ActorType: auditevent.ActorTypeSystem, Action: "tenant.create", Outcome: auditevent.OutcomeSuccess})
	if first.Seq != 1 || !bytes.Equal(first.PrevHash, zeroHash) || second.Seq != 2 || !bytes.Equal(second.PrevHash, first.Hash) {
		t.Fatalf("chain not linked: %+v %+v", first, second)
	}
	if *first.SourceIP != "10.0.0.1" {
		t.Errorf("source IP stored as %q", *first.SourceIP)
	}
	if err := verify(d, tn); err != nil {
		t.Fatalf("Verify after reading back from the database: %v", err)
	}
	for _, bad := range []Event{
		{ActorType: auditevent.ActorTypeUser, Action: "x.y", Outcome: auditevent.OutcomeSuccess, SourceIP: "nope"},
		{ActorType: auditevent.ActorTypeUser, Action: "x.y", Outcome: auditevent.OutcomeSuccess, SourceIP: "fe80::1%eth0"},
		{ActorType: auditevent.ActorTypeUser, Action: "noverb", Outcome: auditevent.OutcomeSuccess},
	} {
		if err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
			_, err := Record(context.Background(), tx, tn, bad)
			return err
		}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestConcurrentWritersDontFork(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() {
			errs <- d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
				_, err := Record(context.Background(), tx, tn, ev)
				return err
			})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := verify(d, tn); err != nil {
		t.Fatal(err)
	}
}

func TestRolledBackActionLeavesNoEntry(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	failed := errors.New("action failed")
	err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) error {
		if _, err := Record(context.Background(), tx, tn, ev); err != nil {
			return err
		}
		return failed
	})
	if !errors.Is(err, failed) {
		t.Fatal(err)
	}
	if r := record(t, d, tn, ev); r.Seq != 1 {
		t.Fatalf("seq after rollback = %d, want 1", r.Seq)
	}
}

func TestAppendOnlyAndIsolated(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	a, b := newTenant(t, d), newTenant(t, d)
	r := record(t, d, a, ev)
	for _, url := range []string{env.TenantURL, env.PlatformURL} {
		db := sqlDB(t, url)
		for _, q := range []string{
			`UPDATE audit_events SET details = '{}' WHERE id = $1`,
			`DELETE FROM audit_events WHERE id = $1`,
		} {
			if _, err := db.ExecContext(ctx, q, r.ID); err == nil || !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("%s: %v, want permission denied", q, err)
			}
		}
	}
	// Tenant b sees nothing of a's chain and can't append to it.
	if err := d.WithTenant(ctx, b, func(tx *ent.Tx) error {
		n, err := tx.AuditEvent.Query().Count(ctx)
		if err == nil && n != 0 {
			t.Errorf("tenant b sees %d of a's entries", n)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.WithTenant(ctx, b, func(tx *ent.Tx) error {
		_, err := Record(ctx, tx, a, ev)
		return err
	}); err == nil {
		t.Fatal("tenant b appended to a's chain")
	}
}

// Someone with owner access edits the table directly: Verify finds it.
func TestVerifyDetectsTampering(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	owner := sqlDB(t, env.OwnerURL)
	for name, tamper := range map[string]func(tn string, rs []*ent.AuditEvent) []string{
		"field changed": func(tn string, rs []*ent.AuditEvent) []string {
			return []string{`UPDATE audit_events SET outcome = 'failure' WHERE id = '` + rs[1].ID + `'`}
		},
		"details changed": func(tn string, rs []*ent.AuditEvent) []string {
			return []string{`UPDATE audit_events SET details = '{"a": "x"}' WHERE id = '` + rs[1].ID + `'`}
		},
		"first entry removed": func(tn string, rs []*ent.AuditEvent) []string {
			return []string{`DELETE FROM audit_events WHERE id = '` + rs[0].ID + `'`}
		},
		"entry removed": func(tn string, rs []*ent.AuditEvent) []string {
			return []string{`DELETE FROM audit_events WHERE id = '` + rs[1].ID + `'`}
		},
		"entry rehashed": func(tn string, rs []*ent.AuditEvent) []string {
			// Changed and given a valid hash: the next entry no longer links.
			e := *rs[1]
			e.Action = "license.revoke"
			return []string{`UPDATE audit_events SET action = 'license.revoke', hash = '\x` + hexs(Hash(&e)) + `' WHERE id = '` + rs[1].ID + `'`}
		},
		"entries swapped": func(tn string, rs []*ent.AuditEvent) []string {
			w := ` WHERE tenant_id = '` + tn + `' AND seq = `
			return []string{`UPDATE audit_events SET seq = 100` + w + `2`, `UPDATE audit_events SET seq = 2` + w + `3`, `UPDATE audit_events SET seq = 3` + w + `100`}
		},
	} {
		t.Run(name, func(t *testing.T) {
			tn := newTenant(t, d)
			var rs []*ent.AuditEvent
			for range 3 {
				rs = append(rs, record(t, d, tn, ev))
			}
			if err := verify(d, tn); err != nil {
				t.Fatal(err)
			}
			for _, q := range tamper(tn, rs) {
				if _, err := owner.ExecContext(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			if err := verify(d, tn); !errors.Is(err, ErrBroken) {
				t.Fatalf("tampering not detected: %v", err)
			}
		})
	}
}

func hexs(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// Moving characters between adjacent fields changes the hash (length
// prefixes), and so does every single field.
func TestHashCoversEveryFieldUnambiguously(t *testing.T) {
	s := func(v string) *string { return &v }
	base := ent.AuditEvent{TenantID: "tnt_1", Seq: 1, ActorType: auditevent.ActorTypeUser, ActorID: s("ab"),
		Action: "c.d", Outcome: auditevent.OutcomeSuccess, Details: "{}", PrevHash: zeroHash}
	h := Hash(&base)
	shifted := base
	shifted.ActorID, shifted.Action = s("a"), "bc.d"
	if bytes.Equal(h, Hash(&shifted)) {
		t.Fatal("field boundary not encoded")
	}
	for name, change := range map[string]func(e *ent.AuditEvent){
		"id":     func(e *ent.AuditEvent) { e.ID = "aud_2" },
		"tenant": func(e *ent.AuditEvent) { e.TenantID = "tnt_2" }, "seq": func(e *ent.AuditEvent) { e.Seq = 2 },
		"time":    func(e *ent.AuditEvent) { e.OccurredAt = e.OccurredAt.Add(time.Microsecond) },
		"actor":   func(e *ent.AuditEvent) { e.ActorType = auditevent.ActorTypeToken },
		"outcome": func(e *ent.AuditEvent) { e.Outcome = auditevent.OutcomeDenied },
		"object":  func(e *ent.AuditEvent) { e.ObjectType, e.ObjectID = s("license"), s("lic_1") },
		"ip":      func(e *ent.AuditEvent) { e.SourceIP = s("10.0.0.1") },
		"ua":      func(e *ent.AuditEvent) { e.UserAgent = s("x") },
		"details": func(e *ent.AuditEvent) { e.Details = `{"a":1}` },
		"prev":    func(e *ent.AuditEvent) { e.PrevHash = bytes.Repeat([]byte{1}, 32) },
	} {
		e := base
		change(&e)
		if bytes.Equal(h, Hash(&e)) {
			t.Errorf("%s not covered by the hash", name)
		}
	}
}

func TestAuditConstraintsInDatabase(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	owner := sqlDB(t, env.OwnerURL)
	tn := newTenant(t, d)
	r := record(t, d, tn, ev)
	// Each case copies the valid row with seq 2 and one field broken.
	ins := func(set string) string {
		return `INSERT INTO audit_events (id, tenant_id, seq, occurred_at, actor_type, actor_id, action, object_type, object_id, outcome, source_ip, user_agent, details, prev_hash, hash)
			SELECT 'aud_bbbbbbbbbbbbbbbbbbbbbbbbbb', tenant_id, 2, occurred_at, actor_type, actor_id, action, object_type, object_id, outcome, source_ip, user_agent, details, prev_hash, hash
			FROM audit_events WHERE id = $1; UPDATE audit_events SET ` + set + ` WHERE id = 'aud_bbbbbbbbbbbbbbbbbbbbbbbbbb'`
	}
	want := map[string]string{
		"action without verb": "audit_events_action_format", "empty actor": "audit_events_no_empty",
		"empty user agent": "audit_events_no_empty", "empty object id": "audit_events_no_empty",
		"empty source ip": "audit_events_no_empty", "object type not key": "audit_events_object_type",
		"details not object": "audit_events_details", "short hash": "audit_events_hash_len",
		"first entry has prev": "audit_events_first_prev", "bad id": "audit_events_id_format",
		"unknown outcome": "audit_events_outcome_valid", "unknown actor": "audit_events_actor_valid",
		"seq zero": "audit_events_seq_positive",
	}
	for name, set := range map[string]string{
		"empty object id":      `object_id = ''`,
		"empty source ip":      `source_ip = ''`,
		"unknown actor":        `actor_type = 'robot'`,
		"seq zero":             `seq = 0`,
		"action without verb":  `action = 'promote'`,
		"empty actor":          `actor_id = ''`,
		"empty user agent":     `user_agent = ''`,
		"object type not key":  `object_type = 'Signing Key'`,
		"details not object":   `details = '[]'`,
		"short hash":           `hash = '\x00'`,
		"first entry has prev": `seq = 1, prev_hash = hash`,
		"bad id":               `id = 'aud_X'`,
		"unknown outcome":      `outcome = 'maybe'`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := owner.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback() }()
			stmts := strings.SplitN(ins(set), "; ", 2)
			if _, err := tx.ExecContext(ctx, stmts[0], r.ID); err != nil {
				t.Fatalf("valid copy refused: %v", err)
			}
			if name == "first entry has prev" { // free seq 1
				if _, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id = $1`, r.ID); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := tx.ExecContext(ctx, stmts[1]); err == nil || !strings.Contains(err.Error(), want[name]) {
				t.Fatalf("%s: %v, want violation of %s", name, err, want[name])
			}
		})
	}
}

// Removing the last entries leaves a valid chain; only the head shows it, to
// be compared with an exported head.
func TestTruncationChangesHead(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	record(t, d, tn, ev)
	last := record(t, d, tn, ev)
	before, err := verifyHead(d, tn)
	if err != nil || before.Seq != 2 || !bytes.Equal(before.Hash, last.Hash) {
		t.Fatalf("head = %+v, %v", before, err)
	}
	if _, err := sqlDB(t, env.OwnerURL).Exec(`DELETE FROM audit_events WHERE id = $1`, last.ID); err != nil {
		t.Fatal(err)
	}
	if after, err := verifyHead(d, tn); err != nil || after.Seq != 1 {
		t.Fatalf("after truncation head = %+v, %v", after, err)
	}
}

// A hostile User-Agent (too long, NUL, invalid UTF-8) can't make Record fail.
func TestHostileUserAgentIsStored(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	e := ev
	e.UserAgent = strings.Repeat("é", 300) + "\x00\xff"
	r := record(t, d, tn, e)
	if ua := *r.UserAgent; len(ua) > maxUserAgent || !utf8.ValidString(ua) || strings.Contains(ua, "\x00") {
		t.Fatalf("stored user agent: %d bytes, valid=%v", len(ua), utf8.ValidString(ua))
	}
	if err := verify(d, tn); err != nil {
		t.Fatal(err)
	}
}

func TestRecordRefusesStaleSnapshot(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	err := d.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(context.Background(), `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`); err != nil {
			return err
		}
		_, err := Record(context.Background(), tx, tn, ev)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "READ COMMITTED") {
		t.Fatalf("Record in REPEATABLE READ: %v", err)
	}
}

// The identity pool (login path, ADR-0029) records an invitation's acceptance
// in that tenant's chain, and can't write into another tenant's.
func TestIdentityRecordsOnlyInItsTenant(t *testing.T) {
	d := openDB(t)
	a, b := newTenant(t, d), newTenant(t, d)
	ev := Event{ActorType: auditevent.ActorTypeUser, ActorID: "usr_x", Action: "invitation.accept", Outcome: auditevent.OutcomeSuccess}
	if err := d.WithIdentity(context.Background(), a, func(tx *ent.Tx) error {
		_, err := Record(context.Background(), tx, a, ev)
		return err
	}); err != nil {
		t.Fatalf("identity records in its tenant: %v", err)
	}
	if err := d.WithIdentity(context.Background(), a, func(tx *ent.Tx) error {
		_, err := Record(context.Background(), tx, b, ev)
		return err
	}); err == nil {
		t.Error("identity wrote into another tenant's chain")
	}
}

// The platform chain (ADR-0027) is written and read on the platform pool only.
// Its reserved tenant row is no tenant to any pool: not listed, not resolvable
// by slug, not changeable, and the tenant and identity pools can't reach its
// rows even with app.tenant_id set to it.
func TestPlatformChain(t *testing.T) {
	ctx := context.Background()
	d := openDB(t)
	onPlatform := func(fn func(*ent.Tx) error) error { return d.WithPlatform(ctx, fn) }
	var first, second *ent.AuditEvent
	if err := onPlatform(func(tx *ent.Tx) error {
		var err error
		if first, err = Record(ctx, tx, PlatformTenant, Event{ActorType: auditevent.ActorTypeUser, ActorID: "usr_a", Action: "user.login", Outcome: auditevent.OutcomeSuccess}); err != nil {
			return err
		}
		second, err = Record(ctx, tx, PlatformTenant, Event{ActorType: auditevent.ActorTypeSystem, Action: "platform_admin.bootstrap", Outcome: auditevent.OutcomeSuccess})
		return err
	}); err != nil {
		t.Fatalf("platform pool records on the platform chain: %v", err)
	}
	if second.Seq != first.Seq+1 || !bytes.Equal(second.PrevHash, first.Hash) {
		t.Errorf("platform chain not linked: %+v %+v", first, second)
	}
	if head, err := Verify(ctx, d.ReadPlatform, PlatformTenant, Head{}); err != nil || head.Seq != second.Seq || !bytes.Equal(head.Hash, second.Hash) {
		t.Errorf("Verify platform chain: %+v, %v", head, err)
	}

	pf := Event{ActorType: auditevent.ActorTypeUser, ActorID: "usr_x", Action: "user.login", Outcome: auditevent.OutcomeSuccess}
	for name, with := range map[string]func(func(*ent.Tx) error) error{
		"tenant pool":   func(fn func(*ent.Tx) error) error { return d.WithTenant(ctx, PlatformTenant, fn) },
		"identity pool": func(fn func(*ent.Tx) error) error { return d.WithIdentity(ctx, PlatformTenant, fn) },
	} {
		if err := with(func(tx *ent.Tx) error {
			n, err := tx.AuditEvent.Query().Count(ctx)
			if err == nil && n != 0 {
				t.Errorf("%s reads %d platform-chain entries", name, n)
			}
			if ok, err := tx.Tenant.Query().Where(tenant.ID(PlatformTenant)).Exist(ctx); err == nil && ok {
				t.Errorf("%s reads the platform tenant row", name)
			}
			return err
		}); err != nil {
			t.Errorf("%s read: %v", name, err)
		}
		if err := with(func(tx *ent.Tx) error { _, err := Record(ctx, tx, PlatformTenant, pf); return err }); err == nil {
			t.Errorf("%s appended to the platform chain", name)
		}
	}
	// Identity resolves slugs and lists tenants (switcher): never the reserved row.
	if err := d.WithIdentity(ctx, "", func(tx *ent.Tx) error {
		if _, err := tx.Tenant.Query().Where(tenant.Slug("platform")).Select(tenant.FieldID).Only(ctx); !ent.IsNotFound(err) {
			t.Errorf("identity resolved the slug platform: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// The platform pool doesn't list, change, delete or recreate it.
	if err := onPlatform(func(tx *ent.Tx) error {
		if ok, err := tx.Tenant.Query().Where(tenant.ID(PlatformTenant)).Exist(ctx); err != nil || ok {
			t.Errorf("platform pool lists the platform tenant: %v %v", ok, err)
		}
		if n, err := tx.Tenant.Update().Where(tenant.ID(PlatformTenant)).SetName("x").Save(ctx); err != nil || n != 0 {
			t.Errorf("platform pool renamed the platform tenant: %d %v", n, err)
		}
		if n, err := tx.Tenant.Delete().Where(tenant.ID(PlatformTenant)).Exec(ctx); err != nil || n != 0 {
			t.Errorf("platform pool deleted the platform tenant: %d %v", n, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := onPlatform(func(tx *ent.Tx) error {
		return tx.Tenant.Create().SetID(PlatformTenant).SetSlug("p-" + storetest.Suffix()).SetName("P").Exec(ctx)
	}); err == nil {
		t.Error("platform pool created a tenant with the reserved ID")
	}
	// It exists all along (owner view), so the chain's foreign key holds.
	var n int
	if err := sqlDB(t, env.OwnerURL).QueryRow(`SELECT count(*) FROM tenants WHERE id = $1 AND slug = 'platform'`, PlatformTenant).Scan(&n); err != nil || n != 1 {
		t.Errorf("reserved row: %d %v", n, err)
	}
}

func TestRefused(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	ctx := context.Background()
	errMissing, errOutage := errors.New("missing"), errors.New("outage")
	count := func() int {
		var n int
		if err := d.WithTenant(ctx, tn, func(tx *ent.Tx) error {
			var err error
			n, err = tx.AuditEvent.Query().Count(ctx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ev := By(authz.Principal{Kind: authz.Token, ID: "tok_x"}, "x.do", "x", "")
	if ev.ActorType != auditevent.ActorTypeToken {
		t.Errorf("token actor = %s", ev.ActorType)
	}
	for _, c := range []struct {
		err  error
		want auditevent.Outcome
	}{
		{fmt.Errorf("wrapped: %w", authz.ErrDenied), auditevent.OutcomeDenied},
		{fmt.Errorf("wrapped: %w", errMissing), auditevent.OutcomeFailure},
		{errOutage, ""},
	} {
		before := count()
		if err := Refused(ctx, d, tn, ev, c.err, errMissing); !errors.Is(err, c.err) {
			t.Errorf("%v: returned %v", c.err, err)
		}
		if c.want == "" {
			if count() != before {
				t.Errorf("%v recorded", c.err)
			}
			continue
		}
		var e *ent.AuditEvent
		if err := d.WithTenant(ctx, tn, func(tx *ent.Tx) error {
			var err error
			e, err = tx.AuditEvent.Query().Order(ent.Desc(auditevent.FieldSeq)).First(ctx)
			return err
		}); err != nil || e.Outcome != c.want || e.Action != "x.do" {
			t.Errorf("%v: recorded %+v, %v", c.err, e, err)
		}
	}
}
