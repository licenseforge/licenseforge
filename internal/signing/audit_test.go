package signing

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// entries returns the tenant's audit entries in seq order, after checking the
// chain verifies and ends at the last one.
func entries(t *testing.T, l Local, tenantID string) []*ent.AuditEvent {
	t.Helper()
	ctx := context.Background()
	var es []*ent.AuditEvent
	head, err := audit.Verify(ctx, func(ctx context.Context, snap bool, fn func(*ent.Tx) error) error {
		return l.DB.ReadTenant(ctx, tenantID, snap, fn)
	}, tenantID, audit.Head{})
	if err != nil {
		t.Fatal(err)
	}
	err = l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		es, err = tx.AuditEvent.Query().Order(ent.Asc(auditevent.FieldSeq)).All(ctx)
		if err == nil && len(es) > 0 && head.Seq != es[len(es)-1].Seq {
			t.Errorf("chain head %d, last entry %d", head.Seq, es[len(es)-1].Seq)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return es
}

type want struct {
	action, object string
	outcome        auditevent.Outcome
	details        map[string]any
}

// expectOne checks that exactly one entry was appended since n and that it
// matches w, and returns the new count.
func expectOne(t *testing.T, l Local, tenantID string, n int, actor string, w want) int {
	t.Helper()
	es := entries(t, l, tenantID)
	if len(es) != n+1 {
		t.Fatalf("%s: %d new entries, want 1", w.action, len(es)-n)
	}
	e := es[n]
	var d map[string]any
	if err := json.Unmarshal([]byte(e.Details), &d); err != nil {
		t.Fatal(err)
	}
	if e.Action != w.action || deref(e.ObjectID) != w.object || e.Outcome != w.outcome || deref(e.ActorID) != actor ||
		deref(e.ObjectType) != "signing_key" || e.ActorType != auditevent.ActorTypeUser {
		t.Errorf("entry %+v, want %+v by %s", e, w, actor)
	}
	if w.details != nil {
		b1, _ := json.Marshal(d)
		b2, _ := json.Marshal(w.details)
		if string(b1) != string(b2) {
			t.Errorf("%s details %s, want %s", w.action, b1, b2)
		}
	}
	return len(es)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func asRole(tenantID string, role authz.Role) context.Context {
	return authz.WithPrincipal(context.Background(), authz.Principal{
		Kind: authz.User, ID: "usr_test", TenantID: tenantID, Role: role, Scope: authz.Scope{All: true}})
}

func TestKeyOperationsAreAudited(t *testing.T) {
	l, _, _ := setup(t)
	tn := newTenant(t, l)
	owner := as(tn)
	n := 0

	first, err := l.Create(owner, tn)
	if err != nil {
		t.Fatal(err)
	}
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.create", first.ID, auditevent.OutcomeSuccess,
		map[string]any{"alg": "ed25519", "to": "active"}})
	next, err := l.Create(owner, tn)
	if err != nil {
		t.Fatal(err)
	}
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.create", next.ID, auditevent.OutcomeSuccess,
		map[string]any{"alg": "ed25519", "to": "pending"}})
	if err := l.Promote(owner, tn, next.ID); err != nil {
		t.Fatal(err)
	}
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.promote", next.ID, auditevent.OutcomeSuccess,
		map[string]any{"alg": "ed25519", "from": "pending", "to": "active", "retired": first.ID}})
	third, err := l.Create(owner, tn)
	if err != nil {
		t.Fatal(err)
	}
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.create", third.ID, auditevent.OutcomeSuccess, nil})
	if err := l.Discard(owner, tn, third.ID); err != nil {
		t.Fatal(err)
	}
	expectOne(t, l, tn, n, "usr_test", want{"signing_key.discard", third.ID, auditevent.OutcomeSuccess,
		map[string]any{"alg": "ed25519", "from": "pending", "to": "retired"}})
}

func TestKeyRefusalsAreAudited(t *testing.T) {
	l, _, _ := setup(t)
	tn, other := newTenant(t, l), newTenant(t, l)
	owner, viewer := as(tn), asRole(tn, authz.Viewer)
	active, err := l.Create(owner, tn)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := l.Create(owner, tn)
	if err != nil {
		t.Fatal(err)
	}
	n := len(entries(t, l, tn))
	denied := auditevent.OutcomeDenied
	failed := auditevent.OutcomeFailure

	_, _ = l.Create(viewer, tn)
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.create", "", denied, map[string]any{}})
	_ = l.Promote(viewer, tn, pending.ID)
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.promote", pending.ID, denied, map[string]any{}})
	_ = l.Discard(viewer, tn, pending.ID)
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.discard", pending.ID, denied, map[string]any{}})
	_ = l.Discard(viewer, tn, "sk_../../x")
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.discard", "", denied, nil}) // malformed IDs aren't stored
	if err := l.Discard(owner, tn, "sk_../../x"); !errors.Is(err, ErrNotPending) {
		t.Errorf("malformed kid: %v", err)
	}
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.discard", "", auditevent.OutcomeFailure, nil})

	_, _ = l.Create(owner, tn)
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.create", "", failed, map[string]any{"reason": ErrPendingExists.Error()}})
	_ = l.Promote(owner, tn, active.ID)
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.promote", active.ID, failed, map[string]any{"reason": ErrNotPending.Error()}})
	_ = l.Discard(owner, tn, active.ID)
	n = expectOne(t, l, tn, n, "usr_test", want{"signing_key.discard", active.ID, failed, map[string]any{"reason": ErrNotPending.Error()}})

	// Another tenant's owner: refused, recorded in the actor's own chain.
	m := len(entries(t, l, other))
	_, _ = l.Create(as(other), tn)
	m = expectOne(t, l, other, m, "usr_test", want{"signing_key.create", "", denied, nil})
	_ = l.Promote(as(other), tn, pending.ID)
	m = expectOne(t, l, other, m, "usr_test", want{"signing_key.promote", pending.ID, denied, nil})
	_ = l.Discard(as(other), tn, pending.ID)
	expectOne(t, l, other, m, "usr_test", want{"signing_key.discard", pending.ID, denied, nil})
	// No principal: no one to attribute an entry to.
	_ = l.Discard(context.Background(), tn, pending.ID)
	if got := len(entries(t, l, tn)); got != n {
		t.Errorf("unattributed attempt wrote %d entries", got-n)
	}
	// Nothing was changed by the refusals.
	if s := statuses(t, l, tn); s[active.ID] != "active" || s[pending.ID] != "pending" || len(s) != 2 {
		t.Errorf("keys after refusals: %v", s)
	}
}

// No entry carries key material in any encoding, and details use only the
// documented fields.
func TestAuditHasNoKeyMaterial(t *testing.T) {
	l, _, _ := setup(t)
	tn := newTenant(t, l)
	owner := as(tn)
	var secrets []string
	keep := func(k *ent.SigningKey) {
		seed, err := l.Keys.Decrypt(*k.PrivateKeyCiphertext, binding(tn, k.ID))
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range [][]byte{seed, append(seed, k.PublicKey...)} { // the seed, and the 64-byte private key
			secrets = append(secrets, string(b), hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b),
				base64.RawStdEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b))
		}
		secrets = append(secrets, *k.PrivateKeyCiphertext)
	}
	a, err := l.Create(owner, tn)
	if err != nil {
		t.Fatal(err)
	}
	keep(a)
	b, err := l.Create(owner, tn)
	if err != nil {
		t.Fatal(err)
	}
	keep(b)
	if err := l.Promote(owner, tn, b.ID); err != nil {
		t.Fatal(err)
	}
	c, err := l.Create(owner, tn)
	if err != nil {
		t.Fatal(err)
	}
	keep(c)
	if err := l.Discard(owner, tn, c.ID); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"alg": true, "from": true, "to": true, "retired": true, "reason": true}
	es := entries(t, l, tn)
	if len(es) != 5 {
		t.Fatalf("%d entries, want 5", len(es))
	}
	for _, e := range es {
		var d map[string]any
		if err := json.Unmarshal([]byte(e.Details), &d); err != nil {
			t.Fatal(err)
		}
		for k := range d {
			if !allowed[k] {
				t.Errorf("%s: unexpected detail %q", e.Action, k)
			}
		}
		raw := e.Details + deref(e.ObjectID) + deref(e.ActorID)
		for _, s := range secrets {
			if strings.Contains(raw, s) {
				t.Errorf("%s: entry contains key material", e.Action)
			}
		}
	}
}

var errInjected = errors.New("injected audit failure")

// failAudit makes every audit write fail until the test ends.
func failAudit(t *testing.T) {
	t.Helper()
	orig := recordAudit
	recordAudit = func(context.Context, *ent.Tx, string, audit.Event) (*ent.AuditEvent, error) { return nil, errInjected }
	t.Cleanup(func() { recordAudit = orig })
}

// Fail closed (ADR-0027): if the audit entry can't be written, the operation
// fails and changes nothing; a refusal whose entry can't be written reports
// both errors.
func TestFailedAuditFailsTheOperation(t *testing.T) {
	l, _, _ := setup(t)
	first, rotating := newTenant(t, l), newTenant(t, l)
	if _, err := l.Create(as(first), first); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Create(as(rotating), rotating); err != nil {
		t.Fatal(err)
	}
	pending, err := l.Create(as(rotating), rotating)
	if err != nil {
		t.Fatal(err)
	}
	beforeFirst, beforeRotating := statuses(t, l, first), statuses(t, l, rotating)
	failAudit(t)

	_, err = l.Create(as(first), first)
	if !errors.Is(err, errInjected) {
		t.Errorf("Create: %v, want the audit error", err)
	}
	if err := l.Promote(as(rotating), rotating, pending.ID); !errors.Is(err, errInjected) {
		t.Errorf("Promote: %v, want the audit error", err)
	}
	if err := l.Discard(as(rotating), rotating, pending.ID); !errors.Is(err, errInjected) {
		t.Errorf("Discard: %v, want the audit error", err)
	}
	_, err = l.Create(asRole(rotating, authz.Viewer), rotating)
	if !errors.Is(err, authz.ErrDenied) || !errors.Is(err, errInjected) {
		t.Errorf("refused Create: %v, want ErrDenied and the audit error", err)
	}
	for tn, before := range map[string]map[string]string{first: beforeFirst, rotating: beforeRotating} {
		after := statuses(t, l, tn)
		if len(after) != len(before) {
			t.Errorf("keys %v, want %v", after, before)
		}
		for id, s := range before {
			if after[id] != s {
				t.Errorf("%s is %s, want %s", id, after[id], s)
			}
		}
	}
}

// Discard and Promote of the same pending key at once: exactly one wins and
// the tenant keeps exactly one active key.
func TestConcurrentDiscardAndPromote(t *testing.T) {
	l, _, _ := setup(t)
	for range 20 {
		tn := newTenant(t, l)
		active, err := l.Create(as(tn), tn)
		if err != nil {
			t.Fatal(err)
		}
		pending, err := l.Create(as(tn), tn)
		if err != nil {
			t.Fatal(err)
		}
		var promoteErr, discardErr error
		var wg sync.WaitGroup
		wg.Go(func() { promoteErr = l.Promote(as(tn), tn, pending.ID) })
		wg.Go(func() { discardErr = l.Discard(as(tn), tn, pending.ID) })
		wg.Wait()
		s := statuses(t, l, tn)
		switch {
		case promoteErr == nil && errors.Is(discardErr, ErrNotPending):
			if s[pending.ID] != "active" || s[active.ID] != "retired" {
				t.Fatalf("promote won, keys %v", s)
			}
		case discardErr == nil && errors.Is(promoteErr, ErrNotPending):
			if s[pending.ID] != "retired" || s[active.ID] != "active" {
				t.Fatalf("discard won, keys %v", s)
			}
		default:
			t.Fatalf("promote %v, discard %v, keys %v", promoteErr, discardErr, s)
		}
	}
}
