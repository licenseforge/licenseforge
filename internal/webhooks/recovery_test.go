package webhooks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/secrets"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func TestEventType(t *testing.T) {
	for _, c := range []struct{ action, details, want string }{
		{"license.issue", `{}`, "license.issued"},
		{"license.revoke", `{}`, "license.revoked"},
		{"license.suspend", `{}`, "license.suspended"},
		{"license.reinstate", `{}`, "license.reinstated"},
		{"activation.create", `{}`, "activation.created"},
		{"activation.offline", `{"new_seat": true}`, "activation.created"},
		{"activation.offline", `{}`, ""}, // a renewal of a seat held
		{"activation.offline", `{"new_seat": false}`, ""},
		{"activation.deactivate", `{}`, "activation.deactivated"},
		{"activation.offline_return", `{}`, "activation.deactivated"},
		{"license.key_reveal", `{}`, ""},
		{"license.offline_file", `{}`, ""},
		{"webhook.create", `{}`, ""},
	} {
		if got := EventType(c.action, c.details); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.action, c.details, got, c.want)
		}
	}
	for _, a := range mapped {
		if EventType(a, `{"new_seat": true}`) == "" {
			t.Errorf("mapped action %s maps to nothing", a)
		}
	}
}

// record writes an audit entry to tenant's chain and returns its seq.
func (f fixture) record(t *testing.T, tenant, action string, outcome auditevent.Outcome, details map[string]any) int64 {
	t.Helper()
	var seq int64
	if err := f.db.WithTenant(context.Background(), tenant, func(tx *ent.Tx) error {
		e, err := audit.Record(context.Background(), tx, tenant, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: action, Outcome: outcome, Details: details})
		if err == nil {
			seq = e.Seq
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return seq
}

// setRetry puts a cursor in retry, as the dispatcher would (platform pool).
func (f fixture) setRetry(t *testing.T, id string, attempts int) {
	t.Helper()
	if err := f.db.WithPlatform(context.Background(), func(tx *ent.Tx) error {
		_, err := tx.ExecContext(context.Background(), `UPDATE webhook_cursors SET attempts = $2, next_attempt_at = now() + interval '1 hour' WHERE endpoint_id = $1`, id, attempts)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDisableEnable(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	c, err := f.s.Create(ctx, hookURL, []string{"license.issued"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := f.s.Disable(ctx, c.ID)
	if err != nil || e.Enabled || e.DisabledReason != UserDisabled || e.Seq != c.Seq {
		t.Fatalf("Disable = %+v, %v", e, err)
	}
	if _, err := f.s.Disable(ctx, c.ID); !errors.Is(err, ErrState) {
		t.Errorf("disable twice: %v", err)
	}
	f.setRetry(t, c.ID, 5)
	if _, err := f.s.Enable(f.as(f.a, f.viewer, authz.Viewer), c.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer enable: %v", err)
	}
	if _, err := f.s.Enable(f.as(f.b, f.ownerB, authz.Owner), c.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another tenant's enable: %v", err)
	}
	e, err = f.s.Enable(ctx, c.ID)
	if err != nil || !e.Enabled || e.DisabledReason != "" || e.Attempts != 0 || e.NextAttemptAt != nil || e.Seq != c.Seq {
		t.Fatalf("Enable = %+v, %v", e, err)
	}
	if _, err := f.s.Enable(ctx, c.ID); !errors.Is(err, ErrState) {
		t.Errorf("enable an enabled endpoint: %v", err)
	}
	ev := f.events(t, f.a, "webhook.enable")
	var d map[string]any
	if err := json.Unmarshal([]byte(ev[1].Details), &d); err != nil || ev[1].Outcome != auditevent.OutcomeSuccess || d["disabled_reason"] != UserDisabled {
		t.Errorf("enable audited as %s %s", ev[1].Outcome, ev[1].Details)
	}
}

// Enable refuses an endpoint whose secret or URL can't be read (a lost
// master key, a disable by the dispatcher): it would only be disabled again.
// Rotating the secret or updating the URL is the way out, then Enable works.
func TestEnableUnreadable(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	other, err := secrets.ParseKeyring("k9=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, secrets.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	// How the ciphertext goes bad: another master key (ErrUnknownKey), this
	// key but another row's binding (ErrDecrypt, what the dispatcher disables
	// on), or readable but unusable (what Send would refuse).
	type spoil func(id string, p secrets.Purpose) (string, error)
	unknownKey := func(id string, p secrets.Purpose) (string, error) {
		return other.Encrypt([]byte("x"), secrets.Binding{Purpose: p, TenantID: f.a, RowID: id})
	}
	wrongBinding := func(_ string, p secrets.Purpose) (string, error) {
		return f.s.Keys.Encrypt([]byte("x"), secrets.Binding{Purpose: p, TenantID: f.a, RowID: ids.WebhookEndpoint()})
	}
	readable := func(plain string) spoil {
		return func(id string, p secrets.Purpose) (string, error) {
			return f.s.Keys.Encrypt([]byte(plain), secrets.Binding{Purpose: p, TenantID: f.a, RowID: id})
		}
	}
	corrupt := func(id string, p secrets.Purpose, how spoil, set func(*ent.WebhookEndpointUpdateOne, []byte) *ent.WebhookEndpointUpdateOne) {
		t.Helper()
		bad, err := how(id, p)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error { return set(tx.WebhookEndpoint.UpdateOneID(id), []byte(bad)).Exec(ctx) }); err != nil {
			t.Fatal(err)
		}
	}
	rotate := func(id string) error { _, _, err := f.s.RotateSecret(ctx, id); return err }
	update := func(id string) error { u := hookURL; _, err := f.s.Update(ctx, id, &u, nil); return err }
	secret, url := (*ent.WebhookEndpointUpdateOne).SetSecretCiphertext, (*ent.WebhookEndpointUpdateOne).SetURLCiphertext
	for _, tc := range []struct {
		name string
		p    secrets.Purpose
		how  spoil
		set  func(*ent.WebhookEndpointUpdateOne, []byte) *ent.WebhookEndpointUpdateOne
		want error
		fix  func(id string) error
	}{
		{"secret, unknown key", secrets.PurposeWebhookSecret, unknownKey, secret, ErrSecretUnreadable, rotate},
		{"secret, wrong binding", secrets.PurposeWebhookSecret, wrongBinding, secret, ErrSecretUnreadable, rotate},
		{"secret, not a whsec_ secret", secrets.PurposeWebhookSecret, readable("not-a-secret"), secret, ErrSecretUnreadable, rotate},
		{"url, unknown key", secrets.PurposeWebhookURL, unknownKey, url, ErrURLUnreadable, update},
		{"url, wrong binding", secrets.PurposeWebhookURL, wrongBinding, url, ErrURLUnreadable, update},
		{"url, not https", secrets.PurposeWebhookURL, readable("http://hooks.example.com/x"), url, ErrURLUnreadable, update},
	} {
		c, err := f.s.Create(ctx, hookURL, []string{"license.issued"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.Disable(ctx, c.ID); err != nil {
			t.Fatal(err)
		}
		corrupt(c.ID, tc.p, tc.how, tc.set)
		if _, err := f.s.Enable(ctx, c.ID); !errors.Is(err, tc.want) || !errors.Is(err, ErrState) {
			t.Errorf("%s: enable = %v, want %v", tc.name, err, tc.want)
		}
		if row := f.raw(t, f.a, c.ID); row.Enabled {
			t.Errorf("%s: enabled although unusable", tc.name)
		}
		if ev := f.events(t, f.a, "webhook.enable"); ev[0].Outcome != auditevent.OutcomeFailure { // newest first
			t.Errorf("%s: refusal audited as %s", tc.name, ev[0].Outcome)
		}
		if err := tc.fix(c.ID); err != nil {
			t.Fatalf("%s: fix: %v", tc.name, err)
		}
		if e, err := f.s.Enable(ctx, c.ID); err != nil || !e.Enabled {
			t.Errorf("%s: enable after the fix = %+v, %v", tc.name, e, err)
		}
	}
}

func TestSkip(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	c, err := f.s.Create(ctx, hookURL, []string{"license.revoked", "activation.created"})
	if err != nil {
		t.Fatal(err)
	}
	ok := auditevent.OutcomeSuccess
	f.record(t, f.a, "license.issue", ok, nil)                                    // not subscribed
	f.record(t, f.a, "activation.offline", ok, map[string]any{"new_seat": false}) // a renewal: no event
	seat := f.record(t, f.a, "activation.offline", ok, map[string]any{"new_seat": true})
	f.record(t, f.a, "license.revoke", auditevent.OutcomeFailure, nil) // refused: no event
	revoked := f.record(t, f.a, "license.revoke", ok, nil)
	f.setRetry(t, c.ID, 3)
	// Only the event held back can be skipped.
	if _, err := f.s.SkipEvent(ctx, c.ID, revoked); !errors.Is(err, ErrState) {
		t.Errorf("skip past the next event: %v", err)
	}
	if _, err := f.s.SkipEvent(ctx, c.ID, seat-1); !errors.Is(err, ErrState) {
		t.Errorf("skip an entry that isn't an event: %v", err)
	}
	for _, bad := range []int64{0, -1} {
		if _, err := f.s.SkipEvent(ctx, c.ID, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("skip %d: %v", bad, err)
		}
	}
	ref := f.events(t, f.a, "webhook.skip_event")
	var rd map[string]any
	if err := json.Unmarshal([]byte(ref[0].Details), &rd); err != nil || ref[0].Outcome != auditevent.OutcomeFailure || rd["requested_seq"] != float64(-1) {
		t.Errorf("refused skip audited as %s %s", ref[0].Outcome, ref[0].Details)
	}
	// The subscription changed since the dashboard showed the event: refused.
	if _, err := f.s.Update(ctx, c.ID, nil, []string{"license.revoked"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SkipEvent(ctx, c.ID, seat); !errors.Is(err, ErrState) {
		t.Errorf("skip an event no longer subscribed: %v", err)
	}
	if _, err := f.s.Update(ctx, c.ID, nil, []string{"license.revoked", "activation.created"}); err != nil {
		t.Fatal(err)
	}
	f.setRetry(t, c.ID, 3)
	if _, err := f.s.SkipEvent(f.as(f.a, f.viewer, authz.Viewer), c.ID, seat); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer skip: %v", err)
	}
	if g, _ := f.s.Get(ctx, c.ID); g.NextSeq != seat {
		t.Errorf("next_seq %d, want %d (the event held back)", g.NextSeq, seat)
	}
	e, err := f.s.SkipEvent(ctx, c.ID, seat)
	if err != nil || e.Seq != seat || e.Attempts != 0 || e.NextAttemptAt != nil {
		t.Fatalf("SkipEvent = %+v, %v", e, err)
	}
	if _, err := f.s.SkipEvent(ctx, c.ID, seat); !errors.Is(err, ErrState) { // passed already
		t.Errorf("skip twice: %v", err)
	}
	if e, err := f.s.SkipEvent(ctx, c.ID, revoked); err != nil || e.Seq != revoked {
		t.Errorf("skip the next one: %+v, %v", e, err)
	}
	// Skip to now: past everything so far, retry state reset.
	f.record(t, f.a, "license.revoke", ok, nil)
	last := f.record(t, f.a, "license.issue", ok, nil)
	f.setRetry(t, c.ID, 2)
	e, err = f.s.SkipToNow(ctx, c.ID)
	if err != nil || e.Seq < last || e.Attempts != 0 || e.NextAttemptAt != nil {
		t.Fatalf("SkipToNow = %+v, %v (last %d)", e, err, last)
	}
	ev := f.events(t, f.a, "webhook.skip_to_now")
	var d map[string]any
	if err := json.Unmarshal([]byte(ev[0].Details), &d); err != nil || d["from_seq"] != float64(revoked) || d["to_seq"] != float64(e.Seq) {
		t.Errorf("skip to now audited as %s", ev[0].Details)
	}
	ev = f.events(t, f.a, "webhook.skip_event")
	if err := json.Unmarshal([]byte(ev[0].Details), &d); err != nil || ev[0].Outcome != auditevent.OutcomeSuccess || d["skipped_seq"] != float64(revoked) || d["from_seq"] != float64(seat) {
		t.Errorf("skip audited as %s %s", ev[0].Outcome, ev[0].Details)
	}
}

// No event pending (e.g. the held-back event's type was unsubscribed): there
// is nothing to skip.
func TestSkipNothingPending(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	c, err := f.s.Create(ctx, hookURL, []string{"license.revoked"})
	if err != nil {
		t.Fatal(err)
	}
	issued := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, nil)
	f.setRetry(t, c.ID, 4)
	if e, _ := f.s.Get(ctx, c.ID); e.NextSeq != 0 {
		t.Errorf("next_seq %d with nothing pending", e.NextSeq)
	}
	if _, err := f.s.SkipEvent(ctx, c.ID, issued); !errors.Is(err, ErrState) {
		t.Errorf("skip with nothing pending: %v", err)
	}
	if e, _ := f.s.Get(ctx, c.ID); e.Attempts != 4 {
		t.Errorf("retry state reset by a refused skip: %d", e.Attempts)
	}
}

// The look-ahead bound: an event further than within entries ahead isn't
// seen (0: no bound).
func TestNextEventWithin(t *testing.T) {
	f := setup(t)
	ctx := f.as(f.a, f.ownerA, authz.Owner)
	base := f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, nil)
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, nil)
	rev := f.record(t, f.a, "license.revoke", auditevent.OutcomeSuccess, nil) // base+2
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		for within, want := range map[int64]int64{1: 0, 2: rev, 0: rev} {
			got, err := nextEventWithin(ctx, tx, f.a, base, []string{"license.revoked"}, within)
			if err != nil {
				return err
			}
			if got != want {
				t.Errorf("within %d: %d, want %d", within, got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
