package webhooks

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
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
	if _, err := f.s.Disable(ctx, c.ID); !errors.Is(err, ErrInvalid) {
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
	if _, err := f.s.Enable(ctx, c.ID); !errors.Is(err, ErrInvalid) {
		t.Errorf("enable an enabled endpoint: %v", err)
	}
	ev := f.events(t, f.a, "webhook.enable")
	var d map[string]any
	if err := json.Unmarshal([]byte(ev[1].Details), &d); err != nil || ev[1].Outcome != auditevent.OutcomeSuccess || d["disabled_reason"] != UserDisabled {
		t.Errorf("enable audited as %s %s", ev[1].Outcome, ev[1].Details)
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
	if _, err := f.s.SkipEvent(ctx, c.ID, revoked); !errors.Is(err, ErrInvalid) {
		t.Errorf("skip past the next event: %v", err)
	}
	if _, err := f.s.SkipEvent(ctx, c.ID, seat-1); !errors.Is(err, ErrInvalid) {
		t.Errorf("skip an entry that isn't an event: %v", err)
	}
	if _, err := f.s.SkipEvent(f.as(f.a, f.viewer, authz.Viewer), c.ID, seat); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer skip: %v", err)
	}
	e, err := f.s.SkipEvent(ctx, c.ID, seat)
	if err != nil || e.Seq != seat || e.Attempts != 0 || e.NextAttemptAt != nil {
		t.Fatalf("SkipEvent = %+v, %v", e, err)
	}
	if _, err := f.s.SkipEvent(ctx, c.ID, seat); !errors.Is(err, ErrInvalid) { // passed already
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
	if err := json.Unmarshal([]byte(ev[0].Details), &d); err != nil || ev[0].Outcome != auditevent.OutcomeSuccess || d["skipped_seq"] != float64(revoked) {
		t.Errorf("skip audited as %s %s", ev[0].Outcome, ev[0].Details)
	}
}
