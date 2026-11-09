package activations

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/sdk/go/licensefile"
)

// receipt is the lfrcpt1 text an SDK writes after deleting the file of l.
func (f fixture) receipt(t *testing.T, l Lease, machine string, edit func(*licensefile.Receipt)) string {
	t.Helper()
	r := licensefile.Receipt{Tenant: f.a, LicenseID: l.Claims.LicenseID, Fingerprint: machine, FileSHA256: l.FileSHA256,
		Nonce: bytes.Repeat([]byte{3}, 16), Created: time.Now()}
	if edit != nil {
		edit(&r)
	}
	s, err := licensefile.EncodeReceipt(r)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f fixture) offlineEvents(t *testing.T, action string) []*ent.AuditEvent {
	t.Helper()
	var out []*ent.AuditEvent
	for _, e := range f.events(t) {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func TestReturn(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "offline") // max_activations 1
	machine := fp()
	file, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, machine, nil))
	if err != nil {
		t.Fatal(err)
	}
	text := f.receipt(t, file, machine, nil)
	got, err := f.s.Return(ctx, manager(f.a), text)
	if err != nil || got.ID != file.ActivationID || got.DeactivatedAt == nil {
		t.Fatalf("Return = %+v, %v", got, err)
	}
	es := f.offlineEvents(t, "activation.offline_return")
	if len(es) != 1 || es[0].Outcome != auditevent.OutcomeSuccess || *es[0].ObjectID != got.ID || *es[0].ActorID != "usr_test" ||
		!strings.Contains(es[0].Details, licensefile.OfflineSHA256(text)) || !strings.Contains(es[0].Details, file.FileSHA256) {
		t.Errorf("events %+v", es)
	}
	// The seat is free: another machine can take it.
	if _, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, fp(), nil)); err != nil {
		t.Errorf("seat not freed: %v", err)
	}
	// The same receipt again, even with other line endings: the same
	// answer, no new entry.
	again, err := f.s.Return(ctx, manager(f.a), text[:10]+"\r\n"+text[10:])
	if err != nil || again.ID != got.ID || !again.DeactivatedAt.Equal(*got.DeactivatedAt) {
		t.Errorf("repeat = %+v, %v", again, err)
	}
	if n := len(f.offlineEvents(t, "activation.offline_return")); n != 1 {
		t.Errorf("repeat audited: %d entries", n)
	}
}

// Only the current file returns the seat: after a renewal, the older
// file's receipt is refused and the seat stays out.
func TestReturnOlderFile(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "offline")
	machine := fp()
	old, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, machine, nil))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second) // a new iat: a new file
	cur, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, machine, func(r *licensefile.Request) { r.Nonce[0] = 9 }))
	if err != nil || cur.FileSHA256 == old.FileSHA256 || cur.ActivationID != old.ActivationID {
		t.Fatalf("renewal = %+v, %v", cur, err)
	}
	if _, err := f.s.Return(ctx, manager(f.a), f.receipt(t, old, machine, nil)); !errors.Is(err, ErrSuperseded) {
		t.Errorf("older file: %v", err)
	}
	if as := f.activations(t, is.License.ID); len(as) != 1 || as[0].DeactivatedAt != nil {
		t.Fatalf("seat changed: %+v", as)
	}
	if _, err := f.s.Return(ctx, manager(f.a), f.receipt(t, cur, machine, nil)); err != nil {
		t.Errorf("current file: %v", err)
	}
	// Once returned, the older file's receipt is about a free seat: no seat
	// of that machine is out, and no file matches it any more.
	if _, err := f.s.Return(ctx, manager(f.a), f.receipt(t, old, machine, nil)); !errors.Is(err, ErrNotFound) {
		t.Errorf("older file after return: %v", err)
	}
}

func TestReturnRefusals(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "offline")
	machine := fp()
	file, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, machine, nil))
	if err != nil {
		t.Fatal(err)
	}
	online := f.issue(t, "offline")
	onlineFP := fp()
	act, err := f.s.Activate(ctx, f.req(online.Key, onlineFP))
	if err != nil {
		t.Fatal(err)
	}
	support := authz.Principal{Kind: authz.User, ID: "usr_s", TenantID: f.a, Role: authz.Support, Scope: authz.Scope{All: true}}
	scoped := authz.Principal{Kind: authz.User, ID: "usr_o", TenantID: f.a, Role: authz.Manager, Scope: authz.Scope{Products: []string{"prd_" + strings.Repeat("0", 26)}}}
	for name, c := range map[string]struct {
		p       authz.Principal
		text    string
		want    error
		outcome auditevent.Outcome
	}{
		"malformed":     {manager(f.a), "lfrcpt1.e30", ErrInvalid, auditevent.OutcomeFailure},
		"other tenant":  {manager(f.b), f.receipt(t, file, machine, nil), ErrInvalid, auditevent.OutcomeFailure},
		"no permission": {support, f.receipt(t, file, machine, nil), authz.ErrDenied, auditevent.OutcomeDenied},
		"out of scope":  {scoped, f.receipt(t, file, machine, nil), ErrNotFound, auditevent.OutcomeDenied},
		"unknown license": {manager(f.a), f.receipt(t, file, machine, func(r *licensefile.Receipt) { r.LicenseID = "lic_" + strings.Repeat("0", 26) }),
			ErrNotFound, auditevent.OutcomeFailure},
		"another file":    {manager(f.a), f.receipt(t, file, machine, func(r *licensefile.Receipt) { r.FileSHA256 = strings.Repeat("0", 64) }), ErrSuperseded, auditevent.OutcomeFailure},
		"another machine": {manager(f.a), f.receipt(t, file, fp(), nil), ErrNotFound, auditevent.OutcomeFailure},
		"online seat": {manager(f.a), f.receipt(t, Lease{Claims: licensefile.Claims{LicenseID: online.License.ID}, FileSHA256: strings.Repeat("a", 64)}, onlineFP, nil),
			ErrNotFound, auditevent.OutcomeFailure},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(f.offlineEvents(t, "activation.offline_return"))
			_, err := f.s.Return(ctx, c.p, c.text)
			if !errors.Is(err, c.want) || (name == "out of scope" && err != ErrNotFound) { //nolint:errorlint // exactly, not errHidden
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.p.TenantID != f.a {
				return
			}
			es := f.offlineEvents(t, "activation.offline_return")
			if len(es) != before+1 {
				t.Fatalf("%d new entries", len(es)-before)
			}
			if e := es[len(es)-1]; e.Outcome != c.outcome || e.ObjectID != nil || !strings.Contains(e.Details, "receipt_sha256") ||
				(errors.Is(c.want, ErrInvalid) && !strings.Contains(e.Details, `"reason":"`+ErrInvalid.Error()+`"`)) {
				t.Errorf("event %+v", e)
			}
		})
	}
	if as := f.activations(t, is.License.ID); len(as) != 1 || as[0].DeactivatedAt != nil {
		t.Errorf("a refusal freed the seat: %+v", as)
	}
	if as := f.activations(t, online.License.ID); len(as) != 1 || as[0].ID != act.ActivationID || as[0].DeactivatedAt != nil {
		t.Errorf("a receipt touched an online seat: %+v", as)
	}
}

// A seat already freed from the dashboard answers the receipt unchanged,
// and a revoked license's seat can still be returned.
func TestReturnFreedOrRevoked(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	is := f.issue(t, "offline")
	machine := fp()
	file, err := f.s.Offline(ctx, manager(f.a), f.offlineReq(t, is.Key, machine, nil))
	if err != nil {
		t.Fatal(err)
	}
	freed, err := f.s.DeactivateByID(ctx, manager(f.a), is.License.ID, file.ActivationID)
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.events(t))
	if got, err := f.s.Return(ctx, manager(f.a), f.receipt(t, file, machine, nil)); err != nil || !got.DeactivatedAt.Equal(*freed.DeactivatedAt) {
		t.Errorf("after dashboard deactivate: %+v, %v", got, err)
	}
	if len(f.events(t)) != before {
		t.Error("an unchanged seat was audited")
	}
	rev := f.issue(t, "offline")
	machine = fp()
	file, err = f.s.Offline(ctx, manager(f.a), f.offlineReq(t, rev.Key, machine, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.lic.Revoke(ctx, manager(f.a), rev.License.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := f.s.Return(ctx, manager(f.a), f.receipt(t, file, machine, nil)); err != nil || got.DeactivatedAt == nil {
		t.Errorf("revoked license: %+v, %v", got, err)
	}
}
