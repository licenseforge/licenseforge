package customers

import (
	"errors"
	"testing"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// A customer archived by mistake comes back (ADR-0015, amended).
func TestRestore(t *testing.T) {
	f := setup(t)
	mgr := as(f.a, authz.Manager)
	c, err := f.s.Create(mgr, Input{Name: "Contoso"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Restore(mgr, c.ID); !errors.Is(err, ErrState) {
		t.Errorf("restore of an active customer: %v", err)
	}
	if _, err := f.s.Archive(mgr, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Restore(as(f.a, authz.Viewer), c.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer: %v", err)
	}
	r, err := f.s.Restore(mgr, c.ID)
	if err != nil || r.ArchivedAt != nil {
		t.Fatalf("restore = %+v, %v", r, err)
	}
	if e := f.lastEvent(t); e.Action != "customer.restore" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != c.ID {
		t.Errorf("audit = %+v", e)
	}
	if a, err := f.s.Archive(mgr, c.ID); err != nil || a.ArchivedAt == nil {
		t.Errorf("archive again: %v", err)
	}
}
