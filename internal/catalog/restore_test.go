package catalog

import (
	"errors"
	"testing"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Archive is reversible (ADR-0015, amended): restore needs the same rights,
// refuses what isn't archived, is audited, and the row can be archived again.
func TestRestore(t *testing.T) {
	f := setup(t)
	admin := as(f.a, authz.Admin)
	db, err := f.s.Create(admin, "db", "Database")
	if err != nil {
		t.Fatal(err)
	}
	pro, err := Plans{DB: f.db}.Create(admin, PlanInput{ProductID: db.ID, Slug: "pro", Name: "Pro", Terms: defaultTerms()})
	if err != nil {
		t.Fatal(err)
	}
	sso, err := Features{DB: f.db}.Create(admin, FeatureInput{ProductID: db.ID, Key: "sso", Name: "SSO", Type: feature.TypeBoolean})
	if err != nil {
		t.Fatal(err)
	}
	type ops struct {
		archive, restore func(id string) (archived bool, err error)
	}
	for name, c := range map[string]struct {
		id, action string
		op         ops
		restoreAs  func(id string) error
	}{
		"product": {db.ID, "product", ops{
			func(id string) (bool, error) {
				p, err := f.s.Archive(admin, id)
				return p != nil && p.ArchivedAt != nil, err
			},
			func(id string) (bool, error) {
				p, err := f.s.Restore(admin, id)
				return p != nil && p.ArchivedAt != nil, err
			},
		}, func(id string) error { _, err := f.s.Restore(as(f.a, authz.Manager), id); return err }},
		"plan": {pro.ID, "plan", ops{
			func(id string) (bool, error) {
				p, err := Plans{DB: f.db}.Archive(admin, id)
				return p != nil && p.ArchivedAt != nil, err
			},
			func(id string) (bool, error) {
				p, err := Plans{DB: f.db}.Restore(admin, id)
				return p != nil && p.ArchivedAt != nil, err
			},
		}, func(id string) error { _, err := Plans{DB: f.db}.Restore(as(f.a, authz.Manager), id); return err }},
		"feature": {sso.ID, "feature", ops{
			func(id string) (bool, error) {
				x, err := Features{DB: f.db}.Archive(admin, id)
				return x != nil && x.ArchivedAt != nil, err
			},
			func(id string) (bool, error) {
				x, err := Features{DB: f.db}.Restore(admin, id)
				return x != nil && x.ArchivedAt != nil, err
			},
		}, func(id string) error { _, err := Features{DB: f.db}.Restore(as(f.a, authz.Manager), id); return err }},
	} {
		if _, err := c.op.restore(c.id); !errors.Is(err, ErrState) {
			t.Errorf("%s: restore of an active one: %v", name, err)
		}
		if archived, err := c.op.archive(c.id); err != nil || !archived {
			t.Fatalf("%s: archive: %v", name, err)
		}
		if err := c.restoreAs(c.id); !errors.Is(err, authz.ErrDenied) {
			t.Errorf("%s: manager restore: %v", name, err)
		}
		if archived, err := c.op.restore(c.id); err != nil || archived {
			t.Fatalf("%s: restore = archived %v, %v", name, archived, err)
		}
		f.event(t, c.action+".restore", auditevent.OutcomeSuccess, c.id, "")
		if archived, err := c.op.archive(c.id); err != nil || !archived {
			t.Errorf("%s: archive again: %v", name, err)
		}
	}
	// Hidden and missing are not found, as for archive.
	if _, err := f.s.Restore(as(f.b, authz.Admin), db.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another tenant's: %v", err)
	}
	if _, err := f.s.Restore(admin, ids.Product()); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}
