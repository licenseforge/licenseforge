package catalog

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func defaultTerms() Terms {
	return Terms{ExpiryBasis: plan.ExpiryBasisFromIssue, BindType: plan.BindTypeMachine, LeaseSeconds: 7 * 24 * 3600}
}

func TestPlans(t *testing.T) {
	f := setup(t)
	admin := as(f.a, authz.Admin)
	db, err := f.s.Create(admin, "db", "Database")
	if err != nil {
		t.Fatal(err)
	}
	cache, err := f.s.Create(admin, "cache", "Cache")
	if err != nil {
		t.Fatal(err)
	}
	ps := Plans{DB: f.db}
	terms := defaultTerms()
	terms.DurationMonths, terms.MaxActivations = ptr(12), ptr(3)
	pro, err := ps.Create(admin, PlanInput{ProductID: db.ID, Slug: "pro", Name: "Pro yearly", Terms: terms})
	if err != nil || pro.Slug != "pro" || *pro.DurationMonths != 12 || *pro.MaxActivations != 3 || pro.BindType != plan.BindTypeMachine {
		t.Fatalf("create = %+v, %v", pro, err)
	}
	f.event(t, "plan.create", auditevent.OutcomeSuccess, pro.ID, `"slug":"pro"`)
	trial, err := ps.Create(admin, PlanInput{ProductID: db.ID, Slug: "trial", Name: "Trial", Terms: Terms{
		DurationSeconds: ptr[int64](14 * 86400), ExpiryBasis: plan.ExpiryBasisFromFirstActivation, BindType: plan.BindTypeMachine, LeaseSeconds: 3600}})
	if err != nil {
		t.Fatal(err)
	}
	other, err := ps.Create(admin, PlanInput{ProductID: cache.ID, Slug: "pro", Name: "Pro", Terms: defaultTerms()})
	if err != nil {
		t.Fatalf("same slug on another product: %v", err)
	}
	// List newest first, by product, within the caller's scope.
	if l, err := ps.List(as(f.a, authz.Viewer), db.ID, 1, time.Time{}, ""); err != nil || len(l) != 1 || l[0].ID != trial.ID {
		t.Errorf("page 1 = %v, %v", l, err)
	}
	if l, err := ps.List(as(f.a, authz.Viewer, cache.ID), "", 5, time.Time{}, ""); err != nil || len(l) != 1 || l[0].ID != other.ID {
		t.Errorf("scoped = %v, %v", l, err)
	}
	for name, c := range map[string]struct {
		ctx context.Context
		id  string
	}{
		"missing":          {admin, ids.Plan()},
		"malformed":        {admin, "x"},
		"another tenant's": {as(f.b, authz.Admin), pro.ID},
		"out of scope":     {as(f.a, authz.Admin, cache.ID), pro.ID},
	} {
		if _, err := ps.Get(c.ctx, c.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("get %s: %v", name, err)
		}
		if _, err := ps.Update(c.ctx, c.id, PlanPatch{Name: ptr("x")}); !errors.Is(err, ErrNotFound) {
			t.Errorf("update %s: %v", name, err)
		}
		if _, err := ps.Archive(c.ctx, c.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("archive %s: %v", name, err)
		}
	}
	// Merge patch on the terms: absent stays, null clears a nullable term,
	// the result is checked whole (months and seconds exclusive).
	u, err := ps.Update(admin, pro.ID, PlanPatch{Name: ptr("Pro"), MaxRehosts: ptr(2), Null: []string{"max_activations"}})
	if err != nil || u.Name != "Pro" || u.MaxActivations != nil || *u.MaxRehosts != 2 || *u.DurationMonths != 12 || u.Slug != "pro" {
		t.Fatalf("update = %+v, %v", u, err)
	}
	f.event(t, "plan.update", auditevent.OutcomeSuccess, pro.ID, `"changed":["name","max_activations","max_rehosts"]`)
	if _, err := ps.Update(admin, pro.ID, PlanPatch{DurationSeconds: ptr[int64](60)}); field(err) != "/duration_seconds" {
		t.Errorf("both durations: %v", err)
	}
	if u, err := ps.Update(admin, pro.ID, PlanPatch{DurationSeconds: ptr[int64](60), Null: []string{"duration_months"}}); err != nil || u.DurationMonths != nil || *u.DurationSeconds != 60 {
		t.Errorf("switch to seconds = %+v, %v", u, err)
	}
	// Archive once, atomically; rights before state.
	a, err := ps.Archive(as(f.a, authz.Admin, db.ID), trial.ID)
	if err != nil || a.ArchivedAt == nil {
		t.Fatalf("archive = %+v, %v", a, err)
	}
	f.event(t, "plan.archive", auditevent.OutcomeSuccess, trial.ID, "")
	if _, err := ps.Archive(admin, trial.ID); !errors.Is(err, ErrState) {
		t.Errorf("archive twice: %v", err)
	}
	f.event(t, "plan.archive", auditevent.OutcomeFailure, trial.ID, "")
	if _, err := ps.Archive(as(f.a, authz.Manager), trial.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("manager archives: %v", err)
	}
	// Terms of an archived plan can still change (its sold licenses keep theirs).
	if _, err := ps.Update(admin, trial.ID, PlanPatch{Name: ptr("Old trial")}); err != nil {
		t.Errorf("rename archived: %v", err)
	}
	var inv *InvalidError
	if _, err := ps.Create(admin, PlanInput{ProductID: db.ID, Slug: "pro", Name: "Again", Terms: defaultTerms()}); !errors.Is(err, ErrConflict) || !errors.As(err, &inv) || inv.Field != "/slug" {
		t.Errorf("reused slug: %v", err)
	}
	f.event(t, "plan.create", auditevent.OutcomeFailure, "", "")
	// No names in audit details.
	if err := f.db.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
		es, err := tx.AuditEvent.Query().All(context.Background())
		for _, e := range es {
			for _, v := range []string{"Pro yearly", "Old trial", "Again"} {
				if strings.Contains(e.Details, v) {
					t.Errorf("%s details carry %q", e.Action, v)
				}
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPlanRefusals(t *testing.T) {
	f := setup(t)
	admin := as(f.a, authz.Admin)
	db, err := f.s.Create(admin, "db", "Database")
	if err != nil {
		t.Fatal(err)
	}
	cache, err := f.s.Create(admin, "cache", "Cache")
	if err != nil {
		t.Fatal(err)
	}
	ps := Plans{DB: f.db}
	ok := PlanInput{ProductID: db.ID, Slug: "pro", Name: "Pro", Terms: defaultTerms()}
	for name, c := range map[string]struct {
		ctx     context.Context
		product string
	}{
		"missing":          {admin, ids.Product()},
		"another tenant's": {as(f.b, authz.Admin), db.ID},
		"out of scope":     {as(f.a, authz.Admin, cache.ID), db.ID},
	} {
		in := ok
		in.ProductID = c.product
		var inv *InvalidError
		if _, err := ps.Create(c.ctx, in); !errors.As(err, &inv) || inv.Field != "/product_id" || strings.Contains(inv.Message, "archived") {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := ok
	bad.Slug, bad.Terms.LeaseSeconds = "BAD", 0
	if _, err := ps.Create(as(f.a, authz.Manager), bad); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("manager (rights before values): %v", err)
	}
	f.event(t, "plan.create", auditevent.OutcomeDenied, "", "")
	for name, c := range map[string]struct {
		change func(*PlanInput)
		field  string
	}{
		"slug":              {func(in *PlanInput) { in.Slug = "Pro" }, "/slug"},
		"name":              {func(in *PlanInput) { in.Name = " " }, "/name"},
		"months range":      {func(in *PlanInput) { in.DurationMonths = ptr(1201) }, "/duration_months"},
		"seconds range":     {func(in *PlanInput) { in.DurationSeconds = ptr[int64](0) }, "/duration_seconds"},
		"both durations":    {func(in *PlanInput) { in.DurationMonths, in.DurationSeconds = ptr(1), ptr[int64](1) }, "/duration_seconds"},
		"expiry basis":      {func(in *PlanInput) { in.ExpiryBasis = "later" }, "/expiry_basis"},
		"bind type":         {func(in *PlanInput) { in.BindType = "user" }, "/bind_type"},
		"activations range": {func(in *PlanInput) { in.MaxActivations = ptr(0) }, "/max_activations"},
		"rehosts range":     {func(in *PlanInput) { in.MaxRehosts = ptr(-1) }, "/max_rehosts"},
		"lease range":       {func(in *PlanInput) { in.LeaseSeconds = 0 }, "/lease_seconds"},
		"offline range":     {func(in *PlanInput) { in.MaxOfflineSeconds = ptr[int64](-1) }, "/max_offline_seconds"},
		"grace range":       {func(in *PlanInput) { in.GraceSeconds = 3153600001 }, "/grace_seconds"},
		"site from activation": {func(in *PlanInput) {
			in.BindType, in.ExpiryBasis = plan.BindTypeNone, plan.ExpiryBasisFromFirstActivation
		}, "/expiry_basis"},
		"site with activation max": {func(in *PlanInput) { in.BindType, in.MaxActivations = plan.BindTypeNone, ptr(1) }, "/max_activations"},
	} {
		in := ok
		c.change(&in)
		if _, err := ps.Create(admin, in); field(err) != c.field || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.event(t, "plan.create", auditevent.OutcomeFailure, "", "")
	pro, err := ps.Create(admin, ok)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]PlanPatch{
		"null name":         {Null: []string{"name"}},
		"null lease":        {Null: []string{"lease_seconds"}},
		"null expiry basis": {Null: []string{"expiry_basis"}},
	} {
		if _, err := ps.Update(admin, pro.ID, p); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ps.Update(as(f.a, authz.Manager), pro.ID, PlanPatch{Name: ptr("")}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("manager update: %v", err)
	}
	// No new plan on an archived product (ADR-0015).
	if _, err := f.s.Archive(admin, cache.ID); err != nil {
		t.Fatal(err)
	}
	in := ok
	in.ProductID = cache.ID
	var inv *InvalidError
	if _, err := ps.Create(admin, in); !errors.As(err, &inv) || inv.Field != "/product_id" || !strings.Contains(inv.Message, "archived") {
		t.Errorf("archived product: %v", err)
	}
}
