package catalog

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// The feature × plan matrix (ADR-0015): a merge patch keyed by feature key,
// true grants a boolean feature, an integer sets a limit (-1 unlimited),
// null removes the grant.
func TestPlanFeatures(t *testing.T) {
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
	fs, ps := Features{DB: f.db}, Plans{DB: f.db}
	for _, in := range []FeatureInput{
		{ProductID: db.ID, Key: "sso", Name: "SSO", Type: feature.TypeBoolean},
		{ProductID: db.ID, Key: "export", Name: "Export", Type: feature.TypeBoolean},
		{ProductID: db.ID, Key: "max_users", Name: "Users", Type: feature.TypeLimit},
		{ProductID: cache.ID, Key: "cluster", Name: "Cluster", Type: feature.TypeBoolean},
	} {
		if _, err := fs.Create(admin, in); err != nil {
			t.Fatal(err)
		}
	}
	pro, err := ps.Create(admin, PlanInput{ProductID: db.ID, Slug: "pro", Name: "Pro", Terms: defaultTerms()})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ps.Features(admin, pro.ID); err != nil || len(got) != 0 {
		t.Fatalf("new plan = %v, %v", got, err)
	}

	// Set, then change and remove in one patch.
	got, err := ps.PatchFeatures(admin, pro.ID, map[string]any{"sso": true, "export": true, "max_users": 50.0})
	if want := map[string]any{"sso": true, "export": true, "max_users": int64(50)}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("patch = %v, %v, want %v", got, err, want)
	}
	f.event(t, "plan.features.update", auditevent.OutcomeSuccess, pro.ID, `"set":["export","max_users","sso"]`)
	got, err = ps.PatchFeatures(admin, pro.ID, map[string]any{"export": nil, "max_users": -1.0})
	if want := map[string]any{"sso": true, "max_users": int64(-1)}; err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("patch 2 = %v, %v, want %v", got, err, want)
	}
	f.event(t, "plan.features.update", auditevent.OutcomeSuccess, pro.ID, `"removed":["export"]`)
	if again, err := ps.Features(as(f.a, authz.Viewer), pro.ID); err != nil || !reflect.DeepEqual(again, got) {
		t.Errorf("read = %v, %v", again, err)
	}
	// Nothing to change: the same answer, no entry.
	before := f.lastEvent(t, f.a).Seq
	if same, err := ps.PatchFeatures(admin, pro.ID, map[string]any{"sso": true, "export": nil, "max_users": -1.0}); err != nil || !reflect.DeepEqual(same, got) {
		t.Errorf("no-op patch = %v, %v", same, err)
	}
	if f.lastEvent(t, f.a).Seq != before {
		t.Errorf("a no-op patch was audited")
	}

	// Refusals: the whole patch or nothing, the field names the key.
	for name, c := range map[string]struct {
		patch map[string]any
		field string
	}{
		"unknown key":        {map[string]any{"sso": nil, "nope": true}, "/nope"},
		"another product's":  {map[string]any{"cluster": true}, "/cluster"},
		"limit on a boolean": {map[string]any{"sso": 5.0}, "/sso"},
		"true on a limit":    {map[string]any{"max_users": true}, "/max_users"},
		"false":              {map[string]any{"sso": false}, "/sso"},
		"fraction":           {map[string]any{"max_users": 1.5}, "/max_users"},
		"below -1":           {map[string]any{"max_users": -2.0}, "/max_users"},
		"above 2^53-1":       {map[string]any{"max_users": 9007199254740992.0}, "/max_users"},
		"a string":           {map[string]any{"max_users": "5"}, "/max_users"},
		"malformed key":      {map[string]any{"Bad Key": true}, ""},
	} {
		_, err := ps.PatchFeatures(admin, pro.ID, c.patch)
		if !errors.Is(err, ErrInvalid) || field(err) != c.field {
			t.Errorf("%s: %v (field %q, want %q)", name, err, field(err), c.field)
		}
	}
	if now, _ := ps.Features(admin, pro.ID); !reflect.DeepEqual(now, got) {
		t.Errorf("a refused patch changed the plan: %v", now)
	}
	f.event(t, "plan.features.update", auditevent.OutcomeFailure, pro.ID, "")

	// Archived features: no new grant; an existing one can change or go.
	exp, err := fs.List(admin, db.ID, 10, time.Time{}, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, ft := range exp {
		if ft.Key == "export" || ft.Key == "max_users" {
			if _, err := fs.Archive(admin, ft.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := ps.PatchFeatures(admin, pro.ID, map[string]any{"export": true}); !errors.Is(err, ErrInvalid) || field(err) != "/export" {
		t.Errorf("grant an archived feature: %v", err)
	}
	if got, err := ps.PatchFeatures(admin, pro.ID, map[string]any{"max_users": 10.0}); err != nil || got["max_users"] != int64(10) {
		t.Errorf("change an archived feature's limit: %v, %v", got, err)
	}
	if got, err := ps.PatchFeatures(admin, pro.ID, map[string]any{"max_users": nil}); err != nil || len(got) != 1 {
		t.Errorf("remove an archived feature: %v, %v", got, err)
	}

	// Access: missing, malformed and out of scope look the same; seen but
	// read-only is denied, audited.
	scoped := as(f.a, authz.Admin, cache.ID)
	for name, id := range map[string]string{"missing": ids.Plan(), "malformed": "x", "hidden": pro.ID} {
		ctx := admin
		if name == "hidden" {
			ctx = scoped
		}
		if _, err := ps.Features(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("read %s: %v", name, err)
		}
		if _, err := ps.PatchFeatures(ctx, id, map[string]any{"sso": nil}); !errors.Is(err, ErrNotFound) {
			t.Errorf("patch %s: %v", name, err)
		}
	}
	if _, err := ps.PatchFeatures(as(f.a, authz.Viewer), pro.ID, map[string]any{"sso": nil}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("viewer patch: %v", err)
	}
	f.event(t, "plan.features.update", auditevent.OutcomeDenied, pro.ID, "")
	if _, err := ps.Features(as(f.b, authz.Owner), pro.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("another tenant: %v", err)
	}
	// Too many keys at once.
	big := map[string]any{}
	for i := range maxPatchKeys + 1 {
		big["k"+string(rune('a'+i%26))+ids.Plan()[4:10]] = nil
	}
	if _, err := ps.PatchFeatures(admin, pro.ID, big); !errors.Is(err, ErrInvalid) || field(err) != "" || !strings.Contains(err.Error(), "at most 1000") {
		t.Errorf("oversized patch: %v", err)
	}
}
