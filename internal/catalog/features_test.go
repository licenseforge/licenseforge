package catalog

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func TestFeatures(t *testing.T) {
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
	fs := Features{DB: f.db}
	sso, err := fs.Create(admin, FeatureInput{ProductID: db.ID, Key: "sso", Name: "Single sign-on", Type: feature.TypeBoolean})
	if err != nil || sso.Key != "sso" || sso.ProductID != db.ID || sso.Type != feature.TypeBoolean {
		t.Fatalf("create = %+v, %v", sso, err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "feature.create" || e.Outcome != auditevent.OutcomeSuccess || *e.ObjectID != sso.ID {
		t.Errorf("audit = %+v", e)
	}
	seats, err := fs.Create(admin, FeatureInput{ProductID: db.ID, Key: "max_users", Name: "Users", Type: feature.TypeLimit, Unit: ptr("users"), Description: ptr("Named users")})
	if err != nil || *seats.Unit != "users" {
		t.Fatalf("create limit = %+v, %v", seats, err)
	}
	other, err := fs.Create(admin, FeatureInput{ProductID: cache.ID, Key: "sso", Name: "SSO", Type: feature.TypeBoolean})
	if err != nil {
		t.Fatalf("same key on another product: %v", err)
	}
	// List newest first, by product, within the caller's scope.
	l, err := fs.List(as(f.a, authz.Viewer), db.ID, 1, time.Time{}, "")
	if err != nil || len(l) != 1 || l[0].ID != seats.ID {
		t.Fatalf("page 1 = %v, %v", l, err)
	}
	if l, err := fs.List(as(f.a, authz.Viewer), db.ID, 5, l[0].CreatedAt, l[0].ID); err != nil || len(l) != 1 || l[0].ID != sso.ID {
		t.Fatalf("page 2 = %v, %v", l, err)
	}
	if l, err := fs.List(as(f.a, authz.Viewer), "", 5, time.Time{}, ""); err != nil || len(l) != 3 {
		t.Errorf("all products = %v, %v", l, err)
	}
	if l, err := fs.List(as(f.a, authz.Viewer, cache.ID), "", 5, time.Time{}, ""); err != nil || len(l) != 1 || l[0].ID != other.ID {
		t.Errorf("scoped = %v, %v", l, err)
	}
	if l, err := fs.List(as(f.a, authz.Viewer, cache.ID), db.ID, 5, time.Time{}, ""); err != nil || len(l) != 0 {
		t.Errorf("scoped, other product = %v, %v", l, err)
	}
	// Hidden and missing alike for get, update and archive.
	for name, c := range map[string]struct {
		ctx context.Context
		id  string
	}{
		"missing":          {admin, ids.Feature()},
		"malformed":        {admin, "x"},
		"another tenant's": {as(f.b, authz.Admin), sso.ID},
		"out of scope":     {as(f.a, authz.Admin, cache.ID), sso.ID},
	} {
		if _, err := fs.Get(c.ctx, c.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("get %s: %v", name, err)
		}
		if _, err := fs.Update(c.ctx, c.id, FeaturePatch{Name: ptr("x")}); !errors.Is(err, ErrNotFound) {
			t.Errorf("update %s: %v", name, err)
		}
		if _, err := fs.Archive(c.ctx, c.id); !errors.Is(err, ErrNotFound) {
			t.Errorf("archive %s: %v", name, err)
		}
	}
	// Merge patch: description and unit are nullable; key and type never change.
	u, err := fs.Update(admin, seats.ID, FeaturePatch{Name: ptr("Named users"), Null: []string{"description"}})
	if err != nil || u.Name != "Named users" || u.Description != nil || *u.Unit != "users" || u.Key != "max_users" {
		t.Fatalf("update = %+v, %v", u, err)
	}
	f.event(t, "feature.update", auditevent.OutcomeSuccess, seats.ID, `"changed":["name","description"]`)
	// Archive once; archived features stay listed; the key is never reused.
	a, err := fs.Archive(as(f.a, authz.Admin, db.ID), sso.ID)
	if err != nil || a.ArchivedAt == nil {
		t.Fatalf("archive = %+v, %v", a, err)
	}
	f.event(t, "feature.archive", auditevent.OutcomeSuccess, sso.ID, "")
	if _, err := fs.Archive(admin, sso.ID); !errors.Is(err, ErrState) {
		t.Errorf("archive twice: %v", err)
	}
	f.event(t, "feature.archive", auditevent.OutcomeFailure, sso.ID, "")
	for _, op := range []func() error{
		func() error { _, err := fs.Update(admin, ids.Feature(), FeaturePatch{Name: ptr("x")}); return err },
		func() error { _, err := fs.Archive(admin, ids.Feature()); return err },
	} {
		if err := op(); !errors.Is(err, ErrNotFound) {
			t.Errorf("missing: %v", err)
		}
		e := f.lastEvent(t, f.a)
		if e.Outcome != auditevent.OutcomeFailure || e.ObjectID != nil || !strings.HasPrefix(e.Action, "feature.") {
			t.Errorf("missing-feature audit = %+v", e)
		}
	}
	if _, err := fs.Archive(as(f.a, authz.Manager), sso.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("manager archives (rights before state): %v", err)
	}
	var inv *InvalidError
	if _, err := fs.Create(admin, FeatureInput{ProductID: db.ID, Key: "sso", Name: "Again", Type: feature.TypeBoolean}); !errors.Is(err, ErrConflict) || !errors.As(err, &inv) || inv.Field != "/key" {
		t.Errorf("reused key: %v", err)
	}
	f.event(t, "feature.create", auditevent.OutcomeFailure, "", "")
	if _, err := fs.Create(admin, FeatureInput{ProductID: db.ID, Key: "BAD", Name: "Bad", Type: feature.TypeBoolean}); field(err) != "/key" {
		t.Errorf("bad key: %v", err)
	}
	f.event(t, "feature.create", auditevent.OutcomeFailure, "", "")
	// No audit entry carries a name, description or unit (text a vendor
	// may consider confidential); only keys, types and which fields changed.
	if err := f.db.WithTenant(context.Background(), f.a, func(tx *ent.Tx) error {
		es, err := tx.AuditEvent.Query().All(context.Background())
		for _, e := range es {
			for _, v := range []string{"Single sign-on", "Named users", "users", "Again"} {
				if strings.Contains(e.Details, `"`+v+`"`) {
					t.Errorf("%s details carry %q: %s", e.Action, v, e.Details)
				}
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// event checks the newest audit entry: action, outcome, object (or none) and
// a fragment of its details.
func (f fixture) event(t *testing.T, action string, outcome auditevent.Outcome, object, details string) {
	t.Helper()
	e := f.lastEvent(t, f.a)
	if e.Action != action || e.Outcome != outcome || (object == "") != (e.ObjectID == nil) || (object != "" && *e.ObjectID != object) || !strings.Contains(e.Details, details) {
		t.Errorf("audit = %s %s %v %s, want %s %s %s %s", e.Action, e.Outcome, e.ObjectID, e.Details, action, outcome, object, details)
	}
}

func TestFeatureRefusals(t *testing.T) {
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
	fs := Features{DB: f.db}
	ok := FeatureInput{ProductID: db.ID, Key: "sso", Name: "SSO", Type: feature.TypeBoolean}
	// The product is a body reference: missing and hidden alike (422).
	for name, c := range map[string]struct {
		ctx     context.Context
		product string
	}{
		"missing":          {admin, ids.Product()},
		"malformed":        {admin, "x"},
		"another tenant's": {as(f.b, authz.Admin), db.ID},
		"out of scope":     {as(f.a, authz.Admin, cache.ID), db.ID},
	} {
		in := ok
		in.ProductID = c.product
		var inv *InvalidError
		if _, err := fs.Create(c.ctx, in); !errors.As(err, &inv) || inv.Field != "/product_id" || strings.Contains(inv.Message, "archived") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Rights before values.
	bad := FeatureInput{ProductID: db.ID, Key: "BAD", Name: "", Type: "nope"}
	if _, err := fs.Create(as(f.a, authz.Manager), bad); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("manager: %v", err)
	}
	if e := f.lastEvent(t, f.a); e.Action != "feature.create" || e.Outcome != auditevent.OutcomeDenied {
		t.Errorf("denied audit = %+v", e)
	}
	for name, c := range map[string]struct {
		change func(*FeatureInput)
		field  string
	}{
		"key uppercase":     {func(in *FeatureInput) { in.Key = "SSO" }, "/key"},
		"key dash":          {func(in *FeatureInput) { in.Key = "max-users" }, "/key"},
		"key too long":      {func(in *FeatureInput) { in.Key = strings.Repeat("k", 64) }, "/key"},
		"name blank":        {func(in *FeatureInput) { in.Name = " " }, "/name"},
		"type":              {func(in *FeatureInput) { in.Type = "string" }, "/type"},
		"description blank": {func(in *FeatureInput) { in.Description = ptr(" ") }, "/description"},
		"description long":  {func(in *FeatureInput) { in.Description = ptr(strings.Repeat("d", 2001)) }, "/description"},
		"unit blank":        {func(in *FeatureInput) { in.Unit = ptr("") }, "/unit"},
		"unit long":         {func(in *FeatureInput) { in.Unit = ptr(strings.Repeat("u", 41)) }, "/unit"},
	} {
		in := ok
		c.change(&in)
		if _, err := fs.Create(admin, in); field(err) != c.field || !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	sso, err := fs.Create(admin, ok)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]FeaturePatch{"null name": {Null: []string{"name"}}, "blank name": {Name: ptr(" ")}} {
		if _, err := fs.Update(admin, sso.ID, p); field(err) != "/name" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := fs.Update(as(f.a, authz.Manager), sso.ID, FeaturePatch{Name: ptr("")}); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("manager update: %v", err)
	}
	// No new feature on an archived product (ADR-0015); a hidden archived
	// product still answers like a missing one.
	if _, err := f.s.Archive(admin, cache.ID); err != nil {
		t.Fatal(err)
	}
	var inv *InvalidError
	if _, err := fs.Create(admin, FeatureInput{ProductID: cache.ID, Key: "x", Name: "X", Type: feature.TypeBoolean}); !errors.As(err, &inv) || inv.Field != "/product_id" || !strings.Contains(inv.Message, "archived") {
		t.Errorf("archived product: %v", err)
	}
	if _, err := fs.Create(as(f.a, authz.Admin, db.ID), FeatureInput{ProductID: cache.ID, Key: "x", Name: "X", Type: feature.TypeBoolean}); !errors.As(err, &inv) || strings.Contains(inv.Message, "archived") {
		t.Errorf("hidden archived product: %v", err)
	}
}

// A feature created while its product is being archived waits for the
// archive (the product is locked FOR SHARE) and is then refused.
func TestFeatureCreateWaitsForArchive(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	admin := as(f.a, authz.Admin)
	db, err := f.s.Create(admin, "db", "Database")
	if err != nil {
		t.Fatal(err)
	}
	adminDB, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adminDB.Close() }()
	done := make(chan error, 1)
	if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT id FROM products WHERE id = $1 FOR UPDATE`, db.ID); err != nil {
			return err
		}
		go func() {
			_, err := Features{DB: f.db}.Create(admin, FeatureInput{ProductID: db.ID, Key: "sso", Name: "SSO", Type: feature.TypeBoolean})
			done <- err
		}()
		for i := 0; ; i++ {
			var n int
			if err := adminDB.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				break
			}
			if i == 100 {
				return errors.New("the create never waited")
			}
			time.Sleep(20 * time.Millisecond)
		}
		_, err := tx.ExecContext(ctx, `UPDATE products SET archived_at = clock_timestamp() WHERE id = $1`, db.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		var inv *InvalidError
		if !errors.As(err, &inv) || inv.Field != "/product_id" || !strings.Contains(inv.Message, "archived") {
			t.Errorf("create after a concurrent archive: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("create didn't finish")
	}
}

// A feature change that waits for a concurrent archive of the feature sees
// it archived (it looks again after archive_once filters the row it waited
// for): a second archive is ErrState, an update succeeds.
func TestFeatureChangeWaitsForArchive(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	admin := as(f.a, authz.Admin)
	db, err := f.s.Create(admin, "db", "Database")
	if err != nil {
		t.Fatal(err)
	}
	fs := Features{DB: f.db}
	adminDB, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adminDB.Close() }()
	for name, c := range map[string]struct {
		key  string
		op   func(id string) error
		want error
	}{
		"archive": {"a", func(id string) error { _, err := fs.Archive(admin, id); return err }, ErrState},
		"update":  {"u", func(id string) error { _, err := fs.Update(admin, id, FeaturePatch{Name: ptr("Renamed")}); return err }, nil},
	} {
		ft, err := fs.Create(admin, FeatureInput{ProductID: db.ID, Key: c.key, Name: "F", Type: feature.TypeBoolean})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		if err := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE features SET archived_at = clock_timestamp() WHERE id = $1`, ft.ID); err != nil {
				return err
			}
			go func() { done <- c.op(ft.ID) }()
			for i := 0; ; i++ {
				var n int
				if err := adminDB.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'`, env.Name).Scan(&n); err != nil {
					return err
				}
				if n > 0 {
					return nil
				}
				if i == 100 {
					return errors.New("never waited")
				}
				time.Sleep(20 * time.Millisecond)
			}
		}); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Errorf("%s after a concurrent archive: %v, want %v", name, err, c.want)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s didn't finish", name)
		}
	}
}
