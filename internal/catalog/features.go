package catalog

import (
	"context"
	"errors"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ent/product"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/schema"
)

// Features works on the tenant pool. A feature belongs to a product and
// shares its scope (ADR-0019); its key and type never change, and features
// are archived, never deleted, so a key is never reused (ADR-0015).
// Archiving a feature doesn't touch plans: plan features that grant it stay
// until the matrix changes them, and licenses keep their snapshot.
type Features struct{ DB *store.DB }

// FeatureInput is a new feature.
type FeatureInput struct {
	ProductID, Key, Name string
	Type                 feature.Type
	Description, Unit    *string
}

// FeaturePatch is a merge patch: nil fields stay; Null lists fields set to
// null (description and unit are cleared; name isn't nullable: invalid).
type FeaturePatch struct {
	Name, Description, Unit *string
	Null                    []string
}

// List returns up to limit of the tenant's features in the caller's scope,
// of productID if not "", archived ones included, newest first.
func (s Features) List(ctx context.Context, productID string, limit int, afterAt time.Time, afterID string) ([]*ent.Feature, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, scope, err := authz.Products(ctx, authz.CatalogRead)
	if err != nil {
		return nil, err
	}
	var out []*ent.Feature
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.Feature.Query().Order(ent.Desc(feature.FieldCreatedAt), ent.Desc(feature.FieldID)).Limit(limit)
		if !all {
			q.Where(feature.ProductIDIn(scope...))
		}
		if productID != "" {
			q.Where(feature.ProductID(productID))
		}
		if afterID != "" {
			q.Where(feature.Or(feature.CreatedAtLT(afterAt), feature.And(feature.CreatedAt(afterAt), feature.IDLT(afterID))))
		}
		out, err = q.All(ctx)
		return err
	})
	return out, err
}

// Get returns a feature; missing, malformed and out of scope are ErrNotFound.
func (s Features) Get(ctx context.Context, id string) (*ent.Feature, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	var f *ent.Feature
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		f, err = lookupFeature(ctx, tx, id, false)
		return err
	})
	return f, err
}

// lookupFeature finds a visible feature (catalog:read on its product); one
// lookup, then the scope, so missing and hidden do the same work.
func lookupFeature(ctx context.Context, tx *ent.Tx, id string, lock bool) (*ent.Feature, error) {
	if !ids.Valid("ftr", id) {
		return nil, ErrNotFound
	}
	q := func() (*ent.Feature, error) {
		q := tx.Feature.Query().Where(feature.ID(id))
		if lock {
			q.ForUpdate()
		}
		return q.Only(ctx)
	}
	f, err := q()
	if lock && (ent.IsNotFound(err) || err == nil && authz.Require(ctx, authz.CatalogRead, f.ProductID) != nil) {
		// Locked after waiting for a concurrent archive, the row is rechecked
		// as its newer version, which archive_or_restore filters (its subquery reads
		// this statement's snapshot): a second statement sees it. Out-of-scope
		// rows take the second statement too, so missing and hidden do the
		// same work.
		f, err = q()
	}
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if authz.Require(ctx, authz.CatalogRead, f.ProductID) != nil {
		return nil, ErrNotFound
	}
	return f, nil
}

// errNoProduct answers a missing, malformed or hidden product reference.
var errNoProduct = &InvalidError{Field: "/product_id", Message: "no such product"}

// activeProduct checks a body reference to a product for a new plan or
// feature, in ADR-0032's order: visible (else errNoProduct, missing and
// hidden alike), catalog:write on it, then not archived. FOR SHARE: an
// archive (FOR UPDATE) waits for the creation, or wins first.
func activeProduct(ctx context.Context, tx *ent.Tx, id string) error {
	if !ids.Valid("prd", id) {
		return errNoProduct
	}
	lock := func() (*ent.Product, error) { return tx.Product.Query().Where(product.ID(id)).ForShare().Only(ctx) }
	visible := authz.Require(ctx, authz.CatalogRead, id) == nil
	p, err := lock()
	if ent.IsNotFound(err) || !visible {
		// Locked after waiting for a concurrent archive, the row is rechecked
		// as its newer version, which archive_or_restore filters (its subquery reads
		// this statement's snapshot): a second statement sees it archived.
		// Out-of-scope products take the same two statements as missing
		// ones, so timing doesn't tell them apart.
		p, err = lock()
	}
	if ent.IsNotFound(err) || err == nil && !visible {
		return errNoProduct
	}
	if err != nil {
		return err
	}
	if err := authz.Require(ctx, authz.CatalogWrite, id); err != nil {
		return err
	}
	if p.ArchivedAt != nil {
		return &InvalidError{Field: "/product_id", Message: "the product is archived"}
	}
	return nil
}

// Create adds a feature to a product.
func (s Features) Create(ctx context.Context, in FeatureInput) (*ent.Feature, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	pr, _ := authz.FromContext(ctx)
	ev := audit.By(pr, "feature.create", "feature", "")
	var f *ent.Feature
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		if err := activeProduct(ctx, tx, in.ProductID); err != nil {
			return err
		}
		if err := validFeature(&in.Key, &in.Name, &in.Type, in.Description, in.Unit); err != nil {
			return err
		}
		var err error
		f, err = tx.Feature.Create().SetTenantID(tenantID).SetProductID(in.ProductID).SetKey(in.Key).SetName(in.Name).
			SetType(in.Type).SetNillableDescription(in.Description).SetNillableUnit(in.Unit).Save(ctx)
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "feature_product_id_key" {
			return &InvalidError{Field: "/key", Message: "already used by a feature of this product (keys are never reused)", Conflict: true}
		}
		if err != nil {
			return err
		}
		ev.ObjectID, ev.Outcome = f.ID, auditevent.OutcomeSuccess
		ev.Details = map[string]any{"product_id": f.ProductID, "key": f.Key, "type": string(f.Type)}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrConflict)
	}
	return f, nil
}

// Update changes a feature's name, description or unit.
func (s Features) Update(ctx context.Context, id string, patch FeaturePatch) (*ent.Feature, error) {
	return s.change(ctx, "feature.update", id, func(tx *ent.Tx, f *ent.Feature) (*ent.Feature, map[string]any, error) {
		for _, n := range patch.Null {
			if n == "name" {
				return nil, nil, &InvalidError{Field: "/name", Message: "can't be null"}
			}
		}
		if err := validFeature(nil, patch.Name, nil, patch.Description, patch.Unit); err != nil {
			return nil, nil, err
		}
		u := tx.Feature.UpdateOne(f)
		var changed []string
		if patch.Name != nil {
			u.SetName(*patch.Name)
			changed = append(changed, "name")
		}
		switch {
		case slices.Contains(patch.Null, "description"):
			u.ClearDescription()
			changed = append(changed, "description")
		case patch.Description != nil:
			u.SetDescription(*patch.Description)
			changed = append(changed, "description")
		}
		switch {
		case slices.Contains(patch.Null, "unit"):
			u.ClearUnit()
			changed = append(changed, "unit")
		case patch.Unit != nil:
			u.SetUnit(*patch.Unit)
			changed = append(changed, "unit")
		}
		f, err := u.Save(ctx)
		return f, map[string]any{"changed": changed}, err
	})
}

// Archive archives a feature (ErrState if it already is; Restore undoes it). It can no longer be
// added to a license by override (internal/licenses); its key is kept.
func (s Features) Archive(ctx context.Context, id string) (*ent.Feature, error) {
	return s.change(ctx, "feature.archive", id, func(tx *ent.Tx, f *ent.Feature) (*ent.Feature, map[string]any, error) {
		// Atomic and counted: only an unarchived feature is archived, once.
		res, err := tx.ExecContext(ctx, `UPDATE features SET archived_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1 AND archived_at IS NULL`, f.ID)
		if err != nil {
			return nil, nil, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return nil, nil, err
		} else if n != 1 {
			return nil, nil, ErrState
		}
		f, err = tx.Feature.Get(ctx, f.ID)
		return f, nil, err
	})
}

// Restore brings an archived feature back (ADR-0015, amended): it is usable
// again where an archived one isn't. ErrState if it isn't archived.
func (s Features) Restore(ctx context.Context, id string) (*ent.Feature, error) {
	return s.change(ctx, "feature.restore", id, func(tx *ent.Tx, f *ent.Feature) (*ent.Feature, map[string]any, error) {
		res, err := tx.ExecContext(ctx, `UPDATE features SET archived_at = NULL, updated_at = clock_timestamp() WHERE id = $1 AND archived_at IS NOT NULL`, f.ID)
		if err != nil {
			return nil, nil, err
		}
		if n, err := res.RowsAffected(); err != nil {
			return nil, nil, err
		} else if n != 1 {
			return nil, nil, ErrState
		}
		f, err = tx.Feature.Get(ctx, f.ID)
		return f, nil, err
	})
}

// change runs fn on the locked, visible feature after catalog:write on its
// product, and records the outcome.
func (s Features) change(ctx context.Context, action, id string, fn func(*ent.Tx, *ent.Feature) (*ent.Feature, map[string]any, error)) (*ent.Feature, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	pr, _ := authz.FromContext(ctx)
	ev := audit.By(pr, action, "feature", "")
	var out *ent.Feature
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		f, err := lookupFeature(ctx, tx, id, true)
		if err != nil {
			return err
		}
		ev.ObjectID = f.ID
		if err := authz.Require(ctx, authz.CatalogWrite, f.ProductID); err != nil {
			return err
		}
		var details map[string]any
		if out, details, err = fn(tx, f); err != nil {
			return err
		}
		ev.Outcome, ev.Details = auditevent.OutcomeSuccess, details
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrNotFound, ErrState)
	}
	return out, nil
}

// validFeature checks the given values (nil: not given).
func validFeature(key, name *string, typ *feature.Type, description, unit *string) error {
	switch {
	case key != nil && (len(*key) > 63 || !schema.KeyRE.MatchString(*key)):
		return &InvalidError{Field: "/key", Message: "snake_case (lowercase letters and digits joined by single underscores), at most 63"}
	case name != nil:
		if err := validName(*name); err != nil {
			return err
		}
	}
	if typ != nil && feature.TypeValidator(*typ) != nil {
		return &InvalidError{Field: "/type", Message: "boolean or limit"}
	}
	if description != nil && !validText(*description, 2000) {
		return &InvalidError{Field: "/description", Message: "1 to 2000 bytes of text, not blank"}
	}
	if unit != nil && !validText(*unit, 40) {
		return &InvalidError{Field: "/unit", Message: "1 to 40 bytes of printable characters, not blank"}
	}
	return nil
}

// validText: valid UTF-8, at most n bytes, not blank, printable (newlines
// and tabs allowed).
func validText(s string, n int) bool {
	if len(s) > n || !utf8.ValidString(s) {
		return false
	}
	blank := true
	for _, r := range s {
		if !unicode.IsGraphic(r) && r != '\n' && r != '\t' {
			return false
		}
		if !unicode.IsSpace(r) {
			blank = false
		}
	}
	return !blank
}
