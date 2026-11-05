// Package catalog manages a tenant's products (ADR-0015); features, plans and
// the feature × plan matrix follow. Products are product-scoped objects
// (ADR-0019): a scoped principal sees and changes only its own. Every change
// and refusal is audited (ADR-0027), a change in its transaction.
//
// Lock contract (schema.PlanFeature): writers of plan features lock the plan
// row FOR UPDATE first. Products don't take part in it.
package catalog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/apitokens"
	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/product"
	"licenseforge.io/licenseforge/internal/store/ids"
	"licenseforge.io/licenseforge/internal/store/schema"
)

var (
	// ErrNotFound means no such product the caller can see (missing and
	// outside the caller's product scope alike, ADR-0032).
	ErrNotFound = errors.New("catalog: not found")
	// ErrInvalid and ErrConflict are wrapped by InvalidError.
	ErrInvalid  = errors.New("catalog: invalid request")
	ErrConflict = errors.New("catalog: conflict")
	// ErrState means the product is already archived.
	ErrState = errors.New("catalog: already archived")
)

// InvalidError names the field (a JSON Pointer into the request); Conflict
// means the value is valid but taken (a slug).
type InvalidError struct {
	Field, Message string
	Conflict       bool
}

func (e *InvalidError) Error() string { return fmt.Sprintf("catalog: %s: %s", e.Field, e.Message) }
func (e *InvalidError) Unwrap() error {
	if e.Conflict {
		return ErrConflict
	}
	return ErrInvalid
}

// Patch is a merge patch: nil fields stay; Null lists fields set to null
// (none is nullable: invalid, after the lookup and rights checks).
type Patch struct {
	Name *string
	Null []string
}

// Products works on the tenant pool.
type Products struct{ DB *store.DB }

// List returns up to limit of the tenant's products in the caller's scope,
// archived ones included unless archived says which, newest first, after
// (afterAt, afterID) or from the start.
func (s Products) List(ctx context.Context, archived *bool, limit int, afterAt time.Time, afterID string) ([]*ent.Product, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, scope, err := authz.Products(ctx, authz.CatalogRead)
	if err != nil {
		return nil, err
	}
	var out []*ent.Product
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.Product.Query().Order(ent.Desc(product.FieldCreatedAt), ent.Desc(product.FieldID)).Limit(limit)
		if !all {
			q.Where(product.IDIn(scope...))
		}
		switch {
		case archived == nil:
		case *archived:
			q.Where(product.ArchivedAtNotNil())
		default:
			q.Where(product.ArchivedAtIsNil())
		}
		if afterID != "" {
			q.Where(product.Or(product.CreatedAtLT(afterAt), product.And(product.CreatedAt(afterAt), product.IDLT(afterID))))
		}
		out, err = q.All(ctx)
		return err
	})
	return out, err
}

// Get returns a product; missing, malformed and out of scope are ErrNotFound.
func (s Products) Get(ctx context.Context, id string) (*ent.Product, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	var p *ent.Product
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		p, err = lookup(ctx, tx, id, false)
		return err
	})
	return p, err
}

// lookup finds a visible product (catalog:read on it), FOR UPDATE if lock.
func lookup(ctx context.Context, tx *ent.Tx, id string, lock bool) (*ent.Product, error) {
	if !ids.Valid("prd", id) || authz.Require(ctx, authz.CatalogRead, id) != nil {
		return nil, ErrNotFound
	}
	q := tx.Product.Query().Where(product.ID(id))
	if lock {
		q.ForUpdate()
	}
	p, err := q.Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	return p, err
}

// Create adds a product. Creating is tenant-wide: catalog:write on every
// product, before the values are checked.
func (s Products) Create(ctx context.Context, slug, name string) (*ent.Product, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	pr, _ := authz.FromContext(ctx)
	ev := audit.By(pr, "product.create", "product", "")
	err = authz.Require(ctx, authz.CatalogWrite, "")
	if err == nil {
		err = validSlug(slug)
	}
	if err == nil {
		err = validName(name)
	}
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid)
	}
	var p *ent.Product
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		if p, err = tx.Product.Create().SetTenantID(tenantID).SetSlug(slug).SetName(name).Save(ctx); err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "product_tenant_id_slug" {
				return &InvalidError{Field: "/slug", Message: "already used by a product of this tenant", Conflict: true}
			}
			return err
		}
		ev.ObjectID, ev.Outcome, ev.Details = p.ID, auditevent.OutcomeSuccess, map[string]any{"slug": slug}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		ev.ObjectID, ev.Details = "", nil
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrConflict)
	}
	return p, nil
}

// Update renames a product (the slug is immutable: licenses carry it).
// Order (ADR-0032): visible (else ErrNotFound), catalog:write on it, then
// the values.
func (s Products) Update(ctx context.Context, id string, patch Patch) (*ent.Product, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	pr, _ := authz.FromContext(ctx)
	ev := audit.By(pr, "product.update", "product", "")
	var p *ent.Product
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		if p, err = lookup(ctx, tx, id, true); err != nil {
			return err
		}
		ev.ObjectID = p.ID
		if err := authz.Require(ctx, authz.CatalogWrite, p.ID); err != nil {
			return err
		}
		if len(patch.Null) > 0 {
			return &InvalidError{Field: "/" + patch.Null[0], Message: "can't be null"}
		}
		if patch.Name != nil {
			if err := validName(*patch.Name); err != nil {
				return err
			}
			if p, err = tx.Product.UpdateOne(p).SetName(*patch.Name).Save(ctx); err != nil {
				return err
			}
		}
		ev.Outcome, ev.Details = auditevent.OutcomeSuccess, map[string]any{"name_changed": patch.Name != nil}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid, ErrNotFound)
	}
	return p, nil
}

// Archive archives a product, once (ErrState after). Order (ADR-0032):
// visible (else ErrNotFound), catalog:write on it. Its licenses and their
// activations keep working; no new license, plan or feature can be created
// on it (ADR-0015).
func (s Products) Archive(ctx context.Context, id string) (*ent.Product, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	pr, _ := authz.FromContext(ctx)
	ev := audit.By(pr, "product.archive", "product", "")
	var p *ent.Product
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		// FOR UPDATE: a license issue holds the product FOR SHARE, so the
		// archive waits for it (internal/licenses).
		if p, err = lookup(ctx, tx, id, true); err != nil {
			return err
		}
		ev.ObjectID = p.ID
		if err := authz.Require(ctx, authz.CatalogWrite, p.ID); err != nil {
			return err
		}
		if p.ArchivedAt != nil {
			return ErrState
		}
		// The database clock, as license times.
		if _, err := tx.ExecContext(ctx, `UPDATE products SET archived_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1`, p.ID); err != nil {
			return err
		}
		if p, err = tx.Product.Get(ctx, p.ID); err != nil {
			return err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrNotFound, ErrState)
	}
	return p, nil
}

func validSlug(s string) error {
	if len(s) > 63 || !schema.SlugRE.MatchString(s) {
		return &InvalidError{Field: "/slug", Message: "lowercase letters and digits in words joined by single dashes, at most 63"}
	}
	return nil
}

// validName: 1-200 bytes of printable characters, not blank (as API token
// names).
func validName(name string) error {
	if apitokens.ValidName(name) != nil {
		return &InvalidError{Field: "/name", Message: "1 to 200 bytes of printable characters, not blank"}
	}
	return nil
}
