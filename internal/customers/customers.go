// Package customers manages a tenant's end customers, who hold licenses
// (ADR-0013). Customers are tenant-wide (authz): customer:read on every
// product to see them, customer:write (managers and up) to change them; a
// product-scoped principal sees none. They are archived, never deleted.
// Every change and refusal is audited (ADR-0027), without names, emails or
// external refs (personal data, ADR-0029).
package customers

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"licenseforge.io/licenseforge/internal/apitokens"
	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/identity"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/customer"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// validEmail: usable (identity.UsableEmail: printable, no spaces, at most
// 320 bytes) and the customers_email_format CHECK's shape: exactly one "@",
// with a non-empty local part and domain.
func validEmail(e string) bool {
	local, domain, ok := strings.Cut(e, "@")
	return identity.UsableEmail(e) && ok && local != "" && domain != "" && !strings.Contains(domain, "@")
}

var (
	// ErrNotFound means no such customer the caller can see.
	ErrNotFound = errors.New("customers: not found")
	// ErrInvalid is wrapped by InvalidError.
	ErrInvalid = errors.New("customers: invalid request")
	// ErrState means the customer is already archived.
	ErrState = errors.New("customers: already archived")
)

// InvalidError names the invalid field (a JSON Pointer into the request).
type InvalidError struct{ Field, Message string }

func (e *InvalidError) Error() string { return fmt.Sprintf("customers: %s: %s", e.Field, e.Message) }
func (e *InvalidError) Unwrap() error { return ErrInvalid }

// Input is a new customer.
type Input struct {
	Name         string
	Email        *string
	ExternalRefs map[string]string
}

// Patch is a merge patch (RFC 7396): nil fields stay. Null lists fields set
// to null: email is cleared; name and external_refs aren't nullable
// (invalid). ExternalRefs merges per key: a value sets the key, nil deletes
// it, absent keys stay.
type Patch struct {
	Name         *string
	Email        *string
	ExternalRefs map[string]*string
	Null         []string
}

// Service works on the tenant pool.
type Service struct{ DB *store.DB }

// List returns up to limit of the tenant's customers (archived included),
// newest first, after (afterAt, afterID) or from the start.
func (s Service) List(ctx context.Context, limit int, afterAt time.Time, afterID string) ([]*ent.Customer, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	all, _, err := authz.Products(ctx, authz.CustomerRead)
	if err != nil || !all {
		return nil, err
	}
	var out []*ent.Customer
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.Customer.Query().Order(ent.Desc(customer.FieldCreatedAt), ent.Desc(customer.FieldID)).Limit(limit)
		if afterID != "" {
			q.Where(customer.Or(customer.CreatedAtLT(afterAt), customer.And(customer.CreatedAt(afterAt), customer.IDLT(afterID))))
		}
		out, err = q.All(ctx)
		return err
	})
	return out, err
}

// Get returns a customer; missing, malformed and hidden are ErrNotFound.
func (s Service) Get(ctx context.Context, id string) (*ent.Customer, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	var c *ent.Customer
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		c, err = lookup(ctx, tx, id, false)
		return err
	})
	return c, err
}

// lookup finds a visible customer (customer:read on every product), FOR
// UPDATE if lock: a license issue holds it FOR SHARE, so an archive waits
// for a concurrent issue (internal/licenses).
func lookup(ctx context.Context, tx *ent.Tx, id string, lock bool) (*ent.Customer, error) {
	if !ids.Valid("cus", id) || authz.Require(ctx, authz.CustomerRead, "") != nil {
		return nil, ErrNotFound
	}
	q := tx.Customer.Query().Where(customer.ID(id))
	if lock {
		q.ForUpdate()
	}
	c, err := q.Only(ctx)
	if ent.IsNotFound(err) {
		return nil, ErrNotFound
	}
	return c, err
}

// Create adds a customer: customer:write first, then the values.
func (s Service) Create(ctx context.Context, in Input) (*ent.Customer, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.By(p, "customer.create", "customer", "")
	err = authz.Require(ctx, authz.CustomerWrite, "")
	if err == nil {
		err = valid(&in.Name, in.Email, in.ExternalRefs)
	}
	if err != nil {
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid)
	}
	if in.ExternalRefs == nil {
		in.ExternalRefs = map[string]string{}
	}
	var c *ent.Customer
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		var err error
		if c, err = tx.Customer.Create().SetTenantID(tenantID).SetName(in.Name).SetNillableEmail(in.Email).
			SetExternalRefs(in.ExternalRefs).Save(ctx); err != nil {
			return err
		}
		ev.ObjectID, ev.Outcome = c.ID, auditevent.OutcomeSuccess
		ev.Details = map[string]any{"email": in.Email != nil, "external_refs": len(in.ExternalRefs)}
		_, err = audit.Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		ev.ObjectID, ev.Details = "", nil
		return nil, audit.Refused(ctx, s.DB, tenantID, ev, err, ErrInvalid)
	}
	return c, nil
}

// Update changes name, email or external refs (merged key by key, RFC 7396). Order
// (ADR-0032): visible (else ErrNotFound), customer:write, then the values.
func (s Service) Update(ctx context.Context, id string, patch Patch) (*ent.Customer, error) {
	return s.change(ctx, "customer.update", id, func(tx *ent.Tx, c *ent.Customer) (*ent.Customer, map[string]any, error) {
		clearEmail := slices.Contains(patch.Null, "email")
		for _, f := range patch.Null {
			if f != "email" {
				return nil, nil, &InvalidError{"/" + f, "can't be null"}
			}
		}
		var refs map[string]string
		if patch.ExternalRefs != nil { // merged into the stored refs, then checked whole
			refs = maps.Clone(c.ExternalRefs)
			if refs == nil {
				refs = map[string]string{}
			}
			for k, v := range patch.ExternalRefs {
				if v == nil {
					delete(refs, k)
				} else {
					refs[k] = *v
				}
			}
		}
		if err := valid(patch.Name, patch.Email, refs); err != nil {
			return nil, nil, err
		}
		u := tx.Customer.UpdateOne(c)
		var changed []string
		if patch.Name != nil {
			u.SetName(*patch.Name)
			changed = append(changed, "name")
		}
		switch {
		case clearEmail:
			u.ClearEmail()
			changed = append(changed, "email")
		case patch.Email != nil:
			u.SetEmail(*patch.Email)
			changed = append(changed, "email")
		}
		if refs != nil {
			u.SetExternalRefs(refs)
			changed = append(changed, "external_refs")
		}
		c, err := u.Save(ctx)
		return c, map[string]any{"changed": changed}, err
	})
}

// Archive archives a customer, once (ErrState after): it keeps its
// licenses, and no new license can be issued for it.
func (s Service) Archive(ctx context.Context, id string) (*ent.Customer, error) {
	return s.change(ctx, "customer.archive", id, func(tx *ent.Tx, c *ent.Customer) (*ent.Customer, map[string]any, error) {
		if c.ArchivedAt != nil {
			return nil, nil, ErrState
		}
		// The database clock, as license times.
		if _, err := tx.ExecContext(ctx, `UPDATE customers SET archived_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1`, c.ID); err != nil {
			return nil, nil, err
		}
		c, err := tx.Customer.Get(ctx, c.ID)
		return c, nil, err
	})
}

// change runs fn on the locked, visible customer after the write check, and
// records the outcome.
func (s Service) change(ctx context.Context, action, id string, fn func(*ent.Tx, *ent.Customer) (*ent.Customer, map[string]any, error)) (*ent.Customer, error) {
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.By(p, action, "customer", "")
	var out *ent.Customer
	err = s.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		c, err := lookup(ctx, tx, id, true)
		if err != nil {
			return err
		}
		ev.ObjectID = c.ID
		if err := authz.Require(ctx, authz.CustomerWrite, ""); err != nil {
			return err
		}
		var details map[string]any
		if out, details, err = fn(tx, c); err != nil {
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

// valid checks the given values (nil: not given).
func valid(name, email *string, refs map[string]string) error {
	if name != nil && apitokens.ValidName(*name) != nil {
		return &InvalidError{"/name", "1 to 200 bytes of printable characters, not blank"}
	}
	if email != nil && !validEmail(*email) {
		return &InvalidError{"/email", "must be an email address without spaces or invisible characters"}
	}
	if refs != nil && !licenses.ValidRefs(refs) {
		return &InvalidError{"/external_refs", "at most 20, keys of 1-64 [a-z0-9_.-], values of up to 255 bytes without control characters"}
	}
	return nil
}
