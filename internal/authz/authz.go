// Package authz is the tenant-scoped role model (ADR-0019): a fixed set of
// roles, each a fixed set of permissions, checked with one Require call per
// handler. Row-level security (ADR-0009) is the backstop behind it.
//
// Invariant: the RLS tenant of a request is the principal's TenantID (use
// TenantID), never a value read from the URL separately, so a principal
// resolved for one tenant can't act in another.
package authz

import (
	"context"
	"errors"
	"slices"
)

// ErrDenied means the principal may not do this. Handlers map it to 403 (or
// 404 where revealing existence matters).
var ErrDenied = errors.New("authz: permission denied")

// Permission names one action, "object:verb".
type Permission string

const (
	TenantRead   Permission = "tenant:read"
	TenantWrite  Permission = "tenant:write" // settings, incl. audit retention: owner only
	TenantDelete Permission = "tenant:delete"
	BillingWrite Permission = "billing:write"

	KeyRead  Permission = "key:read"  // public signing keys
	KeyWrite Permission = "key:write" // create, promote, discard signing keys

	CatalogRead  Permission = "catalog:read" // products, features, plans
	CatalogWrite Permission = "catalog:write"

	MemberRead   Permission = "member:read" // members and invitations
	MemberWrite  Permission = "member:write"
	TokenRead    Permission = "token:read" // API token metadata, never the secret
	TokenWrite   Permission = "token:write"
	WebhookRead  Permission = "webhook:read"
	WebhookWrite Permission = "webhook:write"
	AuditRead    Permission = "audit:read" // privileged (ADR-0027)

	CustomerRead  Permission = "customer:read"
	CustomerWrite Permission = "customer:write"
	LicenseRead   Permission = "license:read"
	LicenseIssue  Permission = "license:issue"
	LicenseWrite  Permission = "license:write" // suspend, reinstate, revoke, edit

	ActivationRead    Permission = "activation:read"
	ActivationManage  Permission = "activation:manage"  // rehost, deactivate machines, reset activations
	ActivationOffline Permission = "activation:offline" // air-gapped activation files

	ActivationClient Permission = "activation:client" // SDK: activate, validate, refresh, deactivate
)

// Role is a built-in role. Custom roles are not in v0.1.
type Role string

const (
	Owner   Role = "owner"
	Admin   Role = "admin"
	Manager Role = "manager"
	Support Role = "support"
	Viewer  Role = "viewer"
	SDK     Role = "sdk" // API tokens only
)

// Each role has the permissions of the role below it plus its own; sdk stands alone.
var (
	viewer  = []Permission{TenantRead, KeyRead, CatalogRead, MemberRead, TokenRead, WebhookRead, CustomerRead, LicenseRead, ActivationRead}
	support = append(slices.Clone(viewer), ActivationManage)
	manager = append(slices.Clone(support), CustomerWrite, LicenseIssue, LicenseWrite, ActivationOffline)
	admin   = append(slices.Clone(manager), CatalogWrite, MemberWrite, TokenWrite, WebhookWrite, AuditRead)
	owner   = append(slices.Clone(admin), TenantWrite, TenantDelete, BillingWrite, KeyWrite)

	permissions = map[Role][]Permission{
		Owner: owner, Admin: admin, Manager: manager, Support: support, Viewer: viewer,
		SDK: {ActivationClient},
	}
)

// Valid reports whether r is a built-in role.
func (r Role) Valid() bool { _, ok := permissions[r]; return ok }

// ForMembership reports whether r can be given to a person; sdk is for API
// tokens only.
func (r Role) ForMembership() bool { return r.Valid() && r != SDK }

// Can reports whether r grants p.
func (r Role) Can(p Permission) bool { return slices.Contains(permissions[r], p) }

// PrincipalKind says who is acting.
type PrincipalKind string

const (
	User  PrincipalKind = "user"
	Token PrincipalKind = "token"
)

// Scope is the products a membership or token covers: every product, or only
// the listed ones. The zero value covers nothing, so a scope that failed to
// load denies instead of widening to every product.
type Scope struct {
	All      bool
	Products []string
}

func (s Scope) covers(product string) bool {
	return s.All || slices.Contains(s.Products, product) // valid scopes contain no ""
}

// valid reports whether s is well formed: All, or a list of product IDs.
func (s Scope) valid() bool {
	return s.All != (len(s.Products) > 0) && !slices.Contains(s.Products, "")
}

// Principal is who is acting in one tenant, resolved from the session or API
// token after the membership check.
type Principal struct {
	Kind     PrincipalKind
	ID       string // user or token ID
	TenantID string
	Role     Role
	Scope    Scope
}

type ctxKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	p.Scope.Products = slices.Clone(p.Scope.Products) // the caller can't change it afterwards
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns a copy of the principal in ctx, if any; changing it
// doesn't change the context.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	p.Scope.Products = slices.Clone(p.Scope.Products)
	return p, ok
}

// wellFormed returns ctx's principal if it has an ID, a tenant, a known kind,
// a role valid for that kind and a valid scope.
func wellFormed(ctx context.Context) (Principal, error) {
	p, ok := FromContext(ctx)
	if !ok || p.ID == "" || p.TenantID == "" || !p.Scope.valid() || !p.Role.Valid() {
		return Principal{}, ErrDenied
	}
	switch p.Kind {
	case Token:
	case User:
		if !p.Role.ForMembership() {
			return Principal{}, ErrDenied
		}
	default:
		return Principal{}, ErrDenied
	}
	return p, nil
}

// principal returns ctx's principal if it is well formed and has perm.
func principal(ctx context.Context, perm Permission) (Principal, error) {
	p, err := wellFormed(ctx)
	if err != nil || !p.Role.Can(perm) {
		return Principal{}, ErrDenied
	}
	return p, nil
}

// TenantID returns the tenant ctx's principal acts in, for the RLS tenant. A
// malformed principal gets no tenant.
func TenantID(ctx context.Context) (string, error) {
	p, err := wellFormed(ctx)
	if err != nil {
		return "", err
	}
	return p.TenantID, nil
}

// Require returns ErrDenied unless ctx's principal has perm for a resource of
// product (the resource's product ID, or "" for a tenant-wide resource). A
// principal scoped to some products may only act on resources of those
// products, never on tenant-wide ones. No principal is denied.
func Require(ctx context.Context, perm Permission, product string) error {
	p, err := principal(ctx, perm)
	if err != nil {
		return err
	}
	if !p.Scope.covers(product) {
		return ErrDenied
	}
	return nil
}

// Products is for list queries over product-owned resources (licenses,
// plans, ...): it returns all=true if ctx's principal has perm on every
// product, else the non-empty list of product IDs to filter by. Lists of
// tenant-wide resources (customers, webhooks) use Require(ctx, perm, "").
func Products(ctx context.Context, perm Permission) (all bool, ids []string, err error) {
	p, err := principal(ctx, perm)
	if err != nil {
		return false, nil, err
	}
	if p.Scope.All {
		return true, nil, nil
	}
	return false, p.Scope.Products, nil // FromContext copied it
}

// Grant is a role and scope held by a member or API token.
type Grant struct {
	Role  Role
	Scope Scope
}

// CanAssign checks that ctx's principal may change a member's (kind User) or
// API token's (kind Token) grant from from to to: from nil creates it, to nil
// removes it.
//
// from must be the current grant, read FOR UPDATE in the same transaction as
// the write, and creating must be a plain INSERT that fails if the member or
// token exists (never an upsert); otherwise an existing owner could be
// overwritten as if it were new.
//
// Rules: the principal is a user (API tokens can't manage access) with
// member:write or token:write and every product (scoped principals can't
// manage access); it may only give or take away a role whose permissions it
// has itself (so only owners touch owner), except that sdk tokens are always
// assignable; members can't get sdk; grants must be well formed.
func CanAssign(ctx context.Context, kind PrincipalKind, from, to *Grant) error {
	perm := MemberWrite
	switch kind {
	case User:
	case Token:
		perm = TokenWrite
	default:
		return ErrDenied
	}
	p, err := principal(ctx, perm)
	if err != nil || p.Kind != User || !p.Scope.All || (from == nil && to == nil) {
		return ErrDenied
	}
	for _, g := range []*Grant{from, to} {
		if g == nil {
			continue
		}
		if !g.Role.Valid() || !g.Scope.valid() || (kind == User && !g.Role.ForMembership()) {
			return ErrDenied
		}
		if g.Role != SDK && !g.Role.Within(p.Role) {
			return ErrDenied
		}
	}
	return nil
}

// Within reports whether every permission of r is also one of g's.
func (r Role) Within(g Role) bool {
	for _, perm := range permissions[r] {
		if !g.Can(perm) {
			return false
		}
	}
	return true
}
