// Package authz is the tenant-scoped role model (ADR-0019): a fixed set of
// roles, each a fixed set of permissions, checked with one Require call per
// handler. Row-level security (ADR-0009) is the backstop behind it.
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
	TenantWrite  Permission = "tenant:write" // settings
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
	admin   = append(slices.Clone(manager), TenantWrite, CatalogWrite, MemberWrite, TokenWrite, WebhookWrite, AuditRead)
	owner   = append(slices.Clone(admin), TenantDelete, BillingWrite, KeyWrite)

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

// CanGrant reports whether a principal with role g may give role r to a
// member or API token, or change or remove a member or token that has r. Only
// owners grant or touch owner, so an admin can't escalate to owner or demote
// one.
func (g Role) CanGrant(r Role) bool {
	return g.Can(MemberWrite) && r.Valid() && (g == Owner || r != Owner)
}

// Can reports whether r grants p.
func (r Role) Can(p Permission) bool { return slices.Contains(permissions[r], p) }

// PrincipalKind says who is acting.
type PrincipalKind string

const (
	User  PrincipalKind = "user"
	Token PrincipalKind = "token"
)

// Principal is who is acting in one tenant, resolved from the session or API
// token after the membership check.
type Principal struct {
	Kind     PrincipalKind
	ID       string // user or token ID
	TenantID string
	Role     Role
	Products []string // product scope; empty means every product
}

type ctxKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the principal in ctx, if any.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Require returns ErrDenied unless ctx's principal has perm for a resource of
// product (the resource's product ID, or "" for a tenant-wide resource). A
// principal scoped to products may only act on resources of those products,
// never on tenant-wide ones. No principal is denied.
func Require(ctx context.Context, perm Permission, product string) error {
	p, ok := FromContext(ctx)
	if !ok || p.TenantID == "" || !p.Role.Can(perm) {
		return ErrDenied
	}
	if p.Kind == User && !p.Role.ForMembership() {
		return ErrDenied
	}
	if len(p.Products) > 0 && (product == "" || !slices.Contains(p.Products, product)) {
		return ErrDenied
	}
	return nil
}
