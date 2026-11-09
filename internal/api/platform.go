package api

import (
	"context"
	"errors"
	"net/http"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/platform"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// platformAdmin is the caller of a platform route: platformSession admitted
// it (a platform admin, platform MFA policy met), a principal with no tenant.
func platformAdmin(ctx context.Context) (string, error) {
	p, ok := authz.FromContext(ctx)
	if !ok || p.Kind != authz.User || p.ID == "" || p.TenantID != "" {
		return "", errUnauthenticated // only reachable through platformSession
	}
	return p.ID, nil
}

func (s *server) ListPlatformTenants(ctx context.Context, req apigen.ListPlatformTenantsRequestObject) (apigen.ListPlatformTenantsResponseObject, error) {
	if _, err := platformAdmin(ctx); err != nil {
		return nil, err
	}
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "tnt")
	if err != nil {
		return nil, err
	}
	rows, err := s.Platform.Tenants(ctx, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListPlatformTenants200JSONResponse{Items: []apigen.PlatformTenant{}}
	for i, t := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, platformTenantView(t))
	}
	return page, nil
}

func (s *server) CreatePlatformTenant(ctx context.Context, req apigen.CreatePlatformTenantRequestObject) (apigen.CreatePlatformTenantResponseObject, error) {
	admin, err := platformAdmin(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	c, err := s.Platform.CreateTenant(ctx, platform.Actor{UserID: admin}, b.Slug, b.Name, b.OwnerEmail)
	if err != nil {
		return nil, err
	}
	return apigen.CreatePlatformTenant201JSONResponse(createdView(c)), nil
}

// ReinvitePlatformTenantOwner gives a tenant without an owner a new owner
// invitation (ADR-0042, amended).
func (s *server) ReinvitePlatformTenantOwner(ctx context.Context, req apigen.ReinvitePlatformTenantOwnerRequestObject) (apigen.ReinvitePlatformTenantOwnerResponseObject, error) {
	admin, err := platformAdmin(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.Platform.ReinviteOwner(ctx, platform.Actor{UserID: admin}, req.Id, req.Body.OwnerEmail)
	if err != nil {
		return nil, err
	}
	return apigen.ReinvitePlatformTenantOwner201JSONResponse(createdView(c)), nil
}

func createdView(c platform.Created) apigen.PlatformTenantCreated {
	out := apigen.PlatformTenantCreated{Tenant: platformTenantView(c.Tenant)}
	out.Invitation.Id, out.Invitation.Email, out.Invitation.Role = c.Invitation.ID, c.Invitation.Email, apigen.PlatformTenantCreatedInvitationRole("owner")
	out.Invitation.ExpiresAt, out.Invitation.Token = c.Invitation.ExpiresAt.UTC(), c.Token
	return out
}

func platformTenantView(t *ent.Tenant) apigen.PlatformTenant {
	return apigen.PlatformTenant{Id: t.ID, Slug: t.Slug, Name: t.Name, MfaPolicy: apigen.MfaPolicy(t.MfaPolicy), CreatedAt: t.CreatedAt.UTC()}
}

// platformProblem maps the platform service's refusals (ADR-0042).
func platformProblem(err error) *problem {
	var inv *platform.InvalidError
	switch {
	case errors.As(err, &inv) && inv.Conflict && inv.Field == "/": // the tenant's state, not a field
		return &problem{status: http.StatusConflict, code: "conflict", detail: inv.Message, err: err}
	case errors.As(err, &inv) && inv.Conflict:
		return &problem{status: http.StatusConflict, code: "conflict", detail: "A value is already taken.", fields: []fieldError{{inv.Field, inv.Message}}}
	case errors.As(err, &inv):
		return invalid(fieldError{inv.Field, inv.Message})
	case errors.Is(err, platform.ErrNotFound):
		return &problem{status: http.StatusNotFound, code: "not_found", detail: "No such tenant.", err: err}
	case errors.Is(err, platform.ErrNotAdmin):
		return &problem{status: http.StatusForbidden, code: "forbidden", detail: "Only platform admins can use the platform API.", err: err}
	}
	return nil
}
