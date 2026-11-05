package api

import (
	"context"
	"time"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
)

func (s *server) ListInvitations(ctx context.Context, req apigen.ListInvitationsRequestObject) (apigen.ListInvitationsResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "inv")
	if err != nil {
		return nil, err
	}
	rows, err := s.Invitations.List(ctx, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListInvitations200JSONResponse{Items: []apigen.Invitation{}}
	for i, row := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, invitationView(row))
	}
	return page, nil
}

func (s *server) CreateInvitation(ctx context.Context, req apigen.CreateInvitationRequestObject) (apigen.CreateInvitationResponseObject, error) {
	b := req.Body
	scope := authz.Scope{All: b.AllProducts}
	if b.ProductIds != nil {
		scope.Products = *b.ProductIds
	}
	c, err := s.Invitations.Create(ctx, b.Email, authz.Role(b.Role), scope)
	if err != nil {
		return nil, err
	}
	v := invitationView(c.Row)
	return apigen.CreateInvitation201JSONResponse{Id: v.Id, Email: v.Email, Role: v.Role, AllProducts: v.AllProducts,
		ProductIds: v.ProductIds, Status: apigen.InvitationCreatedStatus(v.Status), InvitedBy: v.InvitedBy, CreatedAt: v.CreatedAt, ExpiresAt: v.ExpiresAt,
		AcceptedAt: v.AcceptedAt, AcceptedBy: v.AcceptedBy, RevokedAt: v.RevokedAt, Token: c.Token}, nil
}

func (s *server) RevokeInvitation(ctx context.Context, req apigen.RevokeInvitationRequestObject) (apigen.RevokeInvitationResponseObject, error) {
	row, err := s.Invitations.Revoke(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.RevokeInvitation200JSONResponse(invitationView(row)), nil
}

// AcceptInvitation is a user route (userRoutes): the principal is the
// signed-in user, with no tenant.
func (s *server) AcceptInvitation(ctx context.Context, req apigen.AcceptInvitationRequestObject) (apigen.AcceptInvitationResponseObject, error) {
	p, ok := authz.FromContext(ctx)
	if !ok || p.Kind != authz.User || p.ID == "" || p.TenantID != "" {
		return nil, errUnauthenticated // only reachable through userRoutes
	}
	m, err := s.Invitations.Accept(ctx, p.ID, req.Body.Token)
	if err != nil {
		return nil, err
	}
	return apigen.AcceptInvitation200JSONResponse{MembershipId: m.ID, TenantId: m.TenantID, Role: apigen.MemberRole(m.Role), AllProducts: m.ScopeAll}, nil
}

// ListMyTenants is a user route (userRoutes): the signed-in user's own
// memberships, for the tenant switcher.
func (s *server) ListMyTenants(ctx context.Context, _ apigen.ListMyTenantsRequestObject) (apigen.ListMyTenantsResponseObject, error) {
	p, ok := authz.FromContext(ctx)
	if !ok || p.Kind != authz.User || p.ID == "" || p.TenantID != "" {
		return nil, errUnauthenticated // only reachable through userRoutes
	}
	ms, err := s.Identity.Memberships(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	page := apigen.ListMyTenants200JSONResponse{Items: []apigen.MyTenant{}}
	for _, m := range ms {
		page.Items = append(page.Items, apigen.MyTenant{
			TenantId: m.TenantID, Slug: m.TenantSlug, Name: m.TenantName, Role: apigen.MemberRole(m.Role),
			AllProducts: m.ScopeAll, ProductIds: append([]string{}, m.Products...),
			MfaPolicy: apigen.MfaPolicy(m.MFAPolicy), Accessible: p.Assurance.Meets(m.MFAPolicy),
		})
	}
	return page, nil
}

func invitationView(i *ent.Invitation) apigen.Invitation {
	status := apigen.InvitationStatusPending
	switch {
	case i.AcceptedAt != nil:
		status = apigen.InvitationStatusAccepted
	case i.RevokedAt != nil:
		status = apigen.InvitationStatusRevoked
	case !i.ExpiresAt.After(time.Now()):
		status = apigen.InvitationStatusExpired
	}
	utc := func(t *time.Time) *time.Time {
		if t == nil {
			return nil
		}
		u := t.UTC()
		return &u
	}
	v := apigen.Invitation{Id: i.ID, Email: i.Email, Role: apigen.MemberRole(i.Role), AllProducts: i.ScopeAll, ProductIds: []string{},
		Status: status, InvitedBy: i.InvitedBy, CreatedAt: i.CreatedAt.UTC(), ExpiresAt: i.ExpiresAt.UTC(),
		AcceptedAt: utc(i.AcceptedAt), AcceptedBy: i.AcceptedBy, RevokedAt: utc(i.RevokedAt)}
	for _, p := range i.Edges.Products {
		v.ProductIds = append(v.ProductIds, p.ProductID)
	}
	return v
}
