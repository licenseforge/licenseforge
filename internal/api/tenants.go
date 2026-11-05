package api

import (
	"context"
	"encoding/json"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/authz"
)

func (s *server) UpdateTenant(ctx context.Context, req apigen.UpdateTenantRequestObject) (apigen.UpdateTenantResponseObject, error) {
	// Merge patch: absent stays; mfa_policy isn't nullable. The rights come
	// before the values (403 before 422).
	var raw map[string]json.RawMessage
	body, _ := ctx.Value(bodyKey{}).([]byte)
	_ = json.Unmarshal(body, &raw) // strictInput decoded it already
	var policy *authz.Assurance
	if v, ok := raw["mfa_policy"]; ok && string(v) == "null" {
		bad := authz.Assurance("null")
		policy = &bad // refused as invalid by the service, after the rights
	} else if req.Body.MfaPolicy != nil {
		p := authz.Assurance(*req.Body.MfaPolicy)
		policy = &p
	}
	c, err := s.Tenants.SetMFAPolicy(ctx, policy)
	if err != nil {
		return nil, err
	}
	t := c.Tenant
	return apigen.UpdateTenant200JSONResponse{Id: t.ID, Slug: t.Slug, Name: t.Name,
		MfaPolicy: apigen.MfaPolicy(t.MfaPolicy), ActiveApiTokens: c.ActiveTokens}, nil
}
