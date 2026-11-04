package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/members"
	"licenseforge.io/licenseforge/internal/store/ent"
)

func (s *server) ListMembers(ctx context.Context, req apigen.ListMembersRequestObject) (apigen.ListMembersResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "mem")
	if err != nil {
		return nil, err
	}
	ms, err := s.Members.List(ctx, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListMembers200JSONResponse{Items: []apigen.Member{}}
	for i, m := range ms {
		if i == limit {
			c := encodeCursor(ms[i-1].CreatedAt, ms[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, memberView(m))
	}
	return page, nil
}

func (s *server) UpdateMember(ctx context.Context, req apigen.UpdateMemberRequestObject) (apigen.UpdateMemberResponseObject, error) {
	// Merge patch: absent stays. None of these fields is nullable, so a null
	// becomes an invalid value, refused (422) after the lookup and rights.
	var raw map[string]json.RawMessage
	body, _ := ctx.Value(bodyKey{}).([]byte)
	_ = json.Unmarshal(body, &raw) // strictInput decoded it already
	null := func(k string) bool { v, ok := raw[k]; return ok && string(v) == "null" }
	b := req.Body
	var c members.Change
	if b.Role != nil || null("role") {
		r := authz.Role("")
		if b.Role != nil {
			r = authz.Role(*b.Role)
		}
		c.Role = &r
	}
	if b.AllProducts != nil || b.ProductIds != nil || null("all_products") || null("product_ids") {
		c.Scope = &authz.Scope{}
		if b.AllProducts != nil {
			c.Scope.All = *b.AllProducts
		}
		if b.ProductIds != nil {
			c.Scope.Products = *b.ProductIds
		}
	}
	m, err := s.Members.Update(ctx, req.Id, c)
	if err != nil {
		return nil, err
	}
	return apigen.UpdateMember200JSONResponse(memberView(m)), nil
}

func (s *server) RemoveMember(ctx context.Context, req apigen.RemoveMemberRequestObject) (apigen.RemoveMemberResponseObject, error) {
	revoke := req.Params.RevokeTokens == nil || *req.Params.RevokeTokens
	if _, err := s.Members.Remove(ctx, req.Id, revoke); err != nil {
		return nil, err
	}
	return apigen.RemoveMember204Response{}, nil
}

func memberView(m *ent.Membership) apigen.Member {
	v := apigen.Member{Id: m.ID, UserId: m.UserID, Role: apigen.MemberRole(m.Role), AllProducts: m.ScopeAll,
		ProductIds: []string{}, CreatedAt: m.CreatedAt.UTC()}
	if u := m.Edges.User; u != nil {
		v.Email, v.Name = u.Email, u.Name
	}
	for _, p := range m.Edges.Products {
		v.ProductIds = append(v.ProductIds, p.ProductID)
	}
	return v
}

// pageParams checks a list's limit and cursor (IDs with prefix).
func pageParams(l *int, c *string, prefix string) (limit int, at time.Time, after string, err error) {
	limit = defaultLimit
	if l != nil {
		limit = *l
	}
	if limit < 1 || limit > maxLimit {
		return 0, at, "", &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "limit must be 1 to 200."}
	}
	if c != nil {
		var ok bool
		if at, after, ok = decodeCursor(*c, prefix); !ok {
			return 0, at, "", &problem{status: http.StatusBadRequest, code: "invalid_cursor", detail: "Malformed cursor."}
		}
	}
	return limit, at, after, nil
}
