package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/apitokens"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// Handlers use the principal's tenant (authz invariant), never the path's.

func (s *server) ListApiTokens(ctx context.Context, req apigen.ListApiTokensRequestObject) (apigen.ListApiTokensResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "tok")
	if err != nil {
		return nil, err
	}
	rows, err := s.Tokens.List(ctx, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListApiTokens200JSONResponse{Items: []apigen.ApiToken{}}
	for i, row := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, view(row, nil))
	}
	return page, nil
}

func (s *server) CreateApiToken(ctx context.Context, req apigen.CreateApiTokenRequestObject) (apigen.CreateApiTokenResponseObject, error) {
	// Whether the caller may create tokens at all comes before validating
	// the values (403 before 422); the role cap needs the input.
	if err := authz.CanAssign(ctx, authz.Token, nil, &authz.Grant{Role: authz.SDK, Scope: authz.Scope{All: true}}); err != nil {
		return nil, err
	}
	b := req.Body
	var products []string
	if b.ProductIds != nil {
		products = *b.ProductIds
	}
	ttl := apitokens.DefaultTTL
	var bad []fieldError
	if apitokens.ValidName(b.Name) != nil {
		bad = append(bad, fieldError{"/name", "must be 1 to 200 bytes of printable characters"})
	}
	if !authz.Role(b.Role).Valid() {
		bad = append(bad, fieldError{"/role", "unknown role"})
	}
	if b.AllProducts == (len(products) > 0) {
		bad = append(bad, fieldError{"/product_ids", "give product IDs exactly when all_products is false"})
	}
	if b.TtlSeconds != nil {
		if sec := *b.TtlSeconds; sec < int(apitokens.MinTTL/time.Second) || sec > int(apitokens.MaxTTL/time.Second) {
			bad = append(bad, fieldError{"/ttl_seconds", "must be 60 to 31536000"})
		} else {
			ttl = time.Duration(sec) * time.Second
		}
	}
	if bad != nil {
		return nil, invalid(bad...)
	}
	c, err := s.Tokens.Create(ctx, b.Name, authz.Role(b.Role), authz.Scope{All: b.AllProducts, Products: products}, ttl)
	if errors.Is(err, apitokens.ErrInvalid) { // the rest: malformed, repeated or unknown products
		return nil, invalid(fieldError{"/product_ids", "must be distinct products of this tenant"})
	}
	if err != nil {
		return nil, err
	}
	v := view(c.Row, products)
	return apigen.CreateApiToken201JSONResponse{
		AllProducts: v.AllProducts, CreatedAt: v.CreatedAt, CreatedBy: v.CreatedBy, Display: v.Display, ExpiresAt: v.ExpiresAt,
		Id: v.Id, LastUsedAt: v.LastUsedAt, Name: v.Name, ProductIds: v.ProductIds, RevokedAt: v.RevokedAt, Role: v.Role,
		Token: c.Token,
	}, nil
}

func (s *server) RevokeApiToken(ctx context.Context, req apigen.RevokeApiTokenRequestObject) (apigen.RevokeApiTokenResponseObject, error) {
	row, err := s.Tokens.Revoke(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.RevokeApiToken200JSONResponse(view(row, nil)), nil
}

func invalid(f ...fieldError) *problem {
	return &problem{status: http.StatusUnprocessableEntity, code: "validation_failed", detail: "Some fields are invalid.", fields: f}
}

// view is the API form of a token: never its hash. products overrides the
// loaded edges (a just-created row has none loaded).
func view(t *ent.APIToken, products []string) apigen.ApiToken {
	if products == nil {
		for _, p := range t.Edges.Products {
			products = append(products, p.ProductID)
		}
	}
	utc := func(t *time.Time) *time.Time {
		if t == nil {
			return nil
		}
		u := t.UTC()
		return &u
	}
	return apigen.ApiToken{
		Id: t.ID, Name: t.Name, Role: apigen.Role(t.Role), AllProducts: t.ScopeAll, ProductIds: append([]string{}, products...),
		Display: t.Display, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt.UTC(), ExpiresAt: t.ExpiresAt.UTC(),
		LastUsedAt: utc(t.LastUsedAt), RevokedAt: utc(t.RevokedAt),
	}
}

// A cursor is only a position: created_at (µs) and ID, base64url. Every
// page re-applies tenant and scope from the request (ADR-0032).
func encodeCursor(at time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(at.UnixMicro(), 10) + "." + id))
}

func decodeCursor(c, prefix string) (time.Time, string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	us, id, ok := strings.Cut(string(raw), ".")
	n, perr := strconv.ParseInt(us, 10, 64)
	if err != nil || !ok || perr != nil || !ids.Valid(prefix, id) {
		return time.Time{}, "", false
	}
	return time.UnixMicro(n), id, true
}
