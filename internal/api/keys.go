package api

import (
	"context"
	"encoding/base64"
	"time"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// The signing keys (ADR-0026) of the path's tenant: internal/signing
// authorizes (key:read to list, key:write to change) and audits changes.

func (s *server) ListSigningKeys(ctx context.Context, req apigen.ListSigningKeysRequestObject) (apigen.ListSigningKeysResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "sk")
	if err != nil {
		return nil, err
	}
	rows, err := s.SigningKeys.List(ctx, principal(ctx).TenantID, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListSigningKeys200JSONResponse{Items: []apigen.SigningKey{}}
	for i, k := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, keyView(k))
	}
	return page, nil
}

func (s *server) CreateSigningKey(ctx context.Context, _ apigen.CreateSigningKeyRequestObject) (apigen.CreateSigningKeyResponseObject, error) {
	k, err := s.SigningKeys.Create(ctx, principal(ctx).TenantID)
	if err != nil {
		return nil, err
	}
	return apigen.CreateSigningKey201JSONResponse(keyView(k)), nil
}

// Promote and discard: internal/signing looks the key up first (ADR-0032
// step 4: a missing key is 404, before key:write's 403) and audits every
// attempt.

func (s *server) PromoteSigningKey(ctx context.Context, req apigen.PromoteSigningKeyRequestObject) (apigen.PromoteSigningKeyResponseObject, error) {
	k, err := s.SigningKeys.PromoteKey(ctx, principal(ctx).TenantID, req.Kid)
	if err != nil {
		return nil, err
	}
	return apigen.PromoteSigningKey200JSONResponse(keyView(k)), nil
}

func (s *server) DiscardSigningKey(ctx context.Context, req apigen.DiscardSigningKeyRequestObject) (apigen.DiscardSigningKeyResponseObject, error) {
	k, err := s.SigningKeys.DiscardKey(ctx, principal(ctx).TenantID, req.Kid)
	if err != nil {
		return nil, err
	}
	return apigen.DiscardSigningKey200JSONResponse(keyView(k)), nil
}

// keyView is the public part only: never the private key ciphertext.
func keyView(k *ent.SigningKey) apigen.SigningKey {
	utc := func(t *time.Time) *time.Time {
		if t == nil {
			return nil
		}
		u := t.UTC()
		return &u
	}
	return apigen.SigningKey{Kid: k.ID, Alg: apigen.SigningKeyAlg(k.Alg), PublicKey: base64.RawURLEncoding.EncodeToString(k.PublicKey),
		Status: apigen.SigningKeyStatus(k.Status), CreatedAt: k.CreatedAt.UTC(), ActivatedAt: utc(k.ActivatedAt), RetiredAt: utc(k.RetiredAt)}
}
