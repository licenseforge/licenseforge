package api

import (
	"context"
	"net/http"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/catalog"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/feature"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func (s *server) ListFeatures(ctx context.Context, req apigen.ListFeaturesRequestObject) (apigen.ListFeaturesResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "ftr")
	if err != nil {
		return nil, err
	}
	var product string
	if req.Params.ProductId != nil {
		if product = *req.Params.ProductId; !ids.Valid("prd", product) {
			return nil, &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "Malformed product_id."}
		}
	}
	rows, err := s.Features.List(ctx, product, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListFeatures200JSONResponse{Items: []apigen.Feature{}}
	for i, f := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, featureView(f))
	}
	return page, nil
}

func (s *server) CreateFeature(ctx context.Context, req apigen.CreateFeatureRequestObject) (apigen.CreateFeatureResponseObject, error) {
	b := req.Body
	f, err := s.Features.Create(ctx, catalog.FeatureInput{ProductID: b.ProductId, Key: b.Key, Name: b.Name,
		Type: feature.Type(b.Type), Description: b.Description, Unit: b.Unit})
	if err != nil {
		return nil, err
	}
	return apigen.CreateFeature201JSONResponse(featureView(f)), nil
}

func (s *server) GetFeature(ctx context.Context, req apigen.GetFeatureRequestObject) (apigen.GetFeatureResponseObject, error) {
	f, err := s.Features.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.GetFeature200JSONResponse(featureView(f)), nil
}

func (s *server) UpdateFeature(ctx context.Context, req apigen.UpdateFeatureRequestObject) (apigen.UpdateFeatureResponseObject, error) {
	b := req.Body
	f, err := s.Features.Update(ctx, req.Id, catalog.FeaturePatch{Name: b.Name, Description: b.Description, Unit: b.Unit,
		Null: nulls(ctx, "name", "description", "unit")})
	if err != nil {
		return nil, err
	}
	return apigen.UpdateFeature200JSONResponse(featureView(f)), nil
}

func (s *server) ArchiveFeature(ctx context.Context, req apigen.ArchiveFeatureRequestObject) (apigen.ArchiveFeatureResponseObject, error) {
	f, err := s.Features.Archive(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.ArchiveFeature200JSONResponse(featureView(f)), nil
}

func featureView(f *ent.Feature) apigen.Feature {
	v := apigen.Feature{Id: f.ID, ProductId: f.ProductID, Key: f.Key, Name: f.Name, Description: f.Description,
		Type: apigen.FeatureType(f.Type), Unit: f.Unit, CreatedAt: f.CreatedAt.UTC()}
	if f.ArchivedAt != nil {
		t := f.ArchivedAt.UTC()
		v.ArchivedAt = &t
	}
	return v
}
