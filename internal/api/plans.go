package api

import (
	"context"
	"net/http"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/catalog"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/plan"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func (s *server) ListPlans(ctx context.Context, req apigen.ListPlansRequestObject) (apigen.ListPlansResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "pln")
	if err != nil {
		return nil, err
	}
	var product string
	if req.Params.ProductId != nil {
		if product = *req.Params.ProductId; !ids.Valid("prd", product) {
			return nil, &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "Malformed product_id."}
		}
	}
	rows, err := s.Plans.List(ctx, product, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListPlans200JSONResponse{Items: []apigen.Plan{}}
	for i, p := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, planView(p))
	}
	return page, nil
}

func (s *server) CreatePlan(ctx context.Context, req apigen.CreatePlanRequestObject) (apigen.CreatePlanResponseObject, error) {
	b := req.Body
	// Defaults (spec: PlanCreate).
	t := catalog.Terms{ExpiryBasis: plan.ExpiryBasisFromIssue, BindType: plan.BindTypeMachine, LeaseSeconds: 7 * 24 * 3600,
		DurationMonths: b.DurationMonths, DurationSeconds: b.DurationSeconds, MaxActivations: b.MaxActivations,
		MaxRehosts: b.MaxRehosts, MaxOfflineSeconds: b.MaxOfflineSeconds}
	if b.ExpiryBasis != nil {
		t.ExpiryBasis = plan.ExpiryBasis(*b.ExpiryBasis)
	}
	if b.BindType != nil {
		t.BindType = plan.BindType(*b.BindType)
	}
	if b.OfflineAllowed != nil {
		t.OfflineAllowed = *b.OfflineAllowed
	}
	if b.LeaseSeconds != nil {
		t.LeaseSeconds = *b.LeaseSeconds
	}
	if b.GraceSeconds != nil {
		t.GraceSeconds = *b.GraceSeconds
	}
	p, err := s.Plans.Create(ctx, catalog.PlanInput{ProductID: b.ProductId, Slug: b.Slug, Name: b.Name, Terms: t})
	if err != nil {
		return nil, err
	}
	return apigen.CreatePlan201JSONResponse(planView(p)), nil
}

func (s *server) GetPlan(ctx context.Context, req apigen.GetPlanRequestObject) (apigen.GetPlanResponseObject, error) {
	p, err := s.Plans.Get(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.GetPlan200JSONResponse(planView(p)), nil
}

func (s *server) UpdatePlan(ctx context.Context, req apigen.UpdatePlanRequestObject) (apigen.UpdatePlanResponseObject, error) {
	b := req.Body
	patch := catalog.PlanPatch{Name: b.Name, DurationMonths: b.DurationMonths, DurationSeconds: b.DurationSeconds,
		MaxActivations: b.MaxActivations, MaxRehosts: b.MaxRehosts, MaxOfflineSeconds: b.MaxOfflineSeconds,
		OfflineAllowed: b.OfflineAllowed, LeaseSeconds: b.LeaseSeconds, GraceSeconds: b.GraceSeconds,
		Null: nulls(ctx, "name", "duration_months", "duration_seconds", "expiry_basis", "max_activations", "max_rehosts",
			"offline_allowed", "lease_seconds", "max_offline_seconds", "grace_seconds")}
	if b.ExpiryBasis != nil {
		e := plan.ExpiryBasis(*b.ExpiryBasis)
		patch.ExpiryBasis = &e
	}
	p, err := s.Plans.Update(ctx, req.Id, patch)
	if err != nil {
		return nil, err
	}
	return apigen.UpdatePlan200JSONResponse(planView(p)), nil
}

func (s *server) ArchivePlan(ctx context.Context, req apigen.ArchivePlanRequestObject) (apigen.ArchivePlanResponseObject, error) {
	p, err := s.Plans.Archive(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.ArchivePlan200JSONResponse(planView(p)), nil
}

func planView(p *ent.Plan) apigen.Plan {
	v := apigen.Plan{Id: p.ID, ProductId: p.ProductID, Slug: p.Slug, Name: p.Name,
		DurationMonths: p.DurationMonths, DurationSeconds: p.DurationSeconds, ExpiryBasis: apigen.PlanExpiryBasis(p.ExpiryBasis),
		MaxActivations: p.MaxActivations, MaxRehosts: p.MaxRehosts, BindType: apigen.PlanBindType(p.BindType),
		OfflineAllowed: p.OfflineAllowed, LeaseSeconds: p.LeaseSeconds, MaxOfflineSeconds: p.MaxOfflineSeconds,
		GraceSeconds: p.GraceSeconds, CreatedAt: p.CreatedAt.UTC()}
	if p.ArchivedAt != nil {
		t := p.ArchivedAt.UTC()
		v.ArchivedAt = &t
	}
	return v
}

func (s *server) GetPlanFeatures(ctx context.Context, req apigen.GetPlanFeaturesRequestObject) (apigen.GetPlanFeaturesResponseObject, error) {
	g, err := s.Plans.Features(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.GetPlanFeatures200JSONResponse(g), nil
}

func (s *server) UpdatePlanFeatures(ctx context.Context, req apigen.UpdatePlanFeaturesRequestObject) (apigen.UpdatePlanFeaturesResponseObject, error) {
	g, err := s.Plans.PatchFeatures(ctx, req.Id, *req.Body)
	if err != nil {
		return nil, err
	}
	return apigen.UpdatePlanFeatures200JSONResponse(g), nil
}
