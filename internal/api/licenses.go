package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/idempotency"
	"licenseforge.io/licenseforge/internal/licenses"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/license"
	"licenseforge.io/licenseforge/internal/store/ids"
)

func principal(ctx context.Context) authz.Principal {
	p, _ := authz.FromContext(ctx)
	return p
}

func (s *server) ListLicenses(ctx context.Context, req apigen.ListLicensesRequestObject) (apigen.ListLicensesResponseObject, error) {
	q := req.Params
	limit, at, after, err := pageParams(q.Limit, q.Cursor, "lic")
	if err != nil {
		return nil, err
	}
	bad := func(what string) error {
		return &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "Malformed " + what + "."}
	}
	var f licenses.Filter
	if q.ProductId != nil {
		if f.ProductID = *q.ProductId; !ids.Valid("prd", f.ProductID) {
			return nil, bad("product_id")
		}
	}
	if q.CustomerId != nil {
		if f.CustomerID = *q.CustomerId; !ids.Valid("cus", f.CustomerID) {
			return nil, bad("customer_id")
		}
	}
	if q.Status != nil {
		if !q.Status.Valid() {
			return nil, bad("status")
		}
		f.Status = license.Status(*q.Status)
	}
	f.CreatedAfter, f.CreatedBefore = q.CreatedAfter, q.CreatedBefore
	rows, err := s.Licenses.List(ctx, principal(ctx), f, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	seats, err := s.seats(ctx, rows[:min(len(rows), limit)]...)
	if err != nil {
		return nil, err
	}
	page := apigen.ListLicenses200JSONResponse{Items: []apigen.License{}}
	for i, l := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, licenseView(l, seats[l.ID]))
	}
	return page, nil
}

// GetSummary answers exact counts for the dashboard overview. Lists carry no
// totals (ADR-0032); this resource is where counts live. License counts are
// in the caller's product scope; customers only for callers who see every
// product (absent otherwise, never a partial count).
func (s *server) GetSummary(ctx context.Context, _ apigen.GetSummaryRequestObject) (apigen.GetSummaryResponseObject, error) {
	byStatus, err := s.Licenses.Counts(ctx, principal(ctx))
	if err != nil {
		return nil, err
	}
	var out apigen.GetSummary200JSONResponse
	out.Licenses.Active = int64(byStatus[license.StatusActive])
	out.Licenses.Suspended = int64(byStatus[license.StatusSuspended])
	out.Licenses.Revoked = int64(byStatus[license.StatusRevoked])
	n, ok, err := s.Customers.CountActive(ctx)
	if err != nil {
		return nil, err
	}
	if ok {
		out.Customers = &struct {
			Active int64 `json:"active"`
		}{int64(n)}
	}
	return out, nil
}

func (s *server) GetLicense(ctx context.Context, req apigen.GetLicenseRequestObject) (apigen.GetLicenseResponseObject, error) {
	l, err := s.Licenses.Get(ctx, principal(ctx), req.Id)
	if err != nil {
		return nil, err
	}
	v, err := s.view(ctx, l)
	return apigen.GetLicense200JSONResponse(v), err
}

func (s *server) SuspendLicense(ctx context.Context, req apigen.SuspendLicenseRequestObject) (apigen.SuspendLicenseResponseObject, error) {
	c, err := s.Licenses.Suspend(ctx, principal(ctx), req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.SuspendLicense200JSONResponse(licenseView(c.License, c.ActiveActivations)), nil
}

func (s *server) ReinstateLicense(ctx context.Context, req apigen.ReinstateLicenseRequestObject) (apigen.ReinstateLicenseResponseObject, error) {
	c, err := s.Licenses.Reinstate(ctx, principal(ctx), req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.ReinstateLicense200JSONResponse(licenseView(c.License, c.ActiveActivations)), nil
}

func (s *server) RevokeLicense(ctx context.Context, req apigen.RevokeLicenseRequestObject) (apigen.RevokeLicenseResponseObject, error) {
	c, err := s.Licenses.Revoke(ctx, principal(ctx), req.Id)
	if err != nil {
		return nil, err
	}
	return apigen.RevokeLicense200JSONResponse(licenseView(c.License, c.ActiveActivations)), nil
}

// IssueLicense issues a license; with Idempotency-Key, at most once per key
// (internal/idempotency): the issue and its outcome, refusals included,
// commit together, and a retry gets the stored answer after the product and
// permission checks pass again.
func (s *server) IssueLicense(ctx context.Context, req apigen.IssueLicenseRequestObject) (apigen.IssueLicenseResponseObject, error) {
	p := principal(ctx)
	ir := issueRequest(req.Body)
	if req.Params.IdempotencyKey == nil {
		got, err := s.Licenses.Issue(ctx, p, ir)
		if err != nil {
			return nil, err
		}
		return apigen.IssueLicense201JSONResponse(issuedView(got)), nil
	}
	body, _ := ctx.Value(bodyKey{}).([]byte)
	ri, _ := ctx.Value(reqKey{}).(reqInfo)
	out, replayed, err := s.Idempotency.Do(ctx, idempotency.Request{TenantID: p.TenantID, Credential: p.ID, Key: *req.Params.IdempotencyKey,
		Operation: "IssueLicense", Body: body},
		func(ctx context.Context, tx *ent.Tx) error { return s.Licenses.RecheckIssue(ctx, tx, p, ir.ProductID) },
		func(ctx context.Context, tx *ent.Tx) (idempotency.Outcome, error) {
			got, err := s.Licenses.IssueTx(ctx, tx, p, ir)
			if err != nil {
				pr := mapErr(err)
				if pr.status >= 500 {
					return idempotency.Outcome{}, err // rolled back with the issue; the client may retry
				}
				s.Log.InfoContext(ctx, "api refusal", "request_id", ri.id, "status", pr.status, "code", pr.code, "err", err, "idempotent", true)
				return idempotency.Outcome{Status: pr.status, Body: pr.body(ri.id)}, nil
			}
			b, err := json.Marshal(issuedView(got))
			return idempotency.Outcome{Status: http.StatusCreated, Body: append(b, '\n')}, err
		})
	if err != nil {
		return nil, err
	}
	if replayed && out.Status == http.StatusCreated { // the key is shown again: audited, or not shown (ADR-0025)
		var lic struct {
			ID        string `json:"id"`
			ProductID string `json:"product_id"`
		}
		if err := json.Unmarshal(out.Body, &lic); err != nil {
			return nil, err
		}
		// RecordKeyReveal refuses malformed IDs (a 500: never an unaudited reveal).
		if err := s.Licenses.RecordKeyReveal(ctx, p, lic.ID, lic.ProductID); err != nil {
			return nil, err
		}
	}
	if out.Status >= 400 { // a replayed problem names this request, like X-Request-Id
		var m map[string]any
		if json.Unmarshal(out.Body, &m) == nil {
			m["request_id"] = ri.id
			if b, err := json.Marshal(m); err == nil {
				out.Body = append(b, '\n')
			}
		}
	}
	return outcome(out), nil
}

// outcome writes a stored or fresh idempotent outcome as it is.
type outcome idempotency.Outcome

func (o outcome) VisitIssueLicenseResponse(w http.ResponseWriter) error {
	ct := "application/json"
	if o.Status >= 400 {
		ct = "application/problem+json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(o.Status)
	_, err := w.Write(o.Body)
	return err
}

func issueRequest(b *apigen.IssueLicenseJSONRequestBody) licenses.IssueRequest {
	r := licenses.IssueRequest{ProductID: b.ProductId, PlanID: b.PlanId, CustomerID: b.CustomerId}
	if b.Type != nil {
		r.Type = license.Type(*b.Type)
	}
	if b.ExternalRefs != nil {
		r.ExternalRefs = *b.ExternalRefs
	}
	if b.Overrides != nil {
		r.Overrides = map[string]licenses.Override{}
		for k, o := range *b.Overrides {
			r.Overrides[k] = licenses.Override{Remove: o.Remove != nil && *o.Remove, Limit: o.Limit}
		}
	}
	return r
}

// seats counts the active activations of ls (activations.ActiveSeats).
func (s *server) seats(ctx context.Context, ls ...*ent.License) (map[string]int, error) {
	ids := make([]string, len(ls))
	for i, l := range ls {
		ids[i] = l.ID
	}
	return s.Activations.ActiveSeats(ctx, principal(ctx), ids...)
}

// view is l's License view, with its seats counted.
func (s *server) view(ctx context.Context, l *ent.License) (apigen.License, error) {
	seats, err := s.seats(ctx, l)
	if err != nil {
		return apigen.License{}, err
	}
	return licenseView(l, seats[l.ID]), nil
}

func licenseView(l *ent.License, seats int) apigen.License {
	utc := func(t *time.Time) *time.Time {
		if t == nil {
			return nil
		}
		u := t.UTC()
		return &u
	}
	v := apigen.License{Id: l.ID, ProductId: l.ProductID, PlanId: l.PlanID, PlanSlug: l.PlanSlug, CustomerId: l.CustomerID,
		Type: apigen.LicenseType(l.Type), Status: apigen.LicenseStatus(l.Status), KeyHint: l.KeyHint,
		ExpiryBasis: apigen.LicenseExpiryBasis(l.ExpiryBasis), ExpiresAt: utc(l.ExpiresAt), MaxActivations: l.MaxActivations, ActiveActivations: seats,
		ExternalRefs: l.ExternalRefs, IssuedAt: l.IssuedAt.UTC(), SuspendedAt: utc(l.SuspendedAt), RevokedAt: utc(l.RevokedAt),
		CreatedAt: l.CreatedAt.UTC()}
	v.Entitlements.Features, v.Entitlements.Limits = l.Entitlements.Features, l.Entitlements.Limits
	if v.Entitlements.Features == nil {
		v.Entitlements.Features = []string{}
	}
	if v.Entitlements.Limits == nil {
		v.Entitlements.Limits = map[string]int64{}
	}
	if v.ExternalRefs == nil {
		v.ExternalRefs = map[string]string{}
	}
	return v
}

func issuedView(i licenses.Issued) apigen.LicenseIssued {
	v := licenseView(i.License, 0) // new: no activations yet
	return apigen.LicenseIssued{Id: v.Id, ProductId: v.ProductId, PlanId: v.PlanId, PlanSlug: v.PlanSlug, CustomerId: v.CustomerId,
		Type: apigen.LicenseIssuedType(v.Type), Status: v.Status, KeyHint: v.KeyHint,
		ExpiryBasis: apigen.LicenseIssuedExpiryBasis(v.ExpiryBasis), ExpiresAt: v.ExpiresAt, MaxActivations: v.MaxActivations, ActiveActivations: v.ActiveActivations,
		Entitlements: v.Entitlements, ExternalRefs: v.ExternalRefs, IssuedAt: v.IssuedAt, SuspendedAt: v.SuspendedAt,
		RevokedAt: v.RevokedAt, CreatedAt: v.CreatedAt, Key: i.Key}
}

func (s *server) ListActivations(ctx context.Context, req apigen.ListActivationsRequestObject) (apigen.ListActivationsResponseObject, error) {
	limit, at, after, err := pageParams(req.Params.Limit, req.Params.Cursor, "act")
	if err != nil {
		return nil, err
	}
	rows, err := s.Activations.List(ctx, principal(ctx), req.Id, limit+1, at, after)
	if err != nil {
		return nil, err
	}
	page := apigen.ListActivations200JSONResponse{Items: []apigen.Activation{}}
	for i, a := range rows {
		if i == limit {
			c := encodeCursor(rows[i-1].CreatedAt, rows[i-1].ID)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, activationView(a))
	}
	return page, nil
}

func (s *server) DeactivateActivation(ctx context.Context, req apigen.DeactivateActivationRequestObject) (apigen.DeactivateActivationResponseObject, error) {
	a, err := s.Activations.DeactivateByID(ctx, principal(ctx), req.Id, req.ActivationId)
	if err != nil {
		return nil, err
	}
	return apigen.DeactivateActivation200JSONResponse(activationView(a)), nil
}

func activationView(a *ent.Activation) apigen.Activation {
	v := apigen.Activation{Id: a.ID, LicenseId: a.LicenseID, Fingerprint: a.Fingerprint, FpSource: apigen.ActivationFpSource(a.FpSource),
		Binding: apigen.ActivationBinding(a.Binding), Mode: apigen.ActivationMode(a.Mode), Hostname: a.Hostname,
		AppVersion: a.AppVersion, SdkVersion: a.SdkVersion, FirstSeenAt: a.FirstSeenAt.UTC(), LastSeenAt: a.LastSeenAt.UTC(),
		CreatedAt: a.CreatedAt.UTC()}
	if a.DeactivatedAt != nil {
		t := a.DeactivatedAt.UTC()
		v.DeactivatedAt = &t
	}
	return v
}
