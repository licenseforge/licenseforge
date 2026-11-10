package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"licenseforge.io/licenseforge/internal/activations"
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
	c, ok, err := s.Customers.Counts(ctx)
	if err != nil {
		return nil, err
	}
	if ok {
		out.Customers = &struct {
			Active        int64     `json:"active"`
			MonthStart    time.Time `json:"month_start"`
			SeenThisMonth int64     `json:"seen_this_month"`
		}{int64(c.Active), c.MonthStart, int64(c.SeenThisMonth)}
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

func (s *server) SetLicenseUpdatesUntil(ctx context.Context, req apigen.SetLicenseUpdatesUntilRequestObject) (apigen.SetLicenseUpdatesUntilResponseObject, error) {
	// Required, nullable: absent must not read as null (every build covered).
	if req.Body.UpdatesUntil == nil && len(nulls(ctx, "updates_until")) == 0 {
		return nil, invalid(fieldError{"/updates_until", "required: a date-time, or null for every build"})
	}
	c, err := s.Licenses.SetUpdatesUntil(ctx, principal(ctx), req.Id, req.Body.UpdatesUntil)
	if err != nil {
		return nil, err
	}
	return apigen.SetLicenseUpdatesUntil200JSONResponse(licenseView(c.License, c.ActiveActivations)), nil
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
	// null isn't "every build" here (it is on updates-until): refuse it rather
	// than silently use the plan's term.
	if len(nulls(ctx, "updates_until")) > 0 {
		return nil, invalid(fieldError{"/updates_until", "a date-time; omit it for the plan's term"})
	}
	ir := issueRequest(req.Body)
	if req.Params.IdempotencyKey == nil {
		got, err := s.Licenses.Issue(ctx, p, ir)
		if err != nil {
			return nil, err
		}
		return apigen.IssueLicense201JSONResponse(issuedView(got)), nil
	}
	out, replayed, err := s.idempotent(ctx, p, *req.Params.IdempotencyKey, "IssueLicense",
		func(ctx context.Context, tx *ent.Tx) error { return s.Licenses.RecheckIssue(ctx, tx, p, ir.ProductID) },
		func(ctx context.Context, tx *ent.Tx) (any, error) {
			got, err := s.Licenses.IssueTx(ctx, tx, p, ir)
			if err != nil {
				return nil, err
			}
			return issuedView(got), nil
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
	return outcome(out), nil
}

// idempotent runs a create under Idempotency-Key key for p (internal/
// idempotency): run's result or refusal commits with its outcome (201 with
// run's view, or the problem a refusal maps to), and a retry gets the
// stored answer once recheck passes again. Errors that map to 5xx roll
// back. A replayed problem names this request, like X-Request-Id.
func (s *server) idempotent(ctx context.Context, p authz.Principal, key, op string, recheck func(context.Context, *ent.Tx) error,
	run func(context.Context, *ent.Tx) (any, error)) (idempotency.Outcome, bool, error) {
	body, _ := ctx.Value(bodyKey{}).([]byte)
	ri, _ := ctx.Value(reqKey{}).(reqInfo)
	out, replayed, err := s.Idempotency.Do(ctx, idempotency.Request{TenantID: p.TenantID, Credential: p.ID, Key: key, Operation: op, Body: body},
		recheck, func(ctx context.Context, tx *ent.Tx) (idempotency.Outcome, error) {
			view, err := run(ctx, tx)
			if err != nil {
				pr := mapErr(err)
				if pr.status >= 500 {
					return idempotency.Outcome{}, err // rolled back; the client may retry
				}
				s.Log.InfoContext(ctx, "api refusal", "request_id", ri.id, "status", pr.status, "code", pr.code, "err", err, "idempotent", true)
				return idempotency.Outcome{Status: pr.status, Body: pr.body(ri.id)}, nil
			}
			b, err := json.Marshal(view)
			return idempotency.Outcome{Status: http.StatusCreated, Body: append(b, '\n')}, err
		})
	if err == nil && out.Status >= 400 {
		var m map[string]any
		if json.Unmarshal(out.Body, &m) == nil {
			m["request_id"] = ri.id
			if b, err := json.Marshal(m); err == nil {
				out.Body = append(b, '\n')
			}
		}
	}
	return out, replayed, err
}

// CreateOfflineActivation answers an offline activation request with a
// license file bound to that machine (ADR-0043); idempotent with
// Idempotency-Key, like IssueLicense. A replay isn't audited again: it
// re-delivers the file recorded at issue, to the same credential, after
// RecheckOffline (license still issuable) and OfflineFileCurrent (the
// file still the seat's current one).
func (s *server) CreateOfflineActivation(ctx context.Context, req apigen.CreateOfflineActivationRequestObject) (apigen.CreateOfflineActivationResponseObject, error) {
	p := principal(ctx)
	text := req.Body.Request
	if req.Params.IdempotencyKey == nil {
		l, err := s.Activations.Offline(ctx, p, text)
		if err != nil {
			return nil, err
		}
		v, err := offlineView(l)
		if err != nil {
			return nil, err
		}
		return apigen.CreateOfflineActivation201JSONResponse(v), nil
	}
	out, replayed, err := s.idempotent(ctx, p, *req.Params.IdempotencyKey, "CreateOfflineActivation",
		func(ctx context.Context, tx *ent.Tx) error { return s.Activations.RecheckOffline(ctx, tx, p, text) },
		func(ctx context.Context, tx *ent.Tx) (any, error) {
			l, err := s.Activations.OfflineTx(ctx, tx, p, text)
			if err != nil {
				return nil, err
			}
			return offlineView(l)
		})
	if err != nil {
		return nil, err
	}
	if replayed && out.Status == http.StatusCreated {
		var v apigen.OfflineActivation
		if err := json.Unmarshal(out.Body, &v); err != nil {
			return nil, err
		}
		if err := s.Activations.OfflineFileCurrent(ctx, p, v.ActivationId, v.FileSha256); err != nil {
			return nil, err // returned or renewed since: the stored file isn't handed out
		}
	}
	return outcome(out), nil
}

func offlineView(l activations.Lease) (apigen.OfflineActivation, error) {
	return apigen.OfflineActivation{LicenseFile: l.File, ActivationId: l.ActivationID, Kid: l.KID, FileSha256: l.FileSHA256, ExpiresAt: l.Claims.Expires}, nil
}

func (o outcome) VisitCreateOfflineActivationResponse(w http.ResponseWriter) error {
	return o.VisitIssueLicenseResponse(w)
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
	r := licenses.IssueRequest{ProductID: b.ProductId, PlanID: b.PlanId, CustomerID: b.CustomerId, UpdatesUntil: b.UpdatesUntil}
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
		ExpiryBasis: apigen.LicenseExpiryBasis(l.ExpiryBasis), ExpiresAt: utc(l.ExpiresAt), UpdatesUntil: utc(l.UpdatesUntil), MaxActivations: l.MaxActivations, ActiveActivations: seats,
		MaxRehosts: l.MaxRehosts, RehostCount: l.RehostCount,
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
		ExpiryBasis: apigen.LicenseIssuedExpiryBasis(v.ExpiryBasis), ExpiresAt: v.ExpiresAt, UpdatesUntil: v.UpdatesUntil, MaxActivations: v.MaxActivations, ActiveActivations: v.ActiveActivations,
		MaxRehosts: v.MaxRehosts, RehostCount: v.RehostCount, Entitlements: v.Entitlements, ExternalRefs: v.ExternalRefs, IssuedAt: v.IssuedAt, SuspendedAt: v.SuspendedAt,
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

// ReturnOfflineSeat frees an offline seat on a deactivation receipt
// (ADR-0043).
func (s *server) ReturnOfflineSeat(ctx context.Context, req apigen.ReturnOfflineSeatRequestObject) (apigen.ReturnOfflineSeatResponseObject, error) {
	a, err := s.Activations.Return(ctx, principal(ctx), req.Body.Receipt)
	if err != nil {
		return nil, err
	}
	return apigen.ReturnOfflineSeat200JSONResponse(activationView(a)), nil
}

func (s *server) DeactivateActivation(ctx context.Context, req apigen.DeactivateActivationRequestObject) (apigen.DeactivateActivationResponseObject, error) {
	a, err := s.Activations.DeactivateByID(ctx, principal(ctx), req.Id, req.ActivationId)
	if err != nil {
		return nil, err
	}
	return apigen.DeactivateActivation200JSONResponse(activationView(a)), nil
}

func (s *server) ResetRehosts(ctx context.Context, req apigen.ResetRehostsRequestObject) (apigen.ResetRehostsResponseObject, error) {
	l, err := s.Activations.ResetRehosts(ctx, principal(ctx), req.Id)
	if err != nil {
		return nil, err
	}
	seats, err := s.Activations.ActiveSeats(ctx, principal(ctx), l.ID)
	if err != nil {
		return nil, err
	}
	return apigen.ResetRehosts200JSONResponse(licenseView(l, seats[l.ID])), nil
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
