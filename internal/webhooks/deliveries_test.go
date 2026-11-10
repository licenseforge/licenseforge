package webhooks

import (
	"context"
	"errors"
	"testing"
	"time"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// The delivery log: newest first, paged, to viewers; another tenant's or
// a product-scoped caller's request is not found.
func TestDeliveries(t *testing.T) {
	f := setupDispatch(t)
	c := f.endpoint(t, "license.issued")
	f.record(t, f.a, "license.issue", auditevent.OutcomeSuccess, issueDetails)
	f.recv.status = 500
	f.once(t)
	f.platformExec(t, `UPDATE webhook_cursors SET next_attempt_at = now() WHERE endpoint_id = $1`, c.ID)
	f.recv.status = 204
	f.once(t)
	viewer := f.as(f.a, f.viewer, authz.Viewer)
	all, err := f.s.Deliveries(viewer, c.ID, 10, time.Time{}, "")
	if err != nil || len(all) != 2 || !all[0].Success || all[0].Attempt != 2 || all[1].Success || all[1].Category != "http" || *all[1].StatusCode != 500 {
		t.Fatalf("Deliveries = %+v, %v", all, err)
	}
	page, err := f.s.Deliveries(viewer, c.ID, 1, all[0].AttemptedAt, all[0].ID)
	if err != nil || len(page) != 1 || page[0].ID != all[1].ID {
		t.Errorf("second page %+v, %v", page, err)
	}
	if _, err := f.s.Deliveries(f.as(f.b, f.ownerB, authz.Owner), c.ID, 10, time.Time{}, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("another tenant: %v", err)
	}
	scoped := authz.WithPrincipal(context.Background(), authz.Principal{Kind: authz.Token, ID: ids.New("tok"), TenantID: f.a, Role: authz.Admin,
		Scope: authz.Scope{Products: []string{ids.New("prd")}}})
	if _, err := f.s.Deliveries(scoped, c.ID, 10, time.Time{}, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("product-scoped: %v", err)
	}
}
