package audit

import (
	"context"
	"testing"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// Reads are recorded once per reader per window: a denied attempt doesn't
// count as a read, and an expired window records again.
func TestListRecordsReads(t *testing.T) {
	d := openDB(t)
	tn := newTenant(t, d)
	l := Log{DB: d}
	reads := func() int {
		t.Helper()
		var n int
		if err := d.WithTenant(context.Background(), tn, func(tx *ent.Tx) (err error) {
			n, err = tx.AuditEvent.Query().Where(auditevent.Action("audit_event.read"), auditevent.OutcomeEQ(auditevent.OutcomeSuccess)).Count(context.Background())
			return
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	p := authz.Principal{Kind: authz.User, ID: "usr_1", TenantID: tn, Role: authz.Viewer, Scope: authz.Scope{All: true}}
	if _, err := l.List(context.Background(), p, Page{Limit: 10}); err == nil {
		t.Fatal("viewer read the log")
	}
	p.Role = authz.Admin // the same user, promoted: the denied attempt wasn't a read
	for range 2 {
		if _, err := l.List(context.Background(), p, Page{Limit: 10}); err != nil {
			t.Fatal(err)
		}
	}
	if n := reads(); n != 1 {
		t.Fatalf("%d reads recorded, want 1", n)
	}
	defer func(w string) { readWindow = w }(readWindow)
	readWindow = "0 seconds"
	if _, err := l.List(context.Background(), p, Page{Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if n := reads(); n != 2 {
		t.Errorf("after the window: %d reads recorded, want 2", n)
	}
}
