package activations

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// An activation inside the caller's transaction (ActivateTx, as the
// idempotency store runs it) holds the tenant's audit lock and then
// share-locks the active key to sign. A key rotation (Promote) must not hold
// the key rows while waiting for that audit lock, or the two deadlock
// (40P01). Deterministic: the activation's transaction holds the audit lock
// until Promote waits on it, then activates and signs.
func TestActivateTxDoesNotDeadlockWithPromote(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	lic := f.issue(t, "pro")
	owner := authz.WithPrincipal(ctx, authz.Principal{Kind: authz.User, ID: "usr_owner", TenantID: f.a, Role: authz.Owner, Scope: authz.Scope{All: true}})
	pending, err := f.keys.Create(owner, f.a)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := sql.Open("pgx", env.AdminURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	promoted := make(chan error, 1)
	var lease Lease
	actErr := f.db.WithTenant(ctx, f.a, func(tx *ent.Tx) error {
		if err := audit.Lock(ctx, tx, f.a); err != nil { // where grant would hold it
			return err
		}
		go func() { promoted <- f.keys.Promote(owner, f.a, pending.ID) }()
		deadline := time.Now().Add(10 * time.Second)
		for { // until Promote waits on the audit lock
			var n int
			if err := admin.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid = l.database
				WHERE l.locktype = 'advisory' AND NOT l.granted AND d.datname = $1`, env.Name).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("Promote never waited on the audit lock")
			}
			time.Sleep(10 * time.Millisecond)
		}
		var err error
		lease, err = f.s.ActivateTx(ctx, tx, f.req(lic.Key, fp()))
		return err
	})
	promoteErr := <-promoted
	var pe *pgconn.PgError
	for name, err := range map[string]error{"ActivateTx": actErr, "Promote": promoteErr} {
		if errors.As(err, &pe) && pe.Code == "40P01" {
			t.Errorf("%s: deadlock: %v", name, err)
		} else if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if actErr == nil && lease.KID != f.kid {
		t.Errorf("lease signed with %s, want the key active before the rotation (%s)", lease.KID, f.kid)
	}
}
