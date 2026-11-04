package store

import (
	"context"

	"licenseforge.io/licenseforge/internal/store/ent"
)

// platformBootstrapLock serializes BootstrapPlatformAdmin across replicas.
const platformBootstrapLock = 0x4C46_5041_444D // "LFPADM"

// BootstrapPlatformAdmin makes userID the first platform admin, only while
// there is none (ADR-0003, ADR-0029): LICENSEFORGE_BOOTSTRAP_ADMIN can't
// re-grant the role after admins are removed. It reports whether it granted.
// Replicas starting together are serialized by an advisory lock, so at most
// one bootstrap admin is created. record runs in the same transaction (audit,
// platform chain).
func (d *DB) BootstrapPlatformAdmin(ctx context.Context, userID string, record func(*ent.Tx) error) (bool, error) {
	granted := false
	err := inTx(ctx, d.platform, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, platformBootstrapLock); err != nil {
			return err
		}
		n, err := tx.PlatformAdmin.Query().Count(ctx)
		if err != nil || n > 0 {
			return err
		}
		if _, err := tx.PlatformAdmin.Create().SetUserID(userID).Save(ctx); err != nil {
			return err
		}
		granted = true
		return record(tx)
	})
	return granted && err == nil, err
}
