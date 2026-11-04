package store

import (
	"context"
	"errors"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/platformadmin"
	"licenseforge.io/licenseforge/internal/store/ent/user"
)

// platformAdminLock serializes changes to the platform admin set across
// replicas (bootstrap, grant, removal).
const platformAdminLock = 0x4C46_5041_444D // "LFPADM"

// ErrLastPlatformAdmin means the removal would leave no platform admin
// (ADR-0031): hand over first.
var ErrLastPlatformAdmin = errors.New("store: can't remove the last platform admin")

// withAdminLock runs fn on the platform pool holding the admin-set lock.
func (d *DB) withAdminLock(ctx context.Context, fn func(*ent.Tx) error) error {
	return inTx(ctx, d.platform, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, platformAdminLock); err != nil {
			return err
		}
		return fn(tx)
	})
}

// BootstrapPlatformAdmin makes userID the first platform admin, only while
// there is none (ADR-0003, ADR-0029, ADR-0031), and never a disabled or
// unknown user. It reports whether it granted. Replicas starting together are
// serialized, so at most one bootstrap admin is created. record runs in the
// same transaction (audit, platform chain).
func (d *DB) BootstrapPlatformAdmin(ctx context.Context, userID string, record func(*ent.Tx) error) (bool, error) {
	granted := false
	err := d.withAdminLock(ctx, func(tx *ent.Tx) error {
		n, err := tx.PlatformAdmin.Query().Count(ctx)
		if err != nil || n > 0 {
			return err
		}
		ok, err := tx.User.Query().Where(user.ID(userID), user.DisabledAtIsNil()).Exist(ctx)
		if err != nil || !ok {
			return err
		}
		if _, err := tx.PlatformAdmin.Create().SetUserID(userID).SetBootstrap(true).Save(ctx); err != nil {
			return err
		}
		granted = true
		return record(tx)
	})
	return granted && err == nil, err
}

// GrantPlatformAdmin makes userID a platform admin, granted by the admin
// grantedBy (the database refuses a granter who isn't one).
func (d *DB) GrantPlatformAdmin(ctx context.Context, userID, grantedBy string, record func(*ent.Tx) error) error {
	return d.withAdminLock(ctx, func(tx *ent.Tx) error {
		if _, err := tx.PlatformAdmin.Create().SetUserID(userID).SetGrantedBy(grantedBy).Save(ctx); err != nil {
			return err
		}
		return record(tx)
	})
}

// RemovePlatformAdmin removes userID's platform admin role, refusing to
// remove the last admin (ErrLastPlatformAdmin). Removals are serialized, so
// two admins removing each other can't empty the table.
func (d *DB) RemovePlatformAdmin(ctx context.Context, userID string, record func(*ent.Tx) error) error {
	return d.withAdminLock(ctx, func(tx *ent.Tx) error {
		n, err := tx.PlatformAdmin.Query().Count(ctx)
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastPlatformAdmin
		}
		if _, err := tx.PlatformAdmin.Delete().Where(platformadmin.UserID(userID)).Exec(ctx); err != nil {
			return err
		}
		return record(tx)
	})
}
