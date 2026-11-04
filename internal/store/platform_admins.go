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

// ErrNotPlatformAdmin means the user isn't a platform admin (to remove, or to
// grant the role), or isn't an enabled user.
var ErrNotPlatformAdmin = errors.New("store: not an enabled platform admin")

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

// GrantPlatformAdmin makes userID (an enabled user) a platform admin, granted
// by grantedBy, who must be an enabled platform admin.
func (d *DB) GrantPlatformAdmin(ctx context.Context, userID, grantedBy string, record func(*ent.Tx) error) error {
	return d.withAdminLock(ctx, func(tx *ent.Tx) error {
		target, err := tx.User.Query().Where(user.ID(userID), user.DisabledAtIsNil()).Exist(ctx)
		if err != nil {
			return err
		}
		granter, err := tx.PlatformAdmin.Query().Where(platformadmin.UserID(grantedBy),
			platformadmin.HasUserWith(user.DisabledAtIsNil())).Exist(ctx)
		if err != nil {
			return err
		}
		if !target || !granter {
			return ErrNotPlatformAdmin
		}
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
		isAdmin, err := tx.PlatformAdmin.Query().Where(platformadmin.UserID(userID)).Exist(ctx)
		if err != nil {
			return err
		}
		if !isAdmin {
			return ErrNotPlatformAdmin
		}
		n, err := tx.PlatformAdmin.Query().Count(ctx)
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastPlatformAdmin
		}
		removed, err := tx.PlatformAdmin.Delete().Where(platformadmin.UserID(userID)).Exec(ctx)
		if err != nil {
			return err
		}
		if removed != 1 { // a raw statement outside the lock removed it meanwhile: don't record a removal that didn't happen
			return ErrNotPlatformAdmin
		}
		return record(tx)
	})
}
