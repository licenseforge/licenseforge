package store

import (
	"context"
	"errors"

	"licenseforge.io/licenseforge/internal/store/ent"
)

// ErrNoSuchUser means the user doesn't exist or is already disabled.
var ErrNoSuchUser = errors.New("store: no such enabled user")

// DisableUser suspends userID (ADR-0029): login is refused from now on and
// every session ends in the same transaction, so access stops at once, not
// at the next login. record runs in the same transaction (audit).
func (d *DB) DisableUser(ctx context.Context, userID string, record func(*ent.Tx) error) error {
	return inTx(ctx, d.platform, func(tx *ent.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = clock_timestamp(), updated_at = clock_timestamp()
			WHERE id = $1 AND disabled_at IS NULL`, userID)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(ErrNoSuchUser, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
			return err
		}
		return record(tx)
	})
}
