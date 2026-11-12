package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/jackc/pgx/v5/stdlib"

	"licenseforge.io/licenseforge/internal/store/ent"
)

// Owner is the schema owner's connection for the operator recovery commands
// (ADR-0031: an admin set nobody can use; ADR-0036: a SIEM sink no longer
// exported). Like `migrate`, it is run by hand with
// LICENSEFORGE_OWNER_DATABASE_URL; serving processes never hold it.
type Owner struct {
	client *ent.Client
	db     *sql.DB
}

// OpenOwner connects the owner login.
func OpenOwner(ctx context.Context, dsn string) (*Owner, error) {
	cfg, err := parseDSN(dsn)
	if err != nil {
		return nil, err
	}
	db := stdlib.OpenDB(*cfg)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("owner login: %w", err)
	}
	return &Owner{client: ent.NewClient(ent.Driver(entsql.OpenDB("postgres", db))), db: db}, nil
}

// Close closes the connection.
func (o *Owner) Close() error { return o.db.Close() }

// ErrNoSuchSink means no registered export sink has that name.
var ErrNoSuchSink = errors.New("store: no such audit export sink")

// ResetPlatformAdmins removes every platform admin, under the admin-set
// lock, so that the next sign-in matching LICENSEFORGE_BOOTSTRAP_ADMIN
// becomes the platform admin again (ADR-0031's recovery when no admin can
// sign in). record runs in the same transaction with the removed user IDs.
func (o *Owner) ResetPlatformAdmins(ctx context.Context, record func(*ent.Tx, []string) error) ([]string, error) {
	var removed []string
	err := inTx(ctx, o.client, nil, func(tx *ent.Tx) error {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, platformAdminLock); err != nil {
			return err
		}
		admins, err := tx.PlatformAdmin.Query().All(ctx)
		if err != nil {
			return err
		}
		for _, a := range admins {
			removed = append(removed, a.UserID)
		}
		if _, err := tx.PlatformAdmin.Delete().Exec(ctx); err != nil {
			return err
		}
		return record(tx, removed)
	})
	return removed, err
}

// RemoveExportSink unregisters a SIEM sink and drops its cursors, so audit
// retention no longer waits for it (ADR-0036): its unexported entries become
// prunable. A serving pod still configured with the sink registers it again
// at start, from the current anchor: take it out of the configuration first.
// record runs in the same transaction with the number of cursors dropped.
func (o *Owner) RemoveExportSink(ctx context.Context, name string, record func(*ent.Tx, int) error) error {
	return inTx(ctx, o.client, nil, func(tx *ent.Tx) error {
		cursors, err := tx.ExecContext(ctx, `DELETE FROM audit_export_cursors WHERE sink_id = $1`, name)
		if err != nil {
			return err
		}
		n, err := cursors.RowsAffected()
		if err != nil {
			return err
		}
		sinks, err := tx.ExecContext(ctx, `DELETE FROM audit_export_sinks WHERE id = $1`, name)
		if err != nil {
			return err
		}
		if gone, err := sinks.RowsAffected(); err != nil || gone != 1 {
			return errors.Join(ErrNoSuchSink, err)
		}
		return record(tx, int(n))
	})
}
