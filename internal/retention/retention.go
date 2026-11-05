// Package retention prunes audit chains (ADR-0036, ADR-0027 AU-11): for each
// chain with a retention period, it cuts the prefix of entries older than
// the period, in batches, behind an anchor, and records each cut in the
// chain as an audit.retention entry. It runs as `licenseforge audit prune`
// with the retention login, the only one that may delete audit entries; the
// database holds it to entries at least 365 days old and at or below the
// chain's newest anchor, whatever this code does.
package retention

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ent/tenant"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// MinDays is the shortest retention period (ADR-0036; the database refuses
// shorter ones too).
const MinDays = 365

// ErrInvalid means a retention period below MinDays.
var ErrInvalid = fmt.Errorf("retention: the retention period must be at least %d days", MinDays)

// batch is the most entries one prune transaction removes from a chain, so
// the chain's lock is held briefly (every login appends to the platform chain).
var batch int64 = 10000

// SetTenantRetention sets the retention period of the caller's tenant's audit
// chain; nil keeps everything. Owners only (tenant:write); audited, refusals
// included. The tenant pool may change only this column of its own row.
func SetTenantRetention(ctx context.Context, db *store.DB, days *int) error {
	tn, err := authz.TenantID(ctx)
	if err != nil {
		return authz.ErrDenied
	}
	p, _ := authz.FromContext(ctx)
	ev := audit.Event{ActorType: actorType(p), ActorID: p.ID, Action: "tenant.audit_retention.update", ObjectType: "tenant", ObjectID: tn,
		Details: map[string]any{"days": days}}
	if err := authz.Require(ctx, authz.TenantWrite, ""); err != nil {
		ev.Outcome = auditevent.OutcomeDenied
		return errors.Join(err, db.WithTenant(ctx, tn, func(tx *ent.Tx) error { _, err := audit.Record(ctx, tx, tn, ev); return err }))
	}
	if days != nil && *days < MinDays {
		return ErrInvalid
	}
	ev.Outcome = auditevent.OutcomeSuccess
	return db.WithTenant(ctx, tn, func(tx *ent.Tx) error {
		up := tx.Tenant.UpdateOneID(tn)
		if days == nil {
			up.ClearAuditRetentionDays()
		} else {
			up.SetAuditRetentionDays(*days)
		}
		if err := up.Exec(ctx); err != nil {
			return err
		}
		_, err := audit.Record(ctx, tx, tn, ev)
		return err
	})
}

func actorType(p authz.Principal) auditevent.ActorType {
	if p.Kind == authz.Token {
		return auditevent.ActorTypeToken
	}
	return auditevent.ActorTypeUser
}

// Cut is one prune transaction's result.
type Cut struct {
	TenantID string
	Through  int64 // the new anchor: entries up to here are gone
	Deleted  int64
}

// Prune cuts every chain that has a retention period: tenants with
// audit_retention_days, and the platform chain if platformDays > 0 (the
// install setting LICENSEFORGE_PLATFORM_AUDIT_RETENTION_DAYS; 0 keeps
// everything). It returns the cuts made, in order. A chain that fails is
// reported and the others are still pruned.
func Prune(ctx context.Context, r *store.Retention, platformDays int) ([]Cut, error) {
	if platformDays != 0 && platformDays < MinDays {
		return nil, ErrInvalid
	}
	type chain struct {
		id   string
		days int
	}
	var chains []chain
	if err := r.Tx(ctx, func(tx *ent.Tx) error {
		ts, err := tx.Tenant.Query().Where(tenant.AuditRetentionDaysNotNil()).Select(tenant.FieldID, tenant.FieldAuditRetentionDays).All(ctx)
		for _, t := range ts {
			chains = append(chains, chain{t.ID, *t.AuditRetentionDays})
		}
		return err
	}); err != nil {
		return nil, err
	}
	if platformDays > 0 {
		chains = append(chains, chain{audit.PlatformTenant, platformDays})
	}
	var cuts []Cut
	var errs []error
	for _, c := range chains {
		for ctx.Err() == nil {
			cut, err := pruneBatch(ctx, r, c.id, c.days)
			if err != nil {
				errs = append(errs, fmt.Errorf("retention: chain %s: %w", c.id, err))
				break
			}
			if cut.Deleted == 0 {
				break
			}
			cuts = append(cuts, cut)
		}
	}
	return cuts, errors.Join(append(errs, ctx.Err())...)
}

// ErrCountMismatch means the delete removed another number of entries than
// the anchor advanced by: the prefix wasn't what it should be. The batch
// rolls back.
var ErrCountMismatch = errors.New("retention: deleted count doesn't match the cut")

// pruneBatch makes at most one cut of at most batch entries in one
// transaction, under the chain's lock:
//
//   - the cut ends before the first entry younger than the period (seq order
//     defines the prefix, so a clock step can't open a hole);
//   - never at the chain's last entry, so the audit.retention entry links to a
//     surviving head;
//   - never past what a registered export sink hasn't delivered (a missing
//     cursor counts as 0);
//   - at most batch entries past the current anchor.
func pruneBatch(ctx context.Context, r *store.Retention, tenantID string, days int) (Cut, error) {
	cut := Cut{TenantID: tenantID}
	err := r.Tx(ctx, func(tx *ent.Tx) error {
		if err := audit.LockChain(ctx, tx, tenantID); err != nil {
			return err
		}
		var anchor, head, firstYoung, gate sql.NullInt64
		var through int64
		var throughHash []byte
		row := func(q string, args []any, dst ...any) error {
			rows, err := tx.QueryContext(ctx, q, args...)
			if err != nil {
				return err
			}
			if rows.Next() {
				err = rows.Scan(dst...)
			}
			return errors.Join(err, rows.Err(), rows.Close())
		}
		if err := row(`SELECT
			(SELECT max(seq) FROM audit_anchors WHERE tenant_id = $1),
			(SELECT max(seq) FROM audit_events WHERE tenant_id = $1),
			(SELECT min(seq) FROM audit_events WHERE tenant_id = $1 AND occurred_at >= now() - make_interval(days => $2)),
			(SELECT min(COALESCE(c.seq, 0)) FROM audit_export_sinks s
			   LEFT JOIN audit_export_cursors c ON c.sink_id = s.id AND c.tenant_id = $1)`,
			[]any{tenantID, days}, &anchor, &head, &firstYoung, &gate); err != nil {
			return err
		}
		if !head.Valid {
			return nil // an empty chain
		}
		through = head.Int64 - 1 // never the last entry
		if firstYoung.Valid {
			through = min(through, firstYoung.Int64-1) // only the prefix before the first young entry
		}
		if gate.Valid {
			through = min(through, gate.Int64) // nothing a registered sink hasn't delivered
		}
		through = min(through, anchor.Int64+batch)
		if through <= anchor.Int64 {
			return nil // nothing to cut
		}
		if err := row(`SELECT hash FROM audit_events WHERE tenant_id = $1 AND seq = $2`, []any{tenantID, through}, &throughHash); err != nil {
			return err
		}
		if len(throughHash) == 0 {
			return fmt.Errorf("retention: entry %d is missing", through)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_anchors (id, tenant_id, seq, hash, cut_at) VALUES ($1, $2, $3, $4, now())`,
			ids.AuditAnchor(), tenantID, through, throughHash); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE tenant_id = $1 AND seq > $2 AND seq <= $3`, tenantID, anchor.Int64, through)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != through-anchor.Int64 {
			return fmt.Errorf("%w: deleted %d entries, cut %d..%d", ErrCountMismatch, n, anchor.Int64+1, through)
		}
		if _, err := audit.Record(ctx, tx, tenantID, audit.Event{ActorType: auditevent.ActorTypeSystem, Action: "audit.retention",
			Outcome: auditevent.OutcomeSuccess, Details: map[string]any{
				"through_seq": through, "through_hash": hex.EncodeToString(throughHash), "retention_days": days, "deleted": n,
			}}); err != nil {
			return err
		}
		cut.Through, cut.Deleted = through, n
		return nil
	})
	if err != nil {
		return Cut{TenantID: tenantID}, err
	}
	return cut, nil
}
