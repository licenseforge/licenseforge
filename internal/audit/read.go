package audit

import (
	"context"
	"errors"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// Log reads a tenant's chain for its own members (the REST API: the
// dashboard's viewer and tenant self-export, ADR-0036), on the tenant pool
// under RLS, so the platform chain and other tenants' are never visible.
type Log struct{ DB *store.DB }

// Page is a position in the chain: entries after Seq oldest first (Asc), or
// before Seq newest first (Seq 0: from the head).
type Page struct {
	Asc   bool
	Seq   int64
	Limit int
}

// readWindow: a reader's next read within it isn't recorded again, so
// paging and polling don't flood the chain. A variable for tests.
var readWindow = "15 minutes"

// List returns a page of p's tenant's entries. p needs audit:read on every
// product (ADR-0027: reading the log is privileged). The read is recorded
// (audit_event.read, in the same transaction, after the read) unless p's
// last read entry is within readWindow; a refusal is recorded as denied.
func (l Log) List(ctx context.Context, p authz.Principal, pg Page) ([]*ent.AuditEvent, error) {
	ctx = authz.WithPrincipal(ctx, p)
	tenantID, err := authz.TenantID(ctx)
	if err != nil {
		return nil, err
	}
	ev := By(p, "audit_event.read", "", "")
	if err := authz.Require(ctx, authz.AuditRead, ""); err != nil {
		return nil, Refused(ctx, l.DB, tenantID, ev, err)
	}
	var out []*ent.AuditEvent
	err = l.DB.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		q := tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID)).Limit(pg.Limit)
		switch {
		case pg.Asc:
			q.Where(auditevent.SeqGT(pg.Seq)).Order(ent.Asc(auditevent.FieldSeq))
		case pg.Seq > 0:
			q.Where(auditevent.SeqLT(pg.Seq)).Order(ent.Desc(auditevent.FieldSeq))
		default:
			q.Order(ent.Desc(auditevent.FieldSeq))
		}
		var err error
		if out, err = q.All(ctx); err != nil {
			return err
		}
		recent, err := recentRead(ctx, tx, tenantID, ev)
		if err != nil || recent {
			return err
		}
		ev.Outcome = auditevent.OutcomeSuccess
		ev.Details = map[string]any{"asc": pg.Asc, "from_seq": pg.Seq}
		_, err = Record(ctx, tx, tenantID, ev)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// recentRead reports whether ev's actor has a successful read entry within
// readWindow among the chain's last 1,000 entries (an index range, however
// long the chain).
// ponytail: a busy chain (over 1,000 entries per window) records a read
// more often; an index on (tenant_id, action, actor_id) if that matters.
func recentRead(ctx context.Context, tx *ent.Tx, tenantID string, ev Event) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT EXISTS (SELECT 1 FROM (SELECT action, actor_type, actor_id, outcome, occurred_at FROM audit_events
		WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1000) r
		WHERE action = $2 AND actor_type = $3 AND actor_id = $4 AND outcome = 'success' AND occurred_at > clock_timestamp() - $5::interval)`,
		tenantID, ev.Action, string(ev.ActorType), ev.ActorID, readWindow)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	var ok bool
	if !rows.Next() {
		return false, errors.Join(errors.New("audit: read check returned no row"), rows.Err())
	}
	err = rows.Scan(&ok)
	return ok, err
}
