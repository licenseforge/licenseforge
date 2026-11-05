// Package auditexport pushes every audit chain to a SIEM sink (ADR-0036).
//
// Each (sink, chain) has a cursor: the last seq delivered. A replica leases
// one chain's cursor in a short transaction (SKIP LOCKED, so replicas never
// wait on each other and need no leader), reads the next batch, sends it
// outside any transaction, then advances the cursor only if it still holds
// the lease and the cursor hasn't moved. A replica that dies between send and
// advance leaves the lease to expire; the next one sends the batch again:
// delivery is at-least-once, and the SIEM deduplicates on the entry ID.
// Per-chain seq is gap-free in commit order (audit.Record holds the chain's
// lock until commit), so a cursor never skips an entry.
package auditexport

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// Entry is one exported audit entry: every AU-3 field plus the chain links,
// so the SIEM holds the external anchor and can check continuity.
type Entry struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	Seq        int64           `json:"seq"`
	OccurredAt time.Time       `json:"occurred_at"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id,omitempty"`
	Action     string          `json:"action"`
	ObjectType string          `json:"object_type,omitempty"`
	ObjectID   string          `json:"object_id,omitempty"`
	Outcome    string          `json:"outcome"`
	SourceIP   string          `json:"source_ip,omitempty"`
	UserAgent  string          `json:"user_agent,omitempty"`
	Details    json.RawMessage `json:"details"`
	PrevHash   string          `json:"prev_hash"` // hex
	Hash       string          `json:"hash"`      // hex
}

// Sink delivers one chain's batch, in seq order. It returns nil only once the
// batch was handed over as far as the transport can tell; the cursor then
// advances past it.
type Sink interface {
	Send(ctx context.Context, batch []Entry) error
}

// ErrLeaseLost means another replica took the cursor over (the lease ran
// out): this replica's batch may arrive twice, and the cursor is theirs.
var ErrLeaseLost = errors.New("auditexport: cursor lease lost")

// Exporter runs one sink on one replica. Several replicas may run the same
// sink: the cursor leases divide the chains between them.
type Exporter struct {
	DB       *store.DB
	Name     string // the sink's registry name, e.g. syslog (a metric label)
	Sink     Sink
	Lease    time.Duration // how long a claimed cursor is ours; above the sink's worst send time
	Batch    int
	Interval time.Duration // between rounds when idle or failing
	Log      *slog.Logger
	replica  string
}

// New returns an Exporter with ADR-0036's defaults.
func New(db *store.DB, name string, sink Sink, log *slog.Logger) *Exporter {
	host, _ := os.Hostname()
	return &Exporter{DB: db, Name: name, Sink: sink, Lease: time.Minute, Batch: 500, Interval: 5 * time.Second, Log: log,
		replica: host + "/" + rand.Text()[:8]}
}

// Register records the sink in audit_export_sinks, so retention never prunes
// what it hasn't exported (ADR-0036). Idempotent; call it at start.
func Register(ctx context.Context, db *store.DB, name string) error {
	return db.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_export_sinks (id, created_at) VALUES ($1, clock_timestamp()) ON CONFLICT (id) DO NOTHING`, name)
		return err
	})
}

// Run exports until ctx is done: every round it adds cursors for new chains,
// sends batches until nothing is pending, and updates the lag metric.
func (x *Exporter) Run(ctx context.Context) {
	failures := metrics.AuditExportFailures.WithLabelValues(x.Name)
	for {
		err := Register(ctx, x.DB, x.Name)
		if err == nil {
			err = x.ensureCursors(ctx)
		}
		for err == nil {
			var n int
			if n, err = x.Once(ctx); n == 0 {
				break
			}
		}
		if err != nil && ctx.Err() == nil {
			failures.Inc()
			x.Log.Error("audit export", "sink", x.Name, "err", err)
		}
		if lag, err := x.lag(ctx); err == nil {
			metrics.AuditExportLag.WithLabelValues(x.Name).Set(lag)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(x.Interval):
		}
	}
}

// Once exports one batch of one chain whose cursor is free and behind. It
// returns how many entries it delivered: 0 when nothing is pending.
func (x *Exporter) Once(ctx context.Context) (int, error) {
	c, ok, err := x.claim(ctx)
	if err != nil || !ok {
		return 0, err
	}
	batch, err := x.read(ctx, c)
	if err == nil && len(batch) > 0 {
		err = x.Sink.Send(ctx, batch)
	}
	if err != nil || len(batch) == 0 {
		return 0, errors.Join(err, x.release(context.WithoutCancel(ctx), c))
	}
	return len(batch), x.advance(context.WithoutCancel(ctx), c, batch[len(batch)-1].Seq)
}

type cursor struct {
	id, tenantID string
	seq          int64
}

// ensureCursors adds a cursor at the chain's start for every chain that has
// none yet: every tenant, and the platform chain (hidden from tenant lists).
func (x *Exporter) ensureCursors(ctx context.Context) error {
	return x.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id FROM (SELECT id FROM tenants UNION SELECT $2::varchar) t
			WHERE NOT EXISTS (SELECT 1 FROM audit_export_cursors c WHERE c.tenant_id = t.id AND c.sink_id = $1)`, x.Name, audit.PlatformTenant)
		if err != nil {
			return err
		}
		var missing []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
			missing = append(missing, id)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		for _, tn := range missing {
			if _, err := tx.ExecContext(ctx, `INSERT INTO audit_export_cursors (id, tenant_id, sink_id, seq) VALUES ($1, $2, $3, 0)
				ON CONFLICT (tenant_id, sink_id) DO NOTHING`, ids.AuditExportCursor(), tn, x.Name); err != nil {
				return err
			}
		}
		return nil
	})
}

// claim leases a free cursor that is behind its chain, picked at random so a
// busy chain can't starve the others.
// ponytail: random order scans every cursor of the sink; order by lag if
// there are ever many thousands of chains.
func (x *Exporter) claim(ctx context.Context) (c cursor, ok bool, err error) {
	err = x.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT c.id, c.tenant_id, c.seq FROM audit_export_cursors c
			WHERE c.sink_id = $1 AND (c.claimed_until IS NULL OR c.claimed_until < clock_timestamp())
			  AND EXISTS (SELECT 1 FROM audit_events e WHERE e.tenant_id = c.tenant_id AND e.seq > c.seq)
			ORDER BY random() LIMIT 1 FOR UPDATE SKIP LOCKED`, x.Name)
		if err != nil {
			return err
		}
		ok = rows.Next()
		if ok {
			err = rows.Scan(&c.id, &c.tenantID, &c.seq)
		}
		if err := errors.Join(err, rows.Err(), rows.Close()); err != nil || !ok {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE audit_export_cursors SET claimed_by = $2,
			claimed_until = clock_timestamp() + make_interval(secs => $3) WHERE id = $1`, c.id, x.replica, x.Lease.Seconds())
		return err
	})
	return c, ok && err == nil, err
}

// read returns the next entries after the cursor, in seq order.
func (x *Exporter) read(ctx context.Context, c cursor) ([]Entry, error) {
	var es []*ent.AuditEvent
	err := x.DB.ReadPlatform(ctx, false, func(tx *ent.Tx) error {
		var err error
		es, err = tx.AuditEvent.Query().Where(auditevent.TenantID(c.tenantID), auditevent.SeqGT(c.seq)).
			Order(ent.Asc(auditevent.FieldSeq)).Limit(x.Batch).All(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]Entry, len(es))
	for i, e := range es {
		out[i] = Entry{ID: e.ID, TenantID: e.TenantID, Seq: e.Seq, OccurredAt: e.OccurredAt.UTC(), ActorType: string(e.ActorType),
			ActorID: deref(e.ActorID), Action: e.Action, ObjectType: deref(e.ObjectType), ObjectID: deref(e.ObjectID),
			Outcome: string(e.Outcome), SourceIP: deref(e.SourceIP), UserAgent: deref(e.UserAgent), Details: json.RawMessage(e.Details),
			PrevHash: hex.EncodeToString(e.PrevHash), Hash: hex.EncodeToString(e.Hash)}
	}
	return out, nil
}

// advance moves the cursor to seq and frees it, only if this replica still
// holds the lease and the cursor is where it was claimed.
func (x *Exporter) advance(ctx context.Context, c cursor, seq int64) error {
	return x.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE audit_export_cursors SET seq = $4, claimed_by = NULL, claimed_until = NULL
			WHERE id = $1 AND claimed_by = $2 AND seq = $3`, c.id, x.replica, c.seq, seq)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return errors.Join(fmt.Errorf("%w: chain %s", ErrLeaseLost, c.tenantID), err)
		}
		return nil
	})
}

// release frees the cursor after a failed send, if this replica still holds it.
func (x *Exporter) release(ctx context.Context, c cursor) error {
	return x.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE audit_export_cursors SET claimed_by = NULL, claimed_until = NULL
			WHERE id = $1 AND claimed_by = $2`, c.id, x.replica)
		return err
	})
}

// lag is the age in seconds of the oldest entry this sink hasn't delivered.
func (x *Exporter) lag(ctx context.Context) (float64, error) {
	var lag float64
	err := x.DB.ReadPlatform(ctx, false, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT COALESCE(EXTRACT(EPOCH FROM clock_timestamp() - min(e.occurred_at)), 0)::float8
			FROM audit_export_cursors c JOIN audit_events e ON e.tenant_id = c.tenant_id AND e.seq = c.seq + 1
			WHERE c.sink_id = $1`, x.Name)
		if err != nil {
			return err
		}
		if rows.Next() {
			err = rows.Scan(&lag)
		}
		return errors.Join(err, rows.Err(), rows.Close())
	})
	return lag, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
