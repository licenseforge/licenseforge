// Package auditverify is the periodic audit chain verification (ADR-0036,
// Verification): every Interval, the leader replica verifies every chain
// from the head it verified last (O(new entries)), and from the anchor every
// FullInterval, then appends audit.checkpoint entries with the verified heads
// and anchors to the platform chain, where the SIEM can compare them with
// what it holds.
//
// Leader election: the first replica to take a session advisory lock keeps
// it, with its connection, for its lifetime, and checks the connection
// before each run; the others try again every interval and only run once
// the leader's session is gone.
//
// It runs inside serve, on the platform pool (the only serving login that
// reads every chain), rather than as a CronJob: the heads it resumes from
// must live outside any table a serving login can write (ADR-0036), and only
// a long-running process keeps them between runs; a CronJob would redo a
// full verify every time and need its own copy of the platform login.
package auditverify

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// lockKey is the leader's session advisory lock ("LFAUVR").
const lockKey = 0x4C46_4155_5652

// HeadsPerEntry caps the heads in one checkpoint entry (about 150 bytes
// each), so an entry stays well inside syslog collectors' message limits; a
// run over more chains writes several entries, numbered batch of batches.
var HeadsPerEntry = 200 // a var so tests can batch small

// aliveTimeout bounds the leader's check of its lock connection, so a hung
// connection can't hold a run; a var so tests can shorten it.
var aliveTimeout = 10 * time.Second

// Defaults (ADR-0036: incremental often, full weekly).
const (
	DefaultInterval     = 15 * time.Minute
	DefaultFullInterval = 7 * 24 * time.Hour
)

// Job verifies chains. One per replica; build it with New, and Close it
// to give up the lead.
type Job struct {
	DB           *store.DB
	Log          *slog.Logger
	Interval     time.Duration // also the time limit of an incremental run
	FullInterval time.Duration
	FullTimeout  time.Duration // limit of a run of the full pass; 0: FullInterval / 4

	heads    map[string]audit.Head // last good head by chain, this replica's memory only
	anchors  map[string]audit.Head // the anchor each chain was last verified from
	broken   map[string]bool       // chains whose last verification failed: re-verified from the anchor
	fullPass map[string]bool       // chains done in the full pass in progress; nil: none in progress
	lastFull time.Time
	lock     *store.SessionLock                      // held while this replica leads
	ping     func(context.Context) error             // the lock's liveness check; nil: lock.Alive (tests replace it)
	tenants  func(context.Context) ([]string, error) // the tenant IDs; nil: listTenants (tests replace it)

	hasFullCheckpoint func(context.Context) (bool, error) // tests replace it
	now               func() time.Time
	verify            func(ctx context.Context, run audit.Runner, tenantID string, from audit.Head) (head, anchor audit.Head, err error)
}

// New returns a Job with the default schedule.
func New(db *store.DB, log *slog.Logger) *Job {
	j := &Job{DB: db, Log: log, Interval: DefaultInterval, FullInterval: DefaultFullInterval,
		heads: map[string]audit.Head{}, anchors: map[string]audit.Head{}, broken: map[string]bool{},
		now: time.Now, verify: audit.VerifyAnchored}
	j.hasFullCheckpoint = j.fullCheckpointExists
	return j
}

// Close gives up the lead, if this replica has it.
func (j *Job) Close() {
	if j.lock != nil {
		j.lock.Release()
		j.lock = nil
	}
}

// Result is what one run did.
type Result struct {
	Ran      bool     // false: another replica leads
	Full     bool     // verified from the anchor
	Verified int      // chains with entries that verified
	Broken   []string // chains that didn't (the metric counts each)
}

// Run verifies every Interval until ctx is done, then gives up the lead.
// Errors are logged; a broken chain is counted in
// licenseforge_audit_verify_failures_total by audit.Verify, run after run,
// until it is repaired.
func (j *Job) Run(ctx context.Context) error {
	if j.Interval <= 0 || j.FullInterval <= 0 {
		return fmt.Errorf("auditverify: invalid schedule (interval %v, full %v)", j.Interval, j.FullInterval)
	}
	defer j.Close()
	j.seed(ctx)
	t := time.NewTicker(j.Interval)
	defer t.Stop()
	for {
		r, err := j.Once(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			j.Log.Error("audit verify", "err", err)
		case len(r.Broken) > 0:
			j.Log.Error("audit chains broken", "chains", r.Broken)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// listTenants returns every tenant's ID, as the platform pool sees them.
func (j *Job) listTenants(ctx context.Context) ([]string, error) {
	var ids []string
	err := j.DB.ReadPlatform(ctx, false, func(tx *ent.Tx) error {
		var err error
		ids, err = tx.Tenant.Query().IDs(ctx)
		return err
	})
	return ids, err
}

// seed starts the full-pass gauge at the job's start on a new install (no
// full-mode checkpoint on the platform chain yet), so the first pass gets
// the overdue alert's grace (two full intervals) and a first pass that
// never completes is still caught. An install that ran full passes before
// isn't seeded: a restart must not hide a pass that keeps failing (the
// alert's max_over_time still sees the last completed pass of any replica).
func (j *Job) seed(ctx context.Context) {
	has, err := j.hasFullCheckpoint(ctx)
	switch {
	case err != nil:
		j.Log.Warn("audit verify: can't tell whether full passes ran before; not seeding the full-pass gauge", "err", err)
	case !has:
		metrics.AuditVerifyLastFull.Set(float64(j.now().Unix()))
	}
}

// fullCheckpointExists reports whether the platform chain has a full-mode
// audit.checkpoint.
func (j *Job) fullCheckpointExists(ctx context.Context) (bool, error) {
	var has bool
	err := j.DB.ReadPlatform(ctx, false, func(tx *ent.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT EXISTS (SELECT 1 FROM audit_events WHERE tenant_id = $1
			AND action = 'audit.checkpoint' AND details->>'mode' = 'full')`, audit.PlatformTenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		if !rows.Next() {
			return errors.Join(errors.New("auditverify: checkpoint query returned no row"), rows.Err())
		}
		return rows.Scan(&has)
	})
	return has, err
}

// lead reports whether this replica leads: it holds the lock and its
// connection still answers, or it takes the lock now. A lost lock (the
// connection dropped) is released and taken again if it's free.
func (j *Job) lead(ctx context.Context) (bool, error) {
	if j.lock != nil {
		ping := j.ping
		if ping == nil {
			ping = j.lock.Alive
		}
		pingCtx, cancel := context.WithTimeout(ctx, aliveTimeout)
		err := ping(pingCtx)
		cancel()
		if err == nil {
			return true, nil
		} else if ctx.Err() == nil {
			j.Log.Warn("audit verify: lost the leader lock; trying to take it again", "err", err)
		}
		j.Close()
	}
	l, ok, err := j.DB.TryPlatformLock(ctx, lockKey)
	if err != nil || !ok {
		return false, err
	}
	j.lock = l
	return true, nil
}

// Once runs one verification if this replica leads. Every chain is
// verified from its last good head, or from its anchor when there is none,
// when it was broken last time, or in a full pass. A full pass starts every
// FullInterval and may span several runs: each run of it may take
// FullTimeout, and a run that runs out of time leaves the chains it finished
// done, so the next run continues with the rest (others resume from their
// heads). Incremental runs may take Interval.
//
// Each verified chain moves licenseforge_audit_verify_last_success_timestamp_seconds
// (progress, also inside a long full pass); a broken chain has its own metric.
func (j *Job) Once(parent context.Context) (Result, error) {
	// lastFull moves only when a pass completes, so an unfinished pass stays due.
	full := j.lastFull.IsZero() || j.now().Sub(j.lastFull) >= j.FullInterval
	limit := j.Interval
	if full {
		limit = j.FullTimeout
		if limit <= 0 {
			limit = j.FullInterval / 4
		}
	}
	ctx, cancel := context.WithTimeout(parent, limit)
	defer cancel()
	ok, err := j.lead(ctx)
	if err != nil {
		metrics.AuditVerifyErrors.Inc()
	}
	if err != nil || !ok {
		return Result{}, err
	}
	if full && j.fullPass == nil {
		j.fullPass = map[string]bool{}
	}
	r := Result{Ran: true, Full: full}
	list := j.tenants
	if list == nil {
		list = j.listTenants
	}
	chains, err := list(ctx)
	if err != nil {
		metrics.AuditVerifyErrors.Inc()
		return r, err
	}
	chains = append(chains, audit.PlatformTenant) // its tenants row is hidden from every serving login
	sort.Strings(chains)
	listed := []head{} // "heads": [] in the entry, never null
	var errs []error
	for _, c := range chains {
		if ctx.Err() != nil { // out of time: the rest waits for the next run
			errs = append(errs, ctx.Err())
			break
		}
		h, anchor, fromAnchor, err := j.chain(ctx, c, full)
		switch {
		case errors.Is(err, audit.ErrBroken):
			// Keep the last good head and verify from the anchor next time,
			// checking that head again: the break, a truncation included,
			// keeps counting until it is repaired.
			j.broken[c] = true
			r.Broken = append(r.Broken, c)
			if full && fromAnchor {
				j.fullPass[c] = true
			}
			continue
		case err != nil:
			errs = append(errs, fmt.Errorf("chain %s: %w", c, err))
			continue
		}
		prev, known := j.heads[c]
		prevAnchor := j.anchors[c]
		j.heads[c], j.anchors[c] = h, anchor
		delete(j.broken, c)
		if full && fromAnchor {
			j.fullPass[c] = true
		}
		metrics.AuditVerifyLastSuccess.Set(float64(j.now().Unix()))
		if h.Seq == 0 {
			continue
		}
		r.Verified++
		moved := !known || h.Seq != prev.Seq || !bytes.Equal(h.Hash, prev.Hash) ||
			anchor.Seq != prevAnchor.Seq || !bytes.Equal(anchor.Hash, prevAnchor.Hash)
		if (full && fromAnchor) || moved {
			listed = append(listed, head{TenantID: c, Seq: h.Seq, Hash: hex.EncodeToString(h.Hash),
				Anchor: anchorOf(anchor)})
		}
	}
	// The checkpoint gets its own time, so a run that ran out of time still
	// records what it verified.
	cpCtx, cpCancel := context.WithTimeout(parent, 30*time.Second)
	defer cpCancel()
	if err := j.checkpoint(cpCtx, r, listed); err != nil {
		errs = append(errs, err)
	}
	metrics.AuditVerifyErrors.Add(float64(len(errs)))
	if full && len(errs) == 0 { // every chain was done in this pass
		j.lastFull, j.fullPass = j.now(), nil
		metrics.AuditVerifyLastFull.Set(float64(j.lastFull.Unix()))
	}
	return r, errors.Join(errs...)
}

// chain verifies one chain and reports whether it started from the anchor.
// After a verification from the anchor, a last good head above the anchor is
// checked too (it must still be there, unchanged): the surviving chain
// verifies on its own after its tail was removed.
func (j *Job) chain(ctx context.Context, c string, full bool) (h, anchor audit.Head, fromAnchor bool, err error) {
	prev, known := j.heads[c]
	fromAnchor = !known || j.broken[c] || (full && !j.fullPass[c])
	from := prev
	if fromAnchor {
		from = audit.Head{}
	}
	h, anchor, err = j.verify(ctx, j.DB.ReadPlatform, c, from)
	if err == nil && fromAnchor && known && prev.Seq > anchor.Seq {
		h, anchor, err = j.verify(ctx, j.DB.ReadPlatform, c, prev)
	}
	return h, anchor, fromAnchor, err
}

type head struct {
	TenantID string    `json:"tenant_id"`
	Seq      int64     `json:"seq"`
	Hash     string    `json:"hash"`
	Anchor   anchorRef `json:"anchor"` // where the chain starts: seq 0 and no hash while nothing was pruned
}

type anchorRef struct {
	Seq  int64  `json:"seq"`
	Hash string `json:"hash"`
}

func anchorOf(a audit.Head) anchorRef {
	if a.Seq == 0 {
		return anchorRef{}
	}
	return anchorRef{Seq: a.Seq, Hash: hex.EncodeToString(a.Hash)}
}

// checkpoint appends the verified heads to the platform chain, HeadsPerEntry
// per entry, in one transaction. Broken chains are listed (IDs only) in the
// first entry, so the SIEM sees the failure too.
func (j *Job) checkpoint(ctx context.Context, r Result, heads []head) error {
	mode := "incremental"
	if r.Full {
		mode = "full"
	}
	batches := max(1, (len(heads)+HeadsPerEntry-1)/HeadsPerEntry)
	return j.DB.WithPlatform(ctx, func(tx *ent.Tx) error {
		for b := range batches {
			part := heads[min(b*HeadsPerEntry, len(heads)):min((b+1)*HeadsPerEntry, len(heads))]
			details := map[string]any{"mode": mode, "batch": b + 1, "batches": batches, "heads": part}
			outcome := auditevent.OutcomeSuccess
			if len(r.Broken) > 0 {
				outcome = auditevent.OutcomeFailure
				if b == 0 {
					details["broken"] = r.Broken
				}
			}
			if _, err := audit.Record(ctx, tx, audit.PlatformTenant, audit.Event{ActorType: auditevent.ActorTypeSystem,
				Action: "audit.checkpoint", Outcome: outcome, Details: details}); err != nil {
				return err
			}
		}
		return nil
	})
}
