// Package auditverify is the periodic audit chain verification (ADR-0036,
// Verification): every Interval, one replica verifies every chain from the
// head it verified last (O(new entries)), and from the anchor every
// FullInterval, then appends audit.checkpoint entries with the verified heads
// to the platform chain, where the SIEM can compare them with what it holds.
//
// It runs inside serve, on the platform pool (the only serving login that
// reads every chain), rather than as a CronJob: the heads it resumes from
// must live outside any table a serving login can write (ADR-0036), and only
// a long-running process keeps them between runs; a CronJob would redo a
// full verify every time and need its own copy of the platform login.
package auditverify

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// lockKey is the session advisory lock that lets one replica run per
// interval ("LFAUVR").
const lockKey = 0x4C46_4155_5652

// HeadsPerEntry caps the heads in one checkpoint entry (about 150 bytes
// each), so an entry stays well inside syslog collectors' message limits; a
// run over more chains writes several entries, numbered batch of batches.
var HeadsPerEntry = 200 // a var so tests can batch small

// Defaults (ADR-0036: incremental often, full weekly).
const (
	DefaultInterval     = 15 * time.Minute
	DefaultFullInterval = 7 * 24 * time.Hour
)

// Job verifies chains. One per replica; build it with New.
type Job struct {
	DB           *store.DB
	Log          *slog.Logger
	Interval     time.Duration
	FullInterval time.Duration

	heads    map[string]audit.Head // verified heads by chain, this replica's memory only
	lastFull time.Time
	now      func() time.Time
}

// New returns a Job with the default schedule.
func New(db *store.DB, log *slog.Logger) *Job {
	return &Job{DB: db, Log: log, Interval: DefaultInterval, FullInterval: DefaultFullInterval,
		heads: map[string]audit.Head{}, now: time.Now}
}

// Result is what one run did.
type Result struct {
	Ran      bool     // false: another replica holds the lock
	Full     bool     // verified from the anchor
	Verified int      // chains with entries that verified
	Broken   []string // chains that didn't (the metric counts each)
}

// Run verifies every Interval until ctx is done. Errors are logged; a
// broken chain is counted in licenseforge_audit_verify_failures_total by
// audit.Verify, run after run, until it is repaired.
func (j *Job) Run(ctx context.Context) error {
	if j.Interval <= 0 || j.FullInterval <= 0 {
		return fmt.Errorf("auditverify: invalid schedule (interval %v, full %v)", j.Interval, j.FullInterval)
	}
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

// Once runs one verification if no other replica is running one: every
// chain from its last verified head (from the anchor when there is none or a
// full run is due), then the checkpoint entries.
func (j *Job) Once(ctx context.Context) (Result, error) {
	unlock, ok, err := j.DB.TryPlatformLock(ctx, lockKey)
	if err != nil || !ok {
		return Result{}, err
	}
	defer unlock()
	r := Result{Ran: true, Full: j.lastFull.IsZero() || j.now().Sub(j.lastFull) >= j.FullInterval}
	var chains []string
	if err := j.DB.ReadPlatform(ctx, false, func(tx *ent.Tx) error {
		var err error
		chains, err = tx.Tenant.Query().IDs(ctx)
		return err
	}); err != nil {
		return r, err
	}
	chains = append(chains, audit.PlatformTenant) // its tenants row is hidden from every serving login
	sort.Strings(chains)
	verified := []head{} // "heads": [] in the entry, never null
	var errs []error
	for _, c := range chains {
		from := j.heads[c]
		if r.Full {
			from = audit.Head{}
		}
		h, err := audit.Verify(ctx, j.DB.ReadPlatform, c, from)
		switch {
		case errors.Is(err, audit.ErrBroken):
			r.Broken = append(r.Broken, c) // keep the last good head: the next run checks again
			continue
		case err != nil:
			errs = append(errs, fmt.Errorf("chain %s: %w", c, err))
			continue
		}
		j.heads[c] = h
		if h.Seq > 0 {
			r.Verified++
			verified = append(verified, head{TenantID: c, Seq: h.Seq, Hash: hex.EncodeToString(h.Hash)})
		}
	}
	if err := j.checkpoint(ctx, r, verified); err != nil {
		errs = append(errs, err)
	}
	if r.Full && len(errs) == 0 {
		j.lastFull = j.now()
	}
	return r, errors.Join(errs...)
}

type head struct {
	TenantID string `json:"tenant_id"`
	Seq      int64  `json:"seq"`
	Hash     string `json:"hash"`
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
