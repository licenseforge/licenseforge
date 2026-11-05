// Package audit writes and verifies the hash-chained audit log (ADR-0027).
//
// Record runs in the caller's transaction, so an action and its audit entry
// commit or roll back together. Failed or denied attempts roll their action
// back, so record those in a transaction of their own after the rollback.
//
// Entries of one tenant form a chain: each entry's hash covers all its fields
// and the previous entry's hash, so Verify detects a changed, reordered or
// removed entry, including a removed first entry. It can't detect removed
// last entries (truncation): compare the head Verify returns with an exported
// head. Someone who can rewrite the whole table can rewrite the whole chain;
// exporting hashes to a SIEM (later) anchors it outside the database.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"licenseforge.io/licenseforge/internal/metrics"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditanchor"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

// PlatformTenant is the reserved tenant row holding the platform chain
// (ADR-0027): events without a tenant, such as logins and platform-admin
// changes. Record and Verify it in a platform-pool transaction
// (store.DB.WithPlatform); the database lets no other login read or append to
// it, and hides it from tenant listings (migration
// 20261104214810_platform_tenant_security.sql).
const PlatformTenant = "tnt_platformaaaaaaaaaaaaaaaaaa"

// ErrBroken means the chain doesn't verify; the error names the first bad seq.
var ErrBroken = errors.New("audit: chain broken")

// Event is what happened. Action is dot-separated snake_case, e.g.
// "signing_key.promote". Details must not contain secrets or PHI.
type Event struct {
	ActorType  auditevent.ActorType
	ActorID    string
	Action     string
	ObjectType string
	ObjectID   string
	Outcome    auditevent.Outcome
	SourceIP   string // from a trusted source only: the connection, or a forwarded header set by a trusted proxy; an invalid value fails Record
	UserAgent  string
	Details    map[string]any
}

var zeroHash = make([]byte, sha256.Size)

// maxUserAgent matches the column; longer values are truncated.
const maxUserAgent = 512

// cleanText makes a client-supplied value storable: valid UTF-8, no NUL (which
// PostgreSQL text refuses), at most n bytes. A hostile header must not be able
// to make the audited action, or the record of a denied attempt, fail.
func cleanText(s string, n int) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, "\uFFFD"), "\x00", "")
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// Record appends e to tenantID's chain in tx, which must be READ COMMITTED
// (the default): the head is read after taking a transaction-scoped advisory
// lock for the tenant, so concurrent writers never fork the chain. The time
// comes from the database clock, so entries written by several server
// instances agree with seq order (AU-8).
func Record(ctx context.Context, tx *ent.Tx, tenantID string, e Event) (*ent.AuditEvent, error) {
	r, err := write(ctx, tx, tenantID, e)
	if err != nil && ctx.Err() == nil { // the caller's action fails with it (AU-5); a client gone away is no audit failure
		chain := "tenant"
		if tenantID == PlatformTenant {
			chain = "platform"
		}
		metrics.AuditWriteFailures.WithLabelValues(chain).Inc()
	}
	return r, err
}

// Lock takes tenantID's chain lock in tx, held until tx ends; Record takes
// it again without waiting (advisory locks are re-entrant). Lock order: a
// transaction that records an entry and also locks signing-key rows takes
// this lock first (signing.Local), because activation records while holding
// it and then share-locks the active key to sign (internal/activations).
func Lock(ctx context.Context, tx *ent.Tx, tenantID string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.audit:' || $1, 0))`, tenantID)
	return err
}

func write(ctx context.Context, tx *ent.Tx, tenantID string, e Event) (*ent.AuditEvent, error) {
	details := []byte("{}")
	if len(e.Details) > 0 {
		var err error
		if details, err = json.Marshal(e.Details); err != nil { // map keys sorted: deterministic
			return nil, fmt.Errorf("audit: details: %w", err)
		}
	}
	if e.SourceIP != "" {
		ip, err := netip.ParseAddr(e.SourceIP)
		if err != nil || ip.Zone() != "" {
			return nil, fmt.Errorf("audit: invalid source IP %q", e.SourceIP)
		}
		e.SourceIP = ip.Unmap().String()
	}
	e.UserAgent = cleanText(e.UserAgent, maxUserAgent)
	if err := Lock(ctx, tx, tenantID); err != nil {
		return nil, err
	}
	// A separate statement, so the clock is read after the lock is held.
	rows, err := tx.QueryContext(ctx, `SELECT current_setting('transaction_isolation'), clock_timestamp()`)
	if err != nil {
		return nil, err
	}
	var isolation string
	var now time.Time
	if !rows.Next() {
		_ = rows.Close()
		return nil, errors.Join(errors.New("audit: lock query returned no row"), rows.Err())
	}
	err = rows.Scan(&isolation, &now)
	if cerr := rows.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if isolation != "read committed" {
		// A snapshot taken before the lock would read a stale head.
		return nil, fmt.Errorf("audit: Record needs a READ COMMITTED transaction, not %s", isolation)
	}
	seq, prev := int64(1), zeroHash
	var head *ent.AuditEvent
	head, err = tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID)).
		Order(ent.Desc(auditevent.FieldSeq)).First(ctx)
	switch {
	case err == nil:
		seq, prev = head.Seq+1, head.Hash
	case !ent.IsNotFound(err):
		return nil, err
	}
	// PostgreSQL stores microseconds; hash what will be read back.
	r := &ent.AuditEvent{
		ID: ids.AuditEvent(), TenantID: tenantID, Seq: seq, OccurredAt: now.UTC().Truncate(time.Microsecond),
		ActorType: e.ActorType, ActorID: nilIfEmpty(e.ActorID), Action: e.Action,
		ObjectType: nilIfEmpty(e.ObjectType), ObjectID: nilIfEmpty(e.ObjectID), Outcome: e.Outcome,
		SourceIP: nilIfEmpty(e.SourceIP), UserAgent: nilIfEmpty(e.UserAgent),
		Details: string(details), PrevHash: prev,
	}
	return tx.AuditEvent.Create().SetID(r.ID).SetTenantID(tenantID).SetSeq(seq).SetOccurredAt(r.OccurredAt).
		SetActorType(r.ActorType).SetNillableActorID(r.ActorID).SetAction(r.Action).
		SetNillableObjectType(r.ObjectType).SetNillableObjectID(r.ObjectID).SetOutcome(r.Outcome).
		SetNillableSourceIP(r.SourceIP).SetNillableUserAgent(r.UserAgent).
		SetDetails(r.Details).SetPrevHash(prev).SetHash(Hash(r)).Save(ctx)
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Hash is the chain hash of e: SHA-256 over a version tag, every field and
// prev_hash, each length-prefixed so no field content can be read two ways.
// NULL fields hash as empty (the database refuses empty strings).
func Hash(e *ent.AuditEvent) []byte {
	h := sha256.New()
	for _, f := range []string{
		"lf-audit-v1", e.ID, e.TenantID, strconv.FormatInt(e.Seq, 10),
		e.OccurredAt.UTC().Format("2006-01-02T15:04:05.000000Z"),
		string(e.ActorType), deref(e.ActorID), e.Action, deref(e.ObjectType), deref(e.ObjectID),
		string(e.Outcome), deref(e.SourceIP), deref(e.UserAgent), e.Details, string(e.PrevHash),
	} {
		_, _ = h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f))))
		_, _ = h.Write([]byte(f))
	}
	return h.Sum(nil)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Head is the last entry of a chain. Export it (SIEM, later) and compare it
// with what Verify returns to detect removed last entries.
type Head struct {
	Seq  int64
	Hash []byte
}

// Runner runs fn in a new read-only transaction on a pool that can read the
// chain, REPEATABLE READ if snapshot: store.DB.ReadPlatform for any chain,
// or store.DB.ReadTenant for a tenant's own.
type Runner func(ctx context.Context, snapshot bool, fn func(*ent.Tx) error) error

// pageSize is Verify's keyset page (ADR-0036); a var so tests can page small.
var pageSize = 1000

// readAnchor returns the chain's effective anchor (ADR-0036): its highest
// audit_anchors row, the seq and hash of the last pruned entry; zero while
// nothing was pruned. A var so tests can simulate a prune moving it.
var readAnchor = func(ctx context.Context, tx *ent.Tx, tenantID string) (Head, error) {
	a, err := tx.AuditAnchor.Query().Where(auditanchor.TenantID(tenantID)).Order(ent.Desc(auditanchor.FieldSeq)).First(ctx)
	if ent.IsNotFound(err) {
		return Head{}, nil
	}
	if err != nil {
		return Head{}, err
	}
	return Head{Seq: a.Seq, Hash: a.Hash}, nil
}

// Verify checks tenantID's chain (ADR-0027, ADR-0036) and returns its head
// (zero for an empty chain). From the anchor (from is zero, or older than the
// anchor) it checks the whole surviving chain: the first entry links to the
// anchor (seq 1 and 32 zero bytes without one) and nothing at or below the
// anchor remains. From a head the caller verified earlier, it checks that
// entry is unchanged and only the entries after it: an incremental check
// costs O(new entries). Keep that head yourself, never in a table a serving
// login can write. Every entry must be the previous seq + 1, link to the
// previous hash and hash correctly; seq is hashed, so a removed or reordered
// entry breaks a link.
//
// Entries are read in keyset pages, one short transaction each; the anchor
// and the first page share one REPEATABLE READ transaction. A break at the
// start or at a page boundary can be a prune that ran meanwhile: Verify then
// re-reads the anchor once and restarts if it moved. Truncation of the last
// entries can't be seen here: compare the head with an exported one.
func Verify(ctx context.Context, run Runner, tenantID string, from Head) (Head, error) {
	h, err := verifyChain(ctx, run, tenantID, from)
	if errors.Is(err, ErrBroken) {
		metrics.AuditVerifyFailures.Inc()
	}
	return h, err
}

func verifyChain(ctx context.Context, run Runner, tenantID string, from Head) (Head, error) {
	for restarted := false; ; restarted = true {
		head, anchor, err := walk(ctx, run, tenantID, from)
		var b boundaryError
		if !errors.As(err, &b) {
			return head, err
		}
		var now Head
		if err := run(ctx, false, func(tx *ent.Tx) error {
			var err error
			now, err = readAnchor(ctx, tx, tenantID)
			return err
		}); err != nil {
			return Head{}, err
		}
		if restarted || now.Seq <= anchor.Seq {
			return Head{}, b.err
		}
	}
}

// boundaryError is a break on the first entry after the start or a page
// boundary, where a concurrent prune could have moved the chain's start.
type boundaryError struct{ err error }

func (b boundaryError) Error() string { return b.err.Error() }
func (b boundaryError) Unwrap() error { return b.err }

func walk(ctx context.Context, run Runner, tenantID string, from Head) (head, anchor Head, err error) {
	var page []*ent.AuditEvent
	err = run(ctx, true, func(tx *ent.Tx) error { // the anchor and the first page from one snapshot
		var err error
		if anchor, err = readAnchor(ctx, tx, tenantID); err != nil {
			return err
		}
		head = anchor
		if from.Seq > anchor.Seq {
			e, err := tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID), auditevent.Seq(from.Seq)).Only(ctx)
			switch {
			case ent.IsNotFound(err):
				return boundaryError{fmt.Errorf("%w: resume head seq %d is gone", ErrBroken, from.Seq)}
			case err != nil:
				return err
			case !bytes.Equal(e.Hash, from.Hash) || !bytes.Equal(e.Hash, Hash(e)):
				return fmt.Errorf("%w: resume head seq %d was modified", ErrBroken, from.Seq)
			}
			head = from
		} else if from.Seq == anchor.Seq && anchor.Seq > 0 && !bytes.Equal(from.Hash, anchor.Hash) {
			return fmt.Errorf("%w: resume head seq %d doesn't match the anchor", ErrBroken, from.Seq)
		}
		if from.Seq <= anchor.Seq && anchor.Seq > 0 { // starting at the anchor
			left, err := tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID), auditevent.SeqLTE(anchor.Seq)).Exist(ctx)
			if err != nil {
				return err
			}
			if left {
				return fmt.Errorf("%w: entries at or below the anchor (seq %d) remain", ErrBroken, anchor.Seq)
			}
		}
		page, err = nextPage(ctx, tx, tenantID, head.Seq)
		return err
	})
	if err != nil {
		return Head{}, anchor, err
	}
	for {
		for i, e := range page {
			prev := head.Hash
			if head.Seq == 0 {
				prev = zeroHash
			}
			if e.Seq != head.Seq+1 || !bytes.Equal(e.PrevHash, prev) {
				err := fmt.Errorf("%w: seq %d doesn't follow seq %d", ErrBroken, e.Seq, head.Seq)
				if i == 0 {
					return Head{}, anchor, boundaryError{err}
				}
				return Head{}, anchor, err
			}
			if !bytes.Equal(e.Hash, Hash(e)) {
				return Head{}, anchor, fmt.Errorf("%w: seq %d was modified", ErrBroken, e.Seq)
			}
			head = Head{Seq: e.Seq, Hash: e.Hash}
		}
		if len(page) < pageSize {
			return head, anchor, nil
		}
		if err := run(ctx, false, func(tx *ent.Tx) error {
			var err error
			page, err = nextPage(ctx, tx, tenantID, head.Seq)
			return err
		}); err != nil {
			return Head{}, anchor, err
		}
	}
}

func nextPage(ctx context.Context, tx *ent.Tx, tenantID string, after int64) ([]*ent.AuditEvent, error) {
	return tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID), auditevent.SeqGT(after)).
		Order(ent.Asc(auditevent.FieldSeq)).Limit(pageSize).All(ctx)
}
