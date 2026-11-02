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

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
	"licenseforge.io/licenseforge/internal/store/ids"
)

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
	SourceIP   string
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
	rows, err := tx.QueryContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.audit:' || $1, 0))::text,
		current_setting('transaction_isolation'), clock_timestamp()`, tenantID)
	if err != nil {
		return nil, err
	}
	var lock, isolation string
	var now time.Time
	if !rows.Next() {
		_ = rows.Close()
		return nil, errors.Join(errors.New("audit: lock query returned no row"), rows.Err())
	}
	err = rows.Scan(&lock, &isolation, &now)
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

// Verify checks tenantID's whole chain in tx: it starts at seq 1 with the zero
// prev_hash, each prev_hash equals the previous entry's hash and each hash is
// correct. seq is hashed, so a removed or reordered entry breaks a link. It
// returns the head (zero for an empty chain).
//
// ponytail: loads the chain into memory; page by seq when chains get large.
// Retention (later) will start from an exported anchor instead of seq 1.
func Verify(ctx context.Context, tx *ent.Tx, tenantID string) (Head, error) {
	events, err := tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID)).
		Order(ent.Asc(auditevent.FieldSeq)).All(ctx)
	if err != nil {
		return Head{}, err
	}
	for i, e := range events {
		switch {
		case i == 0 && (e.Seq != 1 || !bytes.Equal(e.PrevHash, zeroHash)):
			return Head{}, fmt.Errorf("%w: chain starts at seq %d, not 1", ErrBroken, e.Seq)
		case i > 0 && !bytes.Equal(e.PrevHash, events[i-1].Hash):
			return Head{}, fmt.Errorf("%w: seq %d doesn't link to the previous entry", ErrBroken, e.Seq)
		case !bytes.Equal(e.Hash, Hash(e)):
			return Head{}, fmt.Errorf("%w: seq %d was modified", ErrBroken, e.Seq)
		}
	}
	if len(events) == 0 {
		return Head{}, nil
	}
	last := events[len(events)-1]
	return Head{Seq: last.Seq, Hash: last.Hash}, nil
}
