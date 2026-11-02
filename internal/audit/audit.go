// Package audit writes and verifies the hash-chained audit log (ADR-0027).
//
// Record runs in the caller's transaction, so an action and its audit entry
// commit or roll back together. Entries of one tenant form a chain: each
// entry's hash covers all its fields and the previous entry's hash, so a
// changed, removed or reordered entry is detected by Verify. Someone who can
// rewrite the whole table can rewrite the whole chain; exporting hashes to a
// SIEM (later) anchors it outside the database.
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
	"time"

	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
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

// Record appends e to tenantID's chain in tx. Concurrent writers for the same
// tenant wait on a transaction-scoped advisory lock, so the chain never forks.
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
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('licenseforge.audit:' || $1, 0))`, tenantID); err != nil {
		return nil, err
	}
	seq, prev := int64(1), zeroHash
	head, err := tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID)).
		Order(ent.Desc(auditevent.FieldSeq)).First(ctx)
	switch {
	case err == nil:
		seq, prev = head.Seq+1, head.Hash
	case !ent.IsNotFound(err):
		return nil, err
	}
	// PostgreSQL stores microseconds; hash what will be read back.
	r := &ent.AuditEvent{
		TenantID: tenantID, Seq: seq, OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		ActorType: e.ActorType, ActorID: nilIfEmpty(e.ActorID), Action: e.Action,
		ObjectType: nilIfEmpty(e.ObjectType), ObjectID: nilIfEmpty(e.ObjectID), Outcome: e.Outcome,
		SourceIP: nilIfEmpty(e.SourceIP), UserAgent: nilIfEmpty(e.UserAgent),
		Details: string(details), PrevHash: prev,
	}
	return tx.AuditEvent.Create().SetTenantID(tenantID).SetSeq(seq).SetOccurredAt(r.OccurredAt).
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
		"lf-audit-v1", e.TenantID, strconv.FormatInt(e.Seq, 10),
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

// Verify checks tenantID's whole chain in tx: each prev_hash equals the
// previous entry's hash and each hash is correct. seq is hashed, so a removed
// or reordered entry breaks a link.
// After retention the first kept entry's prev_hash is the anchor; compare it
// with the exported hash of the entry before it.
//
// ponytail: loads the chain into memory; page by seq when chains get large.
func Verify(ctx context.Context, tx *ent.Tx, tenantID string) error {
	events, err := tx.AuditEvent.Query().Where(auditevent.TenantID(tenantID)).
		Order(ent.Asc(auditevent.FieldSeq)).All(ctx)
	if err != nil {
		return err
	}
	for i, e := range events {
		switch {
		case i > 0 && !bytes.Equal(e.PrevHash, events[i-1].Hash):
			return fmt.Errorf("%w: seq %d doesn't link to the previous entry", ErrBroken, e.Seq)
		case !bytes.Equal(e.Hash, Hash(e)):
			return fmt.Errorf("%w: seq %d was modified", ErrBroken, e.Seq)
		}
	}
	return nil
}
