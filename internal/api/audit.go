package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"licenseforge.io/licenseforge/internal/api/apigen"
	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// ListAuditEvents pages the tenant's chain by seq (its order, gap-free),
// not by created_at and ID like other lists (ADR-0032): newest first, or
// oldest first from after_seq for export. The cursor carries the direction
// and a seq, nothing else.
func (s *server) ListAuditEvents(ctx context.Context, req apigen.ListAuditEventsRequestObject) (apigen.ListAuditEventsResponseObject, error) {
	q := req.Params
	limit, _, _, err := pageParams(q.Limit, nil, "")
	if err != nil {
		return nil, err
	}
	pg := audit.Page{Limit: limit + 1}
	switch {
	case q.Cursor != nil && q.AfterSeq != nil:
		return nil, &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "Send cursor or after_seq, not both."}
	case q.Cursor != nil:
		var ok bool
		if pg.Asc, pg.Seq, ok = decodeSeqCursor(*q.Cursor); !ok {
			return nil, &problem{status: http.StatusBadRequest, code: "invalid_cursor", detail: "Malformed cursor."}
		}
	case q.AfterSeq != nil:
		if *q.AfterSeq < 0 {
			return nil, &problem{status: http.StatusBadRequest, code: "invalid_request", detail: "after_seq must be 0 or more."}
		}
		pg.Asc, pg.Seq = true, *q.AfterSeq
	}
	rows, err := s.Audit.List(ctx, principal(ctx), pg)
	if err != nil {
		return nil, err
	}
	page := auditPage{Items: []auditEventView{}}
	for i, e := range rows {
		if i == limit {
			c := seqCursor(pg.Asc, rows[i-1].Seq)
			page.NextCursor = &c
			break
		}
		page.Items = append(page.Items, auditView(e))
	}
	return page, nil
}

// auditEventView is apigen.AuditEvent with details as stored, byte for
// byte (the hash covers that text; a decoded map would re-encode it).
// TestAuditEventEndpoints checks it against the spec's fields.
type auditEventView struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	Seq        int64           `json:"seq"`
	OccurredAt string          `json:"occurred_at"` // as hashed (audit.TimeFormat)
	ActorType  string          `json:"actor_type"`
	ActorID    *string         `json:"actor_id"`
	Action     string          `json:"action"`
	ObjectType *string         `json:"object_type"`
	ObjectID   *string         `json:"object_id"`
	Outcome    string          `json:"outcome"`
	SourceIP   *string         `json:"source_ip"`
	UserAgent  *string         `json:"user_agent"`
	Details    json.RawMessage `json:"details"`
	PrevHash   string          `json:"prev_hash"`
	Hash       string          `json:"hash"`
}

type auditPage struct {
	Items      []auditEventView `json:"items"`
	NextCursor *string          `json:"next_cursor,omitempty"`
}

func (p auditPage) VisitListAuditEventsResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(p) // stored details are already escaped as the encoder would: unchanged
}

func auditView(e *ent.AuditEvent) auditEventView {
	return auditEventView{ID: e.ID, TenantID: e.TenantID, Seq: e.Seq, OccurredAt: e.OccurredAt.UTC().Format(audit.TimeFormat), ActorType: string(e.ActorType),
		ActorID: e.ActorID, Action: e.Action, ObjectType: e.ObjectType, ObjectID: e.ObjectID, Outcome: string(e.Outcome),
		SourceIP: e.SourceIP, UserAgent: e.UserAgent, Details: json.RawMessage(e.Details),
		PrevHash: hex.EncodeToString(e.PrevHash), Hash: hex.EncodeToString(e.Hash)}
}

func seqCursor(asc bool, seq int64) string {
	dir := "d"
	if asc {
		dir = "a"
	}
	return base64.RawURLEncoding.EncodeToString([]byte(dir + "." + strconv.FormatInt(seq, 10)))
}

func decodeSeqCursor(c string) (asc bool, seq int64, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	dir, n, found := strings.Cut(string(raw), ".")
	seq, perr := strconv.ParseInt(n, 10, 64)
	return dir == "a", seq, err == nil && found && perr == nil && (dir == "a" && seq >= 0 || dir == "d" && seq > 0)
}
