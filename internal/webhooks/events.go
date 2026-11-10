package webhooks

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/jackc/pgx/v5/pgtype"

	"licenseforge.io/licenseforge/internal/store/ent"
)

// mapped are the audit actions that can become events (ADR-0044).
var mapped = []string{"license.issue", "license.revoke", "license.suspend", "license.reinstate",
	"activation.create", "activation.offline", "activation.deactivate", "activation.offline_return"}

// EventType is the event a successful audit entry becomes, or "" (ADR-0044's
// mapping). details is the entry's JSON details.
func EventType(action, details string) string {
	switch action {
	case "license.issue":
		return "license.issued"
	case "license.revoke":
		return "license.revoked"
	case "license.suspend":
		return "license.suspended"
	case "license.reinstate":
		return "license.reinstated"
	case "activation.create": // recorded only for a new seat
		return "activation.created"
	case "activation.offline": // a new seat, not a renewal
		var d struct {
			NewSeat bool `json:"new_seat"`
		}
		if json.Unmarshal([]byte(details), &d) == nil && d.NewSeat {
			return "activation.created"
		}
	case "activation.deactivate", "activation.offline_return":
		return "activation.deactivated"
	}
	return ""
}

// actionsFor lists the audit actions that become one of events.
func actionsFor(events []string) []string {
	var out []string
	for _, a := range mapped {
		if slices.Contains(events, EventType(a, `{"new_seat": true}`)) {
			out = append(out, a)
		}
	}
	return out
}

// nextEvent returns the seq of the first successful entry after seq in the
// tenant's chain that is an event the endpoint subscribes to, or 0. One
// indexed query (EventType's rules in SQL), so it is cheap under the
// endpoint's locks however long the chain.
func nextEvent(ctx context.Context, tx *ent.Tx, tenantID string, seq int64, events []string) (int64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT seq FROM audit_events WHERE tenant_id = $1 AND seq > $2 AND outcome = 'success'
		AND action = ANY($3) AND (action <> 'activation.offline' OR details->>'new_seat' = 'true') ORDER BY seq LIMIT 1`,
		tenantID, seq, pgtype.FlatArray[string](actionsFor(events)))
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var next int64
	if rows.Next() {
		if err := rows.Scan(&next); err != nil {
			return 0, err
		}
	}
	return next, rows.Err()
}
