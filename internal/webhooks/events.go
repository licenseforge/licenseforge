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

// nextEvent returns the seq of the first successful entry after seq in the
// tenant's chain that is an event the endpoint subscribes to, or 0.
func nextEvent(ctx context.Context, tx *ent.Tx, tenantID string, seq int64, events []string) (int64, error) {
	for {
		rows, err := tx.QueryContext(ctx, `SELECT seq, action, details::text FROM audit_events
			WHERE tenant_id = $1 AND seq > $2 AND outcome = 'success' AND action = ANY($3) ORDER BY seq LIMIT 200`, tenantID, seq, pgtype.FlatArray[string](mapped))
		if err != nil {
			return 0, err
		}
		n, found := 0, int64(0)
		for rows.Next() {
			var action, details string
			if err := rows.Scan(&seq, &action, &details); err != nil {
				_ = rows.Close()
				return 0, err
			}
			n++
			if t := EventType(action, details); t != "" && slices.Contains(events, t) {
				found = seq
				break
			}
		}
		if err := rows.Close(); err != nil {
			return 0, err
		}
		if found != 0 || n < 200 {
			return found, nil
		}
	}
}
