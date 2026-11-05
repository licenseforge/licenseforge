package audit

import (
	"context"
	"errors"

	"licenseforge.io/licenseforge/internal/authz"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// By returns an event of p (a user or an API token) doing action on an
// object; set Outcome (and Details) before recording it.
func By(p authz.Principal, action, objectType, objectID string) Event {
	actor := auditevent.ActorTypeUser
	if p.Kind == authz.Token {
		actor = auditevent.ActorTypeToken
	}
	return Event{ActorType: actor, ActorID: p.ID, Action: action, ObjectType: objectType, ObjectID: objectID}
}

// Refused records a refused attempt in its own transaction (the attempt's
// rolled back, ADR-0027) and returns err: denied for authz.ErrDenied,
// failure for an error matching one of failures. Any other error is an
// outage, not an attempt: returned unrecorded.
func Refused(ctx context.Context, db *store.DB, tenantID string, ev Event, err error, failures ...error) error {
	switch {
	case errors.Is(err, authz.ErrDenied):
		ev.Outcome = auditevent.OutcomeDenied
	case func() bool {
		for _, f := range failures {
			if errors.Is(err, f) {
				return true
			}
		}
		return false
	}():
		ev.Outcome = auditevent.OutcomeFailure
	default:
		return err
	}
	if rerr := db.WithTenant(ctx, tenantID, func(tx *ent.Tx) error {
		_, err := Record(ctx, tx, tenantID, ev)
		return err
	}); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}
