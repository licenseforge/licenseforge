package webhooks

import (
	"context"
	"errors"
	"fmt"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store/ent"
)

// The recovery actions (ADR-0044) run under change's locks (the cursor, then
// the endpoint), so a send being recorded finishes first. Enable and the
// skips reset the retry state, so a send recorded later matches nothing
// (the dispatcher pins its writes to the lease, seq and attempts it read);
// Disable leaves the cursor alone, and the dispatcher disables only an
// enabled endpoint. Audited with what they actually did.

// UserDisabled is the reason recorded when a user disables an endpoint.
const UserDisabled = "disabled by a user"

// cursorUpdate moves the cursor (never back) and resets its retry state.
func cursorUpdate(ctx context.Context, tx *ent.Tx, id string, seq int64) error {
	_, err := tx.ExecContext(ctx, `UPDATE webhook_cursors SET seq = GREATEST(seq, $2), attempts = 0, next_attempt_at = NULL
		WHERE endpoint_id = $1`, id, seq)
	return err
}

// cursorSeq reads the cursor's position.
func cursorSeq(ctx context.Context, tx *ent.Tx, id string) (int64, error) {
	e := Endpoint{ID: id}
	err := state(ctx, tx, &e)
	return e.Seq, err
}

// Disable stops deliveries to an enabled endpoint; its position stays.
func (s Service) Disable(ctx context.Context, id string) (Endpoint, error) {
	return s.change(ctx, "webhook.disable", id, func(tx *ent.Tx, row *ent.WebhookEndpoint, _ *audit.Event) error {
		if !row.Enabled {
			return fmt.Errorf("%w: already disabled", ErrState)
		}
		return tx.WebhookEndpoint.UpdateOneID(id).SetEnabled(false).SetDisabledReason(UserDisabled).Exec(ctx)
	})
}

// Enable resumes a disabled endpoint at the event it stopped on, with a
// fresh retry schedule.
func (s Service) Enable(ctx context.Context, id string) (Endpoint, error) {
	return s.change(ctx, "webhook.enable", id, func(tx *ent.Tx, row *ent.WebhookEndpoint, ev *audit.Event) error {
		if row.Enabled {
			return fmt.Errorf("%w: not disabled", ErrState)
		}
		if row.DisabledReason != nil {
			ev.Details["disabled_reason"] = *row.DisabledReason
		}
		if err := tx.WebhookEndpoint.UpdateOneID(id).SetEnabled(true).ClearDisabledReason().Exec(ctx); err != nil {
			return err
		}
		seq, err := cursorSeq(ctx, tx, id)
		if err != nil {
			return err
		}
		return cursorUpdate(ctx, tx, id, seq)
	})
}

// SkipEvent passes the event at seq, which must be the endpoint's next one
// (the one held back): a payload the receiver will never accept. If it was
// delivered meanwhile, or isn't the next event, nothing changes (ErrInvalid
// says which).
func (s Service) SkipEvent(ctx context.Context, id string, seq int64) (Endpoint, error) {
	return s.change(ctx, "webhook.skip_event", id, func(tx *ent.Tx, row *ent.WebhookEndpoint, ev *audit.Event) error {
		ev.Details["requested_seq"] = seq
		cur, err := cursorSeq(ctx, tx, id)
		if err != nil {
			return err
		}
		next, err := nextEvent(ctx, tx, row.TenantID, cur, row.Events)
		if err != nil {
			return err
		}
		if next == 0 || next != seq { // also when it was delivered or passed meanwhile
			return fmt.Errorf("%w: %d isn't the endpoint's next event (delivered meanwhile, or not an event it subscribes to)", ErrState, seq)
		}
		ev.Details["skipped_seq"], ev.Details["from_seq"] = seq, cur // from a cursor below a prune: the passed range
		return cursorUpdate(ctx, tx, id, seq)
	})
}

// SkipToNow passes every event so far: delivery resumes with the next one.
func (s Service) SkipToNow(ctx context.Context, id string) (Endpoint, error) {
	return s.change(ctx, "webhook.skip_to_now", id, func(tx *ent.Tx, row *ent.WebhookEndpoint, ev *audit.Event) error {
		cur, err := cursorSeq(ctx, tx, id)
		if err != nil {
			return err
		}
		var head int64
		rows, err := tx.QueryContext(ctx, `SELECT COALESCE(max(seq), 0) FROM audit_events WHERE tenant_id = $1`, row.TenantID)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := rows.Scan(&head); err != nil {
				_ = rows.Close()
				return err
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return err
		}
		ev.Details["from_seq"], ev.Details["to_seq"] = cur, max(cur, head)
		return cursorUpdate(ctx, tx, id, head)
	})
}
