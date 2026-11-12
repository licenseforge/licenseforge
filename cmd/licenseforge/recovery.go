package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"licenseforge.io/licenseforge/internal/audit"
	"licenseforge.io/licenseforge/internal/store"
	"licenseforge.io/licenseforge/internal/store/ent"
	"licenseforge.io/licenseforge/internal/store/ent/auditevent"
)

// Operator recovery commands on the owner login (LICENSEFORGE_OWNER_DATABASE_URL),
// run by hand like `migrate`: ways out of states the product can't leave by
// itself. Each is audited on the platform chain as the system, via the CLI.

// adminReset removes every platform admin (ADR-0031's recovery when no admin
// can sign in): the next sign-in matching LICENSEFORGE_BOOTSTRAP_ADMIN
// becomes the platform admin again.
func adminReset(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("admin reset", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "confirm: every platform admin loses the role until the bootstrap admin signs in")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*yes || fs.NArg() > 0 {
		return errors.New("admin reset: removes every platform admin; the next sign-in matching LICENSEFORGE_BOOTSTRAP_ADMIN becomes the platform admin. Run with --yes, and nothing else")
	}
	o, err := openOwner(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = o.Close() }()
	removed, err := o.ResetPlatformAdmins(ctx, func(tx *ent.Tx, removed []string) error {
		_, err := audit.Record(ctx, tx, audit.PlatformTenant, audit.Event{ActorType: auditevent.ActorTypeSystem,
			Action: "platform_admin.reset", ObjectType: "platform_admin", Outcome: auditevent.OutcomeSuccess,
			Details: map[string]any{"via": "cli", "removed_user_ids": removed}})
		return err
	})
	if err != nil {
		return fmt.Errorf("admin reset: %w", err)
	}
	_, err = fmt.Fprintf(out, "%d platform admin(s) removed; the next sign-in matching LICENSEFORGE_BOOTSTRAP_ADMIN becomes the platform admin\n", len(removed))
	return err
}

// auditRemoveSink unregisters a SIEM sink that is no longer exported, so
// audit retention stops waiting for it (ADR-0036).
func auditRemoveSink(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit remove-sink", flag.ContinueOnError)
	name := fs.String("name", "", "the sink's name, as configured (audit.export[].name) (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || fs.NArg() > 0 {
		return errors.New("audit remove-sink: --name is required, and nothing else")
	}
	o, err := openOwner(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = o.Close() }()
	err = o.RemoveExportSink(ctx, *name, func(tx *ent.Tx, cursors int) error {
		_, err := audit.Record(ctx, tx, audit.PlatformTenant, audit.Event{ActorType: auditevent.ActorTypeSystem,
			Action: "audit.export_sink_remove", ObjectType: "audit_export_sink", ObjectID: *name, Outcome: auditevent.OutcomeSuccess,
			Details: map[string]any{"via": "cli", "cursors_dropped": cursors}})
		return err
	})
	if errors.Is(err, store.ErrNoSuchSink) {
		return fmt.Errorf("audit remove-sink: no registered sink %q", *name)
	}
	if err != nil {
		return fmt.Errorf("audit remove-sink: %w", err)
	}
	_, err = fmt.Fprintf(out, "sink %s removed: audit retention no longer waits for it. A server still configured with it registers it again at start.\n", *name)
	return err
}

func openOwner(ctx context.Context) (*store.Owner, error) {
	dsn, err := mustEnv("LICENSEFORGE_OWNER_DATABASE_URL")
	if err != nil {
		return nil, err
	}
	return store.OpenOwner(ctx, dsn)
}
