package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"licenseforge.io/licenseforge/internal/audit"
)

// The owner-login recovery commands run end to end: their arguments are
// checked before any connection, and each change lands with its audit entry
// on the platform chain.
func TestRecoveryCommands(t *testing.T) {
	ctx := context.Background()
	t.Setenv("LICENSEFORGE_OWNER_DATABASE_URL", env.OwnerURL)
	var out strings.Builder
	for name, run := range map[string]func() error{
		"reset without --yes":   func() error { return adminReset(ctx, nil, &out) },
		"reset with extra args": func() error { return adminReset(ctx, []string{"--yes", "x"}, &out) },
		"remove-sink no name":   func() error { return auditRemoveSink(ctx, nil, &out) },
		"remove-sink unknown":   func() error { return auditRemoveSink(ctx, []string{"--name", "nope"}, &out) },
	} {
		if err := run(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	owner, err := sql.Open("pgx", env.OwnerURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Close() }()
	count := func(action string) (n int) {
		t.Helper()
		if err := owner.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2 AND actor_type = 'system'`,
			audit.PlatformTenant, action).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	resets := count("platform_admin.reset")
	if err := adminReset(ctx, []string{"--yes"}, &out); err != nil || !strings.Contains(out.String(), "platform admin(s) removed") {
		t.Fatalf("reset: %v, %q", err, out.String())
	}
	if count("platform_admin.reset") != resets+1 {
		t.Error("reset not audited")
	}
	var details string
	if err := owner.QueryRowContext(ctx, `SELECT details::text FROM audit_events WHERE tenant_id = $1 AND action = 'platform_admin.reset' ORDER BY seq DESC LIMIT 1`,
		audit.PlatformTenant).Scan(&details); err != nil || !strings.Contains(details, `"db_login"`) || !strings.Contains(details, `"removed_user_ids":[`) {
		t.Errorf("reset details %s, %v", details, err)
	}
	if _, err := owner.ExecContext(ctx, `INSERT INTO audit_export_sinks (id, created_at) VALUES ('cli-siem', now())`); err != nil {
		t.Fatal(err)
	}
	if err := auditRemoveSink(ctx, []string{"--name", "cli-siem"}, &out); err != nil || !strings.Contains(out.String(), "sink cli-siem removed") {
		t.Fatalf("remove-sink: %v, %q", err, out.String())
	}
	if count("audit.export_sink_remove") != 1 {
		t.Error("remove-sink not audited")
	}
}
