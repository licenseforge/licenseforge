// Command migrate is a developer tool for versioned migrations (ADR-0008).
// It needs a throwaway PostgreSQL in LICENSEFORGE_DEV_DATABASE_URL (any
// superuser database; `make dev-db` starts one).
//
//	go run ./internal/store/tools/migrate diff <name>  # new migration from schema changes
//	go run ./internal/store/tools/migrate hash         # update atlas.sum after editing SQL by hand
//	go run ./internal/store/tools/migrate check        # fail if schema and migrations drift
package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	atlas "ariga.io/atlas/sql/migrate"
	atlasschema "ariga.io/atlas/sql/schema"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql/schema"

	"github.com/jackc/pgx/v5/stdlib"

	"licenseforge.io/licenseforge/internal/store/ent/migrate"
)

// ent's diff opens the dev database with the "postgres" driver name.
func init() { sql.Register("postgres", cascadeDriver{stdlib.GetDefaultDriver()}) }

// cascadeDriver is pgx with one change, for the throwaway dev database only:
// DROP TABLE gets CASCADE. After replaying the migrations, ent drops every
// table in foreign-key order, but row-level security policies that read other
// tables (ADR-0029) are dependencies too, and plain DROP TABLE refuses them.
type cascadeDriver struct{ driver.Driver }

func (d cascadeDriver) Open(name string) (driver.Conn, error) {
	c, err := d.Driver.Open(name)
	if err != nil {
		return nil, err
	}
	pc, ok := c.(pgxConn)
	if !ok {
		return nil, fmt.Errorf("unexpected driver connection %T", c)
	}
	return cascadeConn{pc}, nil
}

type pgxConn interface {
	driver.Conn
	driver.ExecerContext
	driver.QueryerContext
	driver.ConnBeginTx
	driver.ConnPrepareContext
}

type cascadeConn struct{ pgxConn }

func (c cascadeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(query, "DROP TABLE ") && !strings.HasSuffix(query, " CASCADE") {
		query += " CASCADE"
	}
	return c.pgxConn.ExecContext(ctx, query, args)
}

const dirPath = "internal/store/migrations"

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: migrate diff <name> | hash | check")
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "diff":
		if len(os.Args) != 3 {
			log.Fatal("usage: migrate diff <name>")
		}
		err = diff(ctx, dirPath, os.Args[2])
	case "hash":
		err = hash(dirPath)
	case "check":
		err = check(ctx)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Fatal(err)
	}
}

func devURL() (string, error) {
	u := os.Getenv("LICENSEFORGE_DEV_DATABASE_URL")
	if u == "" {
		return "", fmt.Errorf("set LICENSEFORGE_DEV_DATABASE_URL (see `make dev-db`)")
	}
	return u, nil
}

// ensureGroupRoles creates the cluster-wide group roles the migrations grant
// to and write policies for (ADR-0009), so the dev database can replay them.
func ensureGroupRoles(ctx context.Context, u string) error {
	db, err := sql.Open("postgres", u)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	_, err = db.ExecContext(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'licenseforge_app') THEN CREATE ROLE licenseforge_app NOLOGIN; END IF;
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'licenseforge_platform') THEN CREATE ROLE licenseforge_platform NOLOGIN; END IF;
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'licenseforge_identity') THEN CREATE ROLE licenseforge_identity NOLOGIN; END IF;
	END $$`)
	return err
}

func diff(ctx context.Context, path, name string) error {
	u, err := devURL()
	if err != nil {
		return err
	}
	if err := ensureGroupRoles(ctx, u); err != nil {
		return err
	}
	dir, err := atlas.NewLocalDir(path)
	if err != nil {
		return err
	}
	return migrate.NamedDiff(ctx, u, name,
		schema.WithDir(dir),
		schema.WithMigrationMode(schema.ModeReplay),
		schema.WithDialect(dialect.Postgres),
		schema.WithFormatter(atlas.DefaultFormatter),
		schema.WithDiffHook(keepSameTenantFKs),
	)
}

// sameTenantSuffix marks hand-written composite foreign keys (tenant_id, x_id)
// that stop a row from referencing another tenant's row (foreign key checks
// bypass row-level security). ent can't model them, so the diff must not drop them.
const sameTenantSuffix = "_same_tenant"

func keepSameTenantFKs(next schema.Differ) schema.Differ {
	return schema.DiffFunc(func(current, desired *atlasschema.Schema) ([]atlasschema.Change, error) {
		changes, err := next.Diff(current, desired)
		if err != nil {
			return nil, err
		}
		var out []atlasschema.Change
		for _, c := range changes {
			if m, ok := c.(*atlasschema.ModifyTable); ok {
				var kept []atlasschema.Change
				for _, tc := range m.Changes {
					if d, ok := tc.(*atlasschema.DropForeignKey); ok && strings.HasSuffix(d.F.Symbol, sameTenantSuffix) {
						continue
					}
					kept = append(kept, tc)
				}
				if len(kept) == 0 {
					continue
				}
				m.Changes = kept
			}
			out = append(out, c)
		}
		return out, nil
	})
}

func hash(path string) error {
	dir, err := atlas.NewLocalDir(path)
	if err != nil {
		return err
	}
	sum, err := dir.Checksum()
	if err != nil {
		return err
	}
	return atlas.WriteSumFile(dir, sum)
}

// check replays the migrations into a copy and fails if the ent schema would
// need a new migration.
func check(ctx context.Context) error {
	tmp, err := os.MkdirTemp("", "lf-migrations-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dirPath, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tmp, e.Name()), b, 0o644); err != nil {
			return err
		}
	}
	if err := diff(ctx, tmp, "drift"); err != nil {
		return err
	}
	after, err := os.ReadDir(tmp)
	if err != nil {
		return err
	}
	if len(after) != len(entries) {
		return fmt.Errorf("ent schema and %s differ; run: go run ./internal/store/tools/migrate diff <name>", dirPath)
	}
	return nil
}
