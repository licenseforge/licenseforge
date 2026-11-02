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
	"fmt"
	"log"
	"os"
	"path/filepath"

	atlas "ariga.io/atlas/sql/migrate"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql/schema"

	"github.com/jackc/pgx/v5/stdlib"

	"licenseforge.io/licenseforge/internal/store/ent/migrate"
)

// ent's diff opens the dev database with the "postgres" driver name.
func init() { sql.Register("postgres", stdlib.GetDefaultDriver()) }

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

func diff(ctx context.Context, path, name string) error {
	u, err := devURL()
	if err != nil {
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
	)
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
