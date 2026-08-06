package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

const LatestSchemaVersion = 1

var ErrInvalidSchemaVersion = errors.New("invalid sqlite schema version")

//go:embed migrations/*.sql
var migrationFiles embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

// Migrate applies every embedded migration newer than the database's current
// version. Each migration and its version record commit atomically.
func Migrate(ctx context.Context, database *sql.DB) error {
	if database == nil {
		return errors.New("sqlite migrate: database is nil")
	}
	if _, err := database.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY CHECK (version > 0),
			name TEXT NOT NULL UNIQUE CHECK (length(trim(name)) > 0),
			applied_at TEXT NOT NULL CHECK (length(trim(applied_at)) > 0)
		)
	`); err != nil {
		return fmt.Errorf("sqlite migrate: create schema_migrations: %w", err)
	}

	current, err := SchemaVersion(ctx, database)
	if err != nil {
		return err
	}
	if current > LatestSchemaVersion {
		return fmt.Errorf("%w: database is at version %d, latest supported is %d", ErrInvalidSchemaVersion, current, LatestSchemaVersion)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, item := range migrations {
		if item.version <= current {
			continue
		}
		if err := applyMigration(ctx, database, item); err != nil {
			return err
		}
		current = item.version
	}
	if current != LatestSchemaVersion {
		return fmt.Errorf("%w: migrated to version %d, expected %d", ErrInvalidSchemaVersion, current, LatestSchemaVersion)
	}
	return nil
}

// SchemaVersion returns zero for an uninitialized database.
func SchemaVersion(ctx context.Context, database *sql.DB) (int, error) {
	if database == nil {
		return 0, errors.New("sqlite schema version: database is nil")
	}

	var exists int
	if err := database.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM sqlite_schema
			WHERE type = 'table' AND name = 'schema_migrations'
		)
	`).Scan(&exists); err != nil {
		return 0, fmt.Errorf("sqlite schema version: inspect schema: %w", err)
	}
	if exists == 0 {
		return 0, nil
	}

	var count int
	var current int
	if err := database.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(MAX(version), 0)
		FROM schema_migrations
	`).Scan(&count, &current); err != nil {
		return 0, fmt.Errorf("sqlite schema version: read migrations: %w", err)
	}
	if count != current {
		return 0, fmt.Errorf("%w: migration history has %d records through version %d", ErrInvalidSchemaVersion, count, current)
	}
	return current, nil
}

func applyMigration(ctx context.Context, database *sql.DB, item migration) error {
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("sqlite migrate: begin version %d: %w", item.version, err)
	}
	defer func() { _ = transaction.Rollback() }()

	if _, err := transaction.ExecContext(ctx, item.sql); err != nil {
		return fmt.Errorf("sqlite migrate: apply version %d: %w", item.version, err)
	}
	if _, err := transaction.ExecContext(
		ctx,
		`INSERT INTO schema_migrations (version, name, applied_at)
		 VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))`,
		item.version,
		item.name,
	); err != nil {
		return fmt.Errorf("sqlite migrate: record version %d: %w", item.version, err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("sqlite migrate: commit version %d: %w", item.version, err)
	}
	return nil
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("sqlite migrate: list embedded migrations: %w", err)
	}

	items := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		parts := strings.SplitN(entry.Name(), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("sqlite migrate: invalid migration filename %q", entry.Name())
		}
		version, err := strconv.Atoi(parts[0])
		if err != nil || version < 1 {
			return nil, fmt.Errorf("sqlite migrate: invalid migration version in %q", entry.Name())
		}
		contents, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("sqlite migrate: read %q: %w", entry.Name(), err)
		}
		items = append(items, migration{version: version, name: entry.Name(), sql: string(contents)})
	}

	sort.Slice(items, func(left, right int) bool { return items[left].version < items[right].version })
	for index, item := range items {
		expected := index + 1
		if item.version != expected {
			return nil, fmt.Errorf("%w: migration %q has version %d, expected %d", ErrInvalidSchemaVersion, item.name, item.version, expected)
		}
	}
	if len(items) != LatestSchemaVersion {
		return nil, fmt.Errorf("%w: embedded migration count is %d, latest version is %d", ErrInvalidSchemaVersion, len(items), LatestSchemaVersion)
	}
	return items, nil
}
