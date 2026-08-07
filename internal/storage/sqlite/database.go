package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const defaultBusyTimeoutMilliseconds = 5000

// Open creates a configured SQLite connection pool and applies every embedded
// migration before returning it. The caller owns the returned database.
func Open(ctx context.Context, databasePath string) (*sql.DB, error) {
	databasePath = strings.TrimSpace(databasePath)
	if databasePath == "" {
		return nil, fmt.Errorf("open sqlite database: path is required")
	}
	absolutePath, err := filepath.Abs(databasePath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: resolve path: %w", err)
	}

	connectionURL := url.URL{Scheme: "file", Path: absolutePath}
	query := connectionURL.Query()
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", defaultBusyTimeoutMilliseconds))
	query.Add("_pragma", "journal_mode(WAL)")
	connectionURL.RawQuery = query.Encode()

	database, err := sql.Open("sqlite", connectionURL.String())
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	database.SetMaxOpenConns(4)
	database.SetMaxIdleConns(4)

	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("open sqlite database: ping: %w", err)
	}
	if err := Migrate(ctx, database); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}
