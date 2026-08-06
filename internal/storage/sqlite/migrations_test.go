package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

const (
	testDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testTime   = "2026-08-06T12:00:00Z"
)

func TestSchemaVersionReturnsZeroBeforeInitialization(t *testing.T) {
	t.Parallel()

	database := openTestDatabase(t)
	version, err := SchemaVersion(context.Background(), database)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if version != 0 {
		t.Fatalf("schema version = %d, want 0", version)
	}
}

func TestMigrateEmptyDatabaseAndReportVersion(t *testing.T) {
	t.Parallel()

	database := openTestDatabase(t)
	ctx := context.Background()
	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("migrate empty database: %v", err)
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatalf("migrate already current database: %v", err)
	}

	version, err := SchemaVersion(ctx, database)
	if err != nil {
		t.Fatalf("schema version: %v", err)
	}
	if version != LatestSchemaVersion {
		t.Fatalf("schema version = %d, want %d", version, LatestSchemaVersion)
	}

	wantTables := []string{"action_requests", "decisions", "policy_effects", "schema_migrations"}
	for _, table := range wantTables {
		var exists int
		if err := database.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?
			)
		`, table).Scan(&exists); err != nil {
			t.Fatalf("inspect table %s: %v", table, err)
		}
		if exists != 1 {
			t.Errorf("table %s was not created", table)
		}
	}

	var migrationCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if migrationCount != LatestSchemaVersion {
		t.Fatalf("migration count = %d, want %d", migrationCount, LatestSchemaVersion)
	}
}

func TestMigrateRejectsDatabaseNewerThanBinary(t *testing.T) {
	t.Parallel()

	database := openTestDatabase(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			applied_at TEXT NOT NULL
		);
		INSERT INTO schema_migrations (version, name, applied_at)
		VALUES (1, '0001.sql', ?), (2, '0002.sql', ?)
	`, testTime, testTime); err != nil {
		t.Fatalf("seed newer schema: %v", err)
	}

	if err := Migrate(ctx, database); !errors.Is(err, ErrInvalidSchemaVersion) {
		t.Fatalf("migrate error = %v, want %v", err, ErrInvalidSchemaVersion)
	}
}

func TestActionRequestConstraints(t *testing.T) {
	t.Parallel()

	database := migratedTestDatabase(t)
	ctx := context.Background()
	insertActionRequest(t, database, "runtime_1", "request_1", testDigest)

	if _, err := database.ExecContext(ctx, actionRequestInsertSQL,
		"runtime_1", "request_1", testDigest, normalizedActionJSON, testTime,
	); err == nil {
		t.Fatal("expected duplicate runtime/request to be rejected")
	}
	insertActionRequest(t, database, "runtime_2", "request_1", testDigest)

	if _, err := database.ExecContext(ctx, actionRequestInsertSQL,
		"runtime_1", "request_bad_digest", "sha256:not-a-digest", normalizedActionJSON, testTime,
	); err == nil {
		t.Fatal("expected invalid action digest to be rejected")
	}
	if _, err := database.ExecContext(ctx, actionRequestInsertSQL,
		"runtime_1", "request_bad_json", testDigest, `{"type":`, testTime,
	); err == nil {
		t.Fatal("expected invalid normalized action JSON to be rejected")
	}
	if _, err := database.ExecContext(ctx, actionRequestInsertSQL,
		"runtime_1", "request_missing_fields", testDigest, `{}`, testTime,
	); err == nil {
		t.Fatal("expected normalized action with missing protected fields to be rejected")
	}
	if _, err := database.ExecContext(ctx, actionRequestInsertSQL,
		"runtime_other", "request_runtime_mismatch", testDigest, normalizedActionJSON, testTime,
	); err == nil {
		t.Fatal("expected authenticated runtime/action runtime mismatch to be rejected")
	}
	withRawPayload := strings.Replace(
		normalizedActionJSON,
		`"payload":{"digest":`,
		`"payload":{"content":"raw email body","digest":`,
		1,
	)
	if _, err := database.ExecContext(ctx, actionRequestInsertSQL,
		"runtime_1", "request_raw_payload", testDigest, withRawPayload, testTime,
	); err == nil {
		t.Fatal("expected normalized action containing raw payload content to be rejected")
	}
}

func TestDecisionConstraints(t *testing.T) {
	t.Parallel()

	database := migratedTestDatabase(t)
	ctx := context.Background()
	insertActionRequest(t, database, "runtime_1", "request_allow", testDigest)
	insertDecision(t, database, "decision_allow", "runtime_1", "request_allow", "ALLOW", `[]`, `[]`)

	insertActionRequest(t, database, "runtime_1", "request_bad_allow", testDigest)
	if _, err := database.ExecContext(ctx, decisionInsertSQL,
		"decision_bad_allow", "runtime_1", "request_bad_allow", "ALLOW",
		`["EXTERNAL_DESTINATION"]`, `[]`, "embedded-mvp-v1", `[]`, testTime,
	); err == nil {
		t.Fatal("expected ALLOW with a reason to be rejected")
	}

	insertActionRequest(t, database, "runtime_1", "request_approval", testDigest)
	insertDecision(
		t,
		database,
		"decision_approval",
		"runtime_1",
		"request_approval",
		"DENY",
		`["DELEGATOR_APPROVAL_REQUIRED","EXTERNAL_DESTINATION"]`,
		`["REQUIRE_APPROVAL"]`,
	)

	insertActionRequest(t, database, "runtime_1", "request_bad_action", testDigest)
	if _, err := database.ExecContext(ctx, decisionInsertSQL,
		"decision_bad_action", "runtime_1", "request_bad_action", "DENY",
		`["DELEGATOR_APPROVAL_REQUIRED"]`, `["CREATE_SAFETY_REVIEW"]`,
		"embedded-mvp-v1", `[]`, testTime,
	); err == nil {
		t.Fatal("expected unsupported public required action to be rejected")
	}

	insertActionRequest(t, database, "runtime_1", "request_missing_action", testDigest)
	if _, err := database.ExecContext(ctx, decisionInsertSQL,
		"decision_missing_action", "runtime_1", "request_missing_action", "DENY",
		`["DELEGATOR_APPROVAL_REQUIRED"]`, `[]`,
		"embedded-mvp-v1", `[]`, testTime,
	); err == nil {
		t.Fatal("expected delegator approval reason without required action to be rejected")
	}

	insertActionRequest(t, database, "runtime_1", "request_missing_reason", testDigest)
	if _, err := database.ExecContext(ctx, decisionInsertSQL,
		"decision_missing_reason", "runtime_1", "request_missing_reason", "DENY",
		`["EXTERNAL_DESTINATION"]`, `["REQUIRE_APPROVAL"]`,
		"embedded-mvp-v1", `[]`, testTime,
	); err == nil {
		t.Fatal("expected required approval without delegator approval reason to be rejected")
	}

	insertActionRequest(t, database, "runtime_1", "request_empty_deny", testDigest)
	if _, err := database.ExecContext(ctx, decisionInsertSQL,
		"decision_empty_deny", "runtime_1", "request_empty_deny", "DENY",
		`[]`, `[]`, "embedded-mvp-v1", `[]`, testTime,
	); err == nil {
		t.Fatal("expected DENY without a reason to be rejected")
	}

	if _, err := database.ExecContext(ctx, decisionInsertSQL,
		"decision_missing_request", "runtime_1", "request_missing", "DENY",
		`["ACTOR_NOT_AUTHORIZED"]`, `[]`, "embedded-mvp-v1", `[]`, testTime,
	); err == nil {
		t.Fatal("expected decision without an action request to be rejected")
	}
}

func TestPolicyEffectOutboxConstraintsAndDispatchIndex(t *testing.T) {
	t.Parallel()

	database := migratedTestDatabase(t)
	ctx := context.Background()
	insertActionRequest(t, database, "runtime_1", "request_1", testDigest)
	insertDecision(t, database, "decision_1", "runtime_1", "request_1", "ALLOW", `[]`, `[]`)

	if _, err := database.ExecContext(ctx, policyEffectInsertSQL,
		"effect_1", "decision_1", `{"priority":"HIGH","evidenceRefs":["message_1"]}`,
		"decision_1:CREATE_SAFETY_REVIEW", "PENDING", 0, nil, nil, testTime, testTime, nil,
	); err != nil {
		t.Fatalf("insert policy effect: %v", err)
	}
	if _, err := database.ExecContext(ctx, policyEffectInsertSQL,
		"effect_2", "decision_1", `{"priority":"HIGH","evidenceRefs":[]}`,
		"decision_1:CREATE_SAFETY_REVIEW", "PENDING", 0, nil, nil, testTime, testTime, nil,
	); err == nil {
		t.Fatal("expected duplicate effect idempotency key to be rejected")
	}
	if _, err := database.ExecContext(ctx, policyEffectInsertSQL,
		"effect_bad_status", "decision_1", `{}`, "effect_bad_status", "QUEUED", 0,
		nil, nil, testTime, testTime, nil,
	); err == nil {
		t.Fatal("expected unsupported dispatch status to be rejected")
	}
	if _, err := database.ExecContext(ctx, policyEffectInsertSQL,
		"effect_bad_success", "decision_1", `{}`, "effect_bad_success", "SUCCEEDED", 1,
		nil, nil, testTime, testTime, nil,
	); err == nil {
		t.Fatal("expected SUCCEEDED without dispatched_at to be rejected")
	}

	var indexSQL string
	if err := database.QueryRowContext(ctx, `
		SELECT sql FROM sqlite_schema
		WHERE type = 'index' AND name = 'idx_policy_effects_dispatchable'
	`).Scan(&indexSQL); err != nil {
		t.Fatalf("read dispatch index: %v", err)
	}
	if !strings.Contains(indexSQL, "WHERE dispatch_status IN ('PENDING', 'FAILED')") {
		t.Fatalf("dispatch index is not partial for dispatchable rows: %s", indexSQL)
	}
}

func TestLedgerRecordsCanBeReconstructedWithoutRawPayloadColumns(t *testing.T) {
	t.Parallel()

	database := migratedTestDatabase(t)
	ctx := context.Background()
	insertActionRequest(t, database, "runtime_1", "request_1", testDigest)
	insertDecision(
		t,
		database,
		"decision_1",
		"runtime_1",
		"request_1",
		"DENY",
		`["DELEGATOR_APPROVAL_REQUIRED","EXTERNAL_DESTINATION"]`,
		`["REQUIRE_APPROVAL"]`,
	)
	if _, err := database.ExecContext(ctx, policyEffectInsertSQL,
		"effect_1", "decision_1", `{"priority":"HIGH","evidenceRefs":["message_1"]}`,
		"decision_1:CREATE_SAFETY_REVIEW", "PENDING", 0, nil, nil, testTime, testTime, nil,
	); err != nil {
		t.Fatalf("insert policy effect: %v", err)
	}

	var actionJSON string
	var reasonsJSON string
	var requiredActionsJSON string
	var matchedRulesJSON string
	var effectContextJSON string
	if err := database.QueryRowContext(ctx, `
		SELECT
			a.normalized_action_json,
			d.reason_codes_json,
			d.required_action_types_json,
			d.matched_rule_ids_json,
			e.effect_context_json
		FROM action_requests AS a
		JOIN decisions AS d
			ON d.runtime_id = a.runtime_id AND d.request_id = a.request_id
		JOIN policy_effects AS e ON e.decision_id = d.decision_id
		WHERE a.runtime_id = ? AND a.request_id = ?
	`, "runtime_1", "request_1").Scan(
		&actionJSON,
		&reasonsJSON,
		&requiredActionsJSON,
		&matchedRulesJSON,
		&effectContextJSON,
	); err != nil {
		t.Fatalf("read ledger records: %v", err)
	}
	for name, value := range map[string]string{
		"action":           actionJSON,
		"reasons":          reasonsJSON,
		"required actions": requiredActionsJSON,
		"matched rules":    matchedRulesJSON,
		"effect context":   effectContextJSON,
	} {
		var decoded any
		if err := json.Unmarshal([]byte(value), &decoded); err != nil {
			t.Errorf("decode %s: %v", name, err)
		}
	}

	rows, err := database.QueryContext(ctx, `PRAGMA table_info(action_requests)`)
	if err != nil {
		t.Fatalf("inspect action request columns: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notNull int
		var defaultValue sql.NullString
		var primaryKey int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatalf("scan action request column: %v", err)
		}
		lowerName := strings.ToLower(name)
		for _, forbidden := range []string{"raw", "body", "content", "payload_bytes"} {
			if strings.Contains(lowerName, forbidden) {
				t.Errorf("action_requests contains raw payload-like column %q", name)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate action request columns: %v", err)
	}
}

func TestRuntimeRequestLookupKeysAreIndexed(t *testing.T) {
	t.Parallel()

	database := migratedTestDatabase(t)
	assertTableHasKeyIndex(t, database, "action_requests")
	assertTableHasKeyIndex(t, database, "decisions")
}

const normalizedActionJSON = `{
    "type":"EXTERNAL_SEND",
    "requestedAt":"2026-08-06T12:00:00Z",
    "actor":{"agentId":"agent_1","runtimeId":"runtime_1"},
    "delegation":{"delegationId":"delegation_1","delegator":{"type":"USER","id":"user_1"}},
    "target":{"resourceType":"EMAIL_DRAFT","resourceId":"draft_1"},
    "parameters":{"destinationScope":"EXTERNAL","recipients":["customer@example.com"]},
    "payload":{"digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111"},
    "authorizationEvidence":[]
}`

const actionRequestInsertSQL = `
	INSERT INTO action_requests (
		runtime_id, request_id, action_digest, action_type,
		action_schema_version, normalized_action_json, created_at
	) VALUES (?, ?, ?, 'EXTERNAL_SEND', 1, ?, ?)
`

const decisionInsertSQL = `
	INSERT INTO decisions (
		decision_id, runtime_id, request_id, decision_type, reason_codes_json,
		required_action_types_json, policy_version, matched_rule_ids_json, evaluated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`

const policyEffectInsertSQL = `
	INSERT INTO policy_effects (
		effect_id, decision_id, effect_type, effect_context_json, idempotency_key,
		dispatch_status, attempt_count, next_attempt_at, last_error,
		created_at, updated_at, dispatched_at
	) VALUES (?, ?, 'CREATE_SAFETY_REVIEW', ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

func openTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.sqlite")
	dsn := (&url.URL{Scheme: "file", Path: path}).String() +
		"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite database: %v", err)
	}
	database.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = database.Close() })
	if err := database.Ping(); err != nil {
		t.Fatalf("ping sqlite database: %v", err)
	}
	return database
}

func migratedTestDatabase(t *testing.T) *sql.DB {
	t.Helper()
	database := openTestDatabase(t)
	if err := Migrate(context.Background(), database); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	return database
}

func insertActionRequest(t *testing.T, database *sql.DB, runtimeID, requestID, digest string) {
	t.Helper()
	actionJSON := strings.Replace(normalizedActionJSON, `"runtimeId":"runtime_1"`, `"runtimeId":"`+runtimeID+`"`, 1)
	if _, err := database.ExecContext(
		context.Background(),
		actionRequestInsertSQL,
		runtimeID,
		requestID,
		digest,
		actionJSON,
		testTime,
	); err != nil {
		t.Fatalf("insert action request %s/%s: %v", runtimeID, requestID, err)
	}
}

func insertDecision(
	t *testing.T,
	database *sql.DB,
	decisionID string,
	runtimeID string,
	requestID string,
	decisionType string,
	reasonsJSON string,
	requiredActionsJSON string,
) {
	t.Helper()
	if _, err := database.ExecContext(
		context.Background(),
		decisionInsertSQL,
		decisionID,
		runtimeID,
		requestID,
		decisionType,
		reasonsJSON,
		requiredActionsJSON,
		"embedded-mvp-v1",
		`["mvp.test-rule"]`,
		testTime,
	); err != nil {
		t.Fatalf("insert decision %s: %v", decisionID, err)
	}
}

func assertTableHasKeyIndex(t *testing.T, database *sql.DB, table string) {
	t.Helper()
	rows, err := database.QueryContext(context.Background(), `PRAGMA index_list(`+table+`)`)
	if err != nil {
		t.Fatalf("inspect indexes for %s: %v", table, err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var sequence int
		var name string
		var unique int
		var origin string
		var partial int
		if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan index for %s: %v", table, err)
		}
		if unique == 1 && (origin == "pk" || origin == "u") {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate indexes for %s: %v", table, err)
	}
	if !found {
		t.Errorf("table %s has no primary or unique lookup index", table)
	}
}
