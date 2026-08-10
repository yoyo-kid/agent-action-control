package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

var _ application.DecisionLedger = (*DecisionLedger)(nil)

type DecisionLedger struct {
	database *sql.DB
}

func NewDecisionLedger(database *sql.DB) (*DecisionLedger, error) {
	if database == nil {
		return nil, fmt.Errorf("%w: sqlite database is required", application.ErrInvalidInput)
	}
	return &DecisionLedger{database: database}, nil
}

func (ledger *DecisionLedger) GetEvaluationByRequestID(
	ctx context.Context,
	runtimeID string,
	requestID string,
) (*application.StoredEvaluation, error) {
	if ledger == nil || ledger.database == nil {
		return nil, fmt.Errorf("%w: sqlite ledger is not initialized", application.ErrLedgerFailure)
	}
	runtimeID = strings.TrimSpace(runtimeID)
	requestID = strings.TrimSpace(requestID)
	if runtimeID == "" || requestID == "" {
		return nil, fmt.Errorf("%w: runtime ID and request ID are required", application.ErrInvalidInput)
	}

	var storedDigest string
	var actionJSON []byte
	var decisionID string
	var decisionType string
	var reasonsJSON []byte
	var requiredActionsJSON []byte
	var policyVersion string
	var matchedRuleIDsJSON []byte
	var evaluatedAt string
	err := ledger.database.QueryRowContext(ctx, `
		SELECT
			a.action_digest,
			a.normalized_action_json,
			d.decision_id,
			d.decision_type,
			d.reason_codes_json,
			d.required_action_types_json,
			d.policy_version,
			d.matched_rule_ids_json,
			d.evaluated_at
		FROM action_requests AS a
		JOIN decisions AS d
			ON d.runtime_id = a.runtime_id AND d.request_id = a.request_id
		WHERE a.runtime_id = ? AND a.request_id = ?
	`, runtimeID, requestID).Scan(
		&storedDigest,
		&actionJSON,
		&decisionID,
		&decisionType,
		&reasonsJSON,
		&requiredActionsJSON,
		&policyVersion,
		&matchedRuleIDsJSON,
		&evaluatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: runtime %q request %q", application.ErrEvaluationNotFound, runtimeID, requestID)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read evaluation: %w", application.ErrLedgerFailure, err)
	}

	action, err := decodeAction(actionJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: reconstruct action: %v", application.ErrLedgerFailure, err)
	}
	digest, err := domain.ParseActionDigest(storedDigest)
	if err != nil {
		return nil, fmt.Errorf("%w: reconstruct digest: %v", application.ErrLedgerFailure, err)
	}
	computedDigest, err := domain.ComputeActionDigest(action)
	if err != nil || computedDigest != digest {
		return nil, fmt.Errorf("%w: stored action does not match its digest", application.ErrLedgerFailure)
	}
	decision, err := decodeDecision(decisionType, reasonsJSON, requiredActionsJSON)
	if err != nil {
		return nil, fmt.Errorf("%w: reconstruct decision: %v", application.ErrLedgerFailure, err)
	}
	var matchedRuleIDs []string
	if err := json.Unmarshal(matchedRuleIDsJSON, &matchedRuleIDs); err != nil {
		return nil, fmt.Errorf("%w: reconstruct matched rules: %v", application.ErrLedgerFailure, err)
	}
	evaluatedTime, err := time.Parse(time.RFC3339Nano, evaluatedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: reconstruct evaluated time: %v", application.ErrLedgerFailure, err)
	}

	return &application.StoredEvaluation{
		RuntimeID: runtimeID,
		RequestID: requestID,
		Action:    action,
		Decision: application.DecisionRecord{
			DecisionID:     decisionID,
			Decision:       decision,
			ActionDigest:   digest,
			PolicyVersion:  policyVersion,
			MatchedRuleIDs: append([]string(nil), matchedRuleIDs...),
			EvaluatedAt:    evaluatedTime.UTC(),
		},
	}, nil
}

func (ledger *DecisionLedger) CommitEvaluation(
	ctx context.Context,
	commit application.EvaluationCommit,
) (application.DecisionRecord, error) {
	if ledger == nil || ledger.database == nil {
		return application.DecisionRecord{}, fmt.Errorf("%w: sqlite ledger is not initialized", application.ErrLedgerFailure)
	}
	encoded, err := encodeEvaluation(commit)
	if err != nil {
		return application.DecisionRecord{}, err
	}

	existing, err := ledger.GetEvaluationByRequestID(ctx, commit.RuntimeID, commit.RequestID)
	if err == nil {
		return resolveExisting(existing, commit.ActionDigest)
	}
	if !errors.Is(err, application.ErrEvaluationNotFound) {
		return application.DecisionRecord{}, err
	}

	transaction, err := ledger.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return application.DecisionRecord{}, fmt.Errorf("%w: begin evaluation commit: %w", application.ErrLedgerFailure, err)
	}
	defer func() { _ = transaction.Rollback() }()

	inserted, err := insertCommittedActionRequest(ctx, transaction, commit, encoded.actionJSON)
	if err != nil {
		_ = transaction.Rollback()
		if resolved, resolutionErr := ledger.resolveCommitRace(ctx, commit); resolutionErr == nil {
			return resolved, nil
		}
		return application.DecisionRecord{}, fmt.Errorf("%w: insert action request: %w", application.ErrLedgerFailure, err)
	}
	if !inserted {
		_ = transaction.Rollback()
		return ledger.resolveCommitRace(ctx, commit)
	}

	if err := insertCommittedDecision(ctx, transaction, commit, encoded); err != nil {
		return application.DecisionRecord{}, fmt.Errorf("%w: insert decision: %w", application.ErrLedgerFailure, err)
	}
	if err := insertPolicyEffects(ctx, transaction, commit, encoded.effects); err != nil {
		return application.DecisionRecord{}, fmt.Errorf("%w: insert policy effects: %w", application.ErrLedgerFailure, err)
	}
	if err := transaction.Commit(); err != nil {
		if resolved, resolutionErr := ledger.resolveCommitRace(ctx, commit); resolutionErr == nil {
			return resolved, nil
		}
		return application.DecisionRecord{}, fmt.Errorf("%w: commit evaluation: %w", application.ErrLedgerFailure, err)
	}
	return decisionRecordFromCommit(commit), nil
}

func (ledger *DecisionLedger) resolveCommitRace(
	ctx context.Context,
	commit application.EvaluationCommit,
) (application.DecisionRecord, error) {
	existing, err := ledger.GetEvaluationByRequestID(ctx, commit.RuntimeID, commit.RequestID)
	if err != nil {
		return application.DecisionRecord{}, err
	}
	return resolveExisting(existing, commit.ActionDigest)
}

func resolveExisting(
	existing *application.StoredEvaluation,
	digest domain.ActionDigest,
) (application.DecisionRecord, error) {
	if existing.Decision.ActionDigest != digest {
		return application.DecisionRecord{}, fmt.Errorf("%w: request is already bound to another action", application.ErrRequestIDConflict)
	}
	return existing.Decision, nil
}

func insertCommittedActionRequest(
	ctx context.Context,
	transaction *sql.Tx,
	commit application.EvaluationCommit,
	actionJSON []byte,
) (bool, error) {
	result, err := transaction.ExecContext(ctx, `
		INSERT INTO action_requests (
			runtime_id,
			request_id,
			action_digest,
			action_type,
			action_schema_version,
			normalized_action_json,
			created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (runtime_id, request_id) DO NOTHING
	`,
		commit.RuntimeID,
		commit.RequestID,
		commit.ActionDigest.String(),
		string(commit.Action.Type()),
		actionSchemaVersionV1,
		string(actionJSON),
		commit.EvaluatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
}

func insertCommittedDecision(
	ctx context.Context,
	transaction *sql.Tx,
	commit application.EvaluationCommit,
	encoded encodedEvaluation,
) error {
	_, err := transaction.ExecContext(ctx, `
		INSERT INTO decisions (
			decision_id,
			runtime_id,
			request_id,
			decision_type,
			reason_codes_json,
			required_action_types_json,
			policy_version,
			matched_rule_ids_json,
			evaluated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		commit.DecisionID,
		commit.RuntimeID,
		commit.RequestID,
		string(commit.Decision.Type()),
		string(encoded.reasonCodesJSON),
		string(encoded.requiredActionsJSON),
		commit.PolicyVersion,
		string(encoded.matchedRuleIDsJSON),
		commit.EvaluatedAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func insertPolicyEffects(
	ctx context.Context,
	transaction *sql.Tx,
	commit application.EvaluationCommit,
	effects []encodedPolicyEffect,
) error {
	for _, effect := range effects {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO policy_effects (
				effect_id,
				decision_id,
				effect_type,
				effect_context_json,
				idempotency_key,
				dispatch_status,
				attempt_count,
				created_at,
				updated_at
			) VALUES (?, ?, ?, ?, ?, 'PENDING', 0, ?, ?)
		`,
			effect.effectID,
			commit.DecisionID,
			string(effect.typ),
			string(effect.contextJSON),
			effect.idempotencyKey,
			commit.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			commit.EvaluatedAt.UTC().Format(time.RFC3339Nano),
		); err != nil {
			return err
		}
	}
	return nil
}

func policyEffectIdempotencyKey(
	runtimeID string,
	requestID string,
	typ domain.PolicyEffectType,
) string {
	value, _ := json.Marshal([]string{runtimeID, requestID, string(typ)})
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decisionRecordFromCommit(commit application.EvaluationCommit) application.DecisionRecord {
	return application.DecisionRecord{
		DecisionID:     commit.DecisionID,
		Decision:       commit.Decision,
		ActionDigest:   commit.ActionDigest,
		PolicyVersion:  commit.PolicyVersion,
		MatchedRuleIDs: append([]string(nil), commit.MatchedRuleIDs...),
		EvaluatedAt:    commit.EvaluatedAt.UTC(),
	}
}
