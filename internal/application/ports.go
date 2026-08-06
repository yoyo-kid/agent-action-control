package application

import (
	"context"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

// PolicyEvaluator evaluates normalized action facts without exposing a
// concrete policy engine to the application layer.
type PolicyEvaluator interface {
	Evaluate(context.Context, domain.ProposedAction) (PolicyEvaluation, error)
}

// DecisionLedger owns idempotency reads and atomic evaluation persistence.
// Implementations must return ErrEvaluationNotFound for a missing request and wrap
// uncertain persistence failures with ErrLedgerFailure.
type DecisionLedger interface {
	GetEvaluationByRequestID(
		ctx context.Context,
		runtimeID string,
		requestID string,
	) (*StoredEvaluation, error)
	CommitEvaluation(context.Context, EvaluationCommit) (DecisionRecord, error)
}
