package application

import (
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

// PolicyEvaluation is the policy-engine-independent result consumed by the
// DecisionComposer. Actions are upstream instructions; effects stay internal.
type PolicyEvaluation struct {
	DenyReasonCodes []domain.ReasonCode
	Actions         []domain.PolicyAction
	Effects         []domain.PolicyEffect
	MatchedRuleIDs  []string
	PolicyVersion   string
}

// DecisionRecord is the authoritative decision metadata returned by a
// successful atomic ledger commit.
type DecisionRecord struct {
	DecisionID     string
	Decision       domain.Decision
	ActionDigest   domain.ActionDigest
	PolicyVersion  string
	MatchedRuleIDs []string
	EvaluatedAt    time.Time
}

// StoredEvaluation is the idempotency view returned for an existing action.
type StoredEvaluation struct {
	Action   domain.ProposedAction
	Decision DecisionRecord
}

// EvaluationCommit contains everything the ledger must persist atomically for
// one evaluated action, including internal effects.
type EvaluationCommit struct {
	RequestID      string
	Action         domain.ProposedAction
	ActionDigest   domain.ActionDigest
	DecisionID     string
	Decision       domain.Decision
	PolicyVersion  string
	MatchedRuleIDs []string
	Effects        []domain.PolicyEffect
	EvaluatedAt    time.Time
}
