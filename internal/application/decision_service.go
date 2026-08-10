package application

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

// EvaluateActionCommand is the transport-independent input to the decision
// use case. AuthenticatedRuntime remains separate trusted context rather than
// caller-controlled action data.
type EvaluateActionCommand struct {
	RequestID      string
	ProposedAction ProposedActionInput
}

// DecisionService turns one runtime-scoped action request into an
// authoritative persisted decision. Policy evaluation happens before the
// ledger opens its short commit transaction.
type DecisionService struct {
	policyEvaluator PolicyEvaluator
	decisionLedger  DecisionLedger
	clock           Clock
	idGenerator     IDGenerator
	normalizer      ActionNormalizer
	composer        DecisionComposer
}

func NewDecisionService(
	policyEvaluator PolicyEvaluator,
	decisionLedger DecisionLedger,
	clock Clock,
	idGenerator IDGenerator,
) (*DecisionService, error) {
	if policyEvaluator == nil || decisionLedger == nil || clock == nil || idGenerator == nil {
		return nil, fmt.Errorf("%w: decision service dependencies are required", ErrInvalidInput)
	}
	return &DecisionService{
		policyEvaluator: policyEvaluator,
		decisionLedger:  decisionLedger,
		clock:           clock,
		idGenerator:     idGenerator,
		normalizer:      ActionNormalizer{},
		composer:        DecisionComposer{},
	}, nil
}

func (service *DecisionService) Evaluate(
	ctx context.Context,
	runtime AuthenticatedRuntime,
	command EvaluateActionCommand,
) (DecisionRecord, error) {
	if service == nil {
		return DecisionRecord{}, fmt.Errorf("%w: decision service is required", ErrInvalidInput)
	}
	requestID, err := normalizeDecisionRequestID(command.RequestID)
	if err != nil {
		return DecisionRecord{}, err
	}
	action, err := service.normalizer.Normalize(runtime, command.ProposedAction)
	if err != nil {
		return DecisionRecord{}, err
	}
	actionDigest, err := domain.ComputeActionDigest(action)
	if err != nil {
		return DecisionRecord{}, fmt.Errorf("%w: compute action digest: %v", ErrInvalidInput, err)
	}

	existing, err := service.decisionLedger.GetEvaluationByRequestID(ctx, runtime.RuntimeID(), requestID)
	switch {
	case err == nil:
		return resolveStoredEvaluation(existing, runtime.RuntimeID(), requestID, actionDigest)
	case !errors.Is(err, ErrEvaluationNotFound):
		return DecisionRecord{}, wrapLedgerError("look up evaluation", err)
	}

	evaluation, err := service.policyEvaluator.Evaluate(ctx, action)
	if err != nil {
		return DecisionRecord{}, fmt.Errorf("%w: evaluate action: %w", ErrPolicyUnavailable, err)
	}
	if err := validatePolicyEvaluation(evaluation); err != nil {
		return DecisionRecord{}, err
	}
	decision, err := service.composer.Compose(evaluation)
	if err != nil {
		return DecisionRecord{}, fmt.Errorf("%w: compose decision: %w", ErrPolicyUnavailable, err)
	}

	decisionID, err := service.newRequiredID(IDDecision)
	if err != nil {
		return DecisionRecord{}, err
	}
	effects, err := service.preparePolicyEffects(evaluation.Effects)
	if err != nil {
		return DecisionRecord{}, err
	}
	evaluatedAt := service.clock.Now().UTC()
	if evaluatedAt.IsZero() {
		return DecisionRecord{}, fmt.Errorf("%w: clock returned zero time", ErrClockFailure)
	}

	record, err := service.decisionLedger.CommitEvaluation(ctx, EvaluationCommit{
		RuntimeID:      runtime.RuntimeID(),
		RequestID:      requestID,
		Action:         action,
		ActionDigest:   actionDigest,
		DecisionID:     decisionID,
		Decision:       decision,
		PolicyVersion:  strings.TrimSpace(evaluation.PolicyVersion),
		MatchedRuleIDs: append([]string(nil), evaluation.MatchedRuleIDs...),
		Effects:        effects,
		EvaluatedAt:    evaluatedAt,
	})
	if err != nil {
		if errors.Is(err, ErrRequestIDConflict) {
			return DecisionRecord{}, err
		}
		return DecisionRecord{}, wrapLedgerError("commit evaluation", err)
	}
	if err := validateAuthoritativeDecision(record, actionDigest); err != nil {
		return DecisionRecord{}, err
	}
	return record, nil
}

func (service *DecisionService) preparePolicyEffects(
	effects []domain.PolicyEffect,
) ([]PolicyEffectCommit, error) {
	prepared := make([]PolicyEffectCommit, 0, len(effects))
	for _, effect := range effects {
		if !validPolicyEffect(effect) {
			return nil, fmt.Errorf("%w: evaluator returned an invalid policy effect", ErrPolicyUnavailable)
		}
		effectID, err := service.newRequiredID(IDPolicyEffect)
		if err != nil {
			return nil, err
		}
		prepared = append(prepared, PolicyEffectCommit{EffectID: effectID, Effect: effect})
	}
	return prepared, nil
}

func validatePolicyEvaluation(evaluation PolicyEvaluation) error {
	if strings.TrimSpace(evaluation.PolicyVersion) == "" {
		return fmt.Errorf("%w: evaluator returned an empty policy version", ErrPolicyUnavailable)
	}
	for _, ruleID := range evaluation.MatchedRuleIDs {
		if strings.TrimSpace(ruleID) == "" {
			return fmt.Errorf("%w: evaluator returned an empty matched rule id", ErrPolicyUnavailable)
		}
	}
	for _, effect := range evaluation.Effects {
		if !validPolicyEffect(effect) {
			return fmt.Errorf("%w: evaluator returned an invalid policy effect", ErrPolicyUnavailable)
		}
	}
	return nil
}

func validPolicyEffect(effect domain.PolicyEffect) bool {
	switch value := effect.(type) {
	case domain.CreateSafetyReviewEffect:
		return value.Type().Valid()
	case *domain.CreateSafetyReviewEffect:
		return value != nil && value.Type().Valid()
	default:
		return false
	}
}

func (service *DecisionService) newRequiredID(kind IDKind) (string, error) {
	value, err := service.idGenerator.NewID(kind)
	if err != nil {
		return "", fmt.Errorf("%w: generate %s id: %w", ErrIDGeneration, kind, err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: generator returned an empty %s id", ErrIDGeneration, kind)
	}
	return value, nil
}

func normalizeDecisionRequestID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 {
		return "", fmt.Errorf("%w: request id must contain 1 to 256 characters", ErrInvalidInput)
	}
	return value, nil
}

func resolveStoredEvaluation(
	stored *StoredEvaluation,
	runtimeID string,
	requestID string,
	actionDigest domain.ActionDigest,
) (DecisionRecord, error) {
	if stored == nil || stored.RuntimeID != runtimeID || stored.RequestID != requestID {
		return DecisionRecord{}, fmt.Errorf("%w: ledger returned a mismatched stored evaluation", ErrLedgerFailure)
	}
	if stored.Decision.ActionDigest != actionDigest {
		return DecisionRecord{}, fmt.Errorf("%w: request is already bound to another action", ErrRequestIDConflict)
	}
	if err := validateAuthoritativeDecision(stored.Decision, actionDigest); err != nil {
		return DecisionRecord{}, err
	}
	return stored.Decision, nil
}

func validateAuthoritativeDecision(record DecisionRecord, actionDigest domain.ActionDigest) error {
	if strings.TrimSpace(record.DecisionID) == "" ||
		!record.Decision.Type().Valid() ||
		record.ActionDigest != actionDigest ||
		strings.TrimSpace(record.PolicyVersion) == "" ||
		record.EvaluatedAt.IsZero() {
		return fmt.Errorf("%w: ledger returned an invalid authoritative decision", ErrLedgerFailure)
	}
	return nil
}

func wrapLedgerError(operation string, err error) error {
	if errors.Is(err, ErrLedgerFailure) {
		return err
	}
	return fmt.Errorf("%w: %s: %w", ErrLedgerFailure, operation, err)
}
