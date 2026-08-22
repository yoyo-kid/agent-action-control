package osprey

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

const (
	terminalDenyPrefix = "deny."
	approvalPrefix     = "require_delegator_approval."
	safetyReviewPrefix = "create_safety_review."
)

var policyKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

var _ application.PolicyEvaluator = (*Evaluator)(nil)

type Config struct {
	Coordinator   Coordinator
	PolicyVersion string
	Timeout       time.Duration
}

// Evaluator maps controlled Osprey verdicts into the engine-independent
// policy evaluation consumed by DecisionService.
type Evaluator struct {
	coordinator   Coordinator
	policyVersion string
	timeout       time.Duration
}

func NewEvaluator(config Config) (*Evaluator, error) {
	policyVersion := strings.TrimSpace(config.PolicyVersion)
	if config.Coordinator == nil || policyVersion == "" || config.Timeout <= 0 {
		return nil, fmt.Errorf("Osprey coordinator, policy version, and positive timeout are required")
	}
	return &Evaluator{
		coordinator:   config.Coordinator,
		policyVersion: policyVersion,
		timeout:       config.Timeout,
	}, nil
}

func (evaluator *Evaluator) Evaluate(
	ctx context.Context,
	action domain.ProposedAction,
) (application.PolicyEvaluation, error) {
	actionJSON, err := marshalAction(action)
	if err != nil {
		return application.PolicyEvaluation{}, err
	}
	callContext, cancel := context.WithTimeout(ctx, evaluator.timeout)
	defer cancel()
	verdicts, err := evaluator.coordinator.ProcessAction(callContext, CoordinatorRequest{
		ActionDataJSON: string(actionJSON),
		Timestamp:      action.RequestedAt(),
	})
	if err != nil {
		return evaluator.failClosed(), nil
	}
	evaluation, err := evaluator.mapVerdicts(verdicts)
	if err != nil {
		return evaluator.failClosed(), nil
	}
	return evaluation, nil
}

func (evaluator *Evaluator) mapVerdicts(verdicts []string) (application.PolicyEvaluation, error) {
	evaluation := application.PolicyEvaluation{PolicyVersion: evaluator.policyVersion}
	seen := make(map[string]struct{}, len(verdicts))
	safetyReviewCreated := false
	for _, verdict := range verdicts {
		if _, exists := seen[verdict]; exists {
			continue
		}
		seen[verdict] = struct{}{}
		switch {
		case strings.HasPrefix(verdict, terminalDenyPrefix):
			reason, err := parseTerminalReason(strings.TrimPrefix(verdict, terminalDenyPrefix))
			if err != nil {
				return application.PolicyEvaluation{}, err
			}
			evaluation.DenyReasonCodes = append(evaluation.DenyReasonCodes, reason)
		case strings.HasPrefix(verdict, approvalPrefix):
			if !validPolicyKey(strings.TrimPrefix(verdict, approvalPrefix)) {
				return application.PolicyEvaluation{}, fmt.Errorf("invalid approval verdict")
			}
			evaluation.DenyReasonCodes = append(
				evaluation.DenyReasonCodes,
				domain.ReasonDelegatorApprovalRequired,
			)
		case strings.HasPrefix(verdict, safetyReviewPrefix):
			if !validPolicyKey(strings.TrimPrefix(verdict, safetyReviewPrefix)) {
				return application.PolicyEvaluation{}, fmt.Errorf("invalid safety review verdict")
			}
			if !safetyReviewCreated {
				effect, err := newSafetyReviewEffect()
				if err != nil {
					return application.PolicyEvaluation{}, err
				}
				evaluation.Effects = append(evaluation.Effects, effect)
				safetyReviewCreated = true
			}
		default:
			return application.PolicyEvaluation{}, fmt.Errorf("unknown Osprey verdict")
		}
		evaluation.MatchedRuleIDs = append(evaluation.MatchedRuleIDs, verdict)
	}
	return evaluation, nil
}

func (evaluator *Evaluator) failClosed() application.PolicyEvaluation {
	return application.PolicyEvaluation{
		DenyReasonCodes: []domain.ReasonCode{domain.ReasonPolicyUnavailable},
		PolicyVersion:   evaluator.policyVersion,
	}
}

func parseTerminalReason(value string) (domain.ReasonCode, error) {
	if !validPolicyKey(value) {
		return "", fmt.Errorf("invalid deny verdict")
	}
	reason, err := domain.ParseReasonCode(strings.ToUpper(value))
	if err != nil || reason == domain.ReasonDelegatorApprovalRequired || reason == domain.ReasonPolicyUnavailable {
		return "", fmt.Errorf("unsupported terminal deny reason")
	}
	return reason, nil
}

func validPolicyKey(value string) bool {
	return policyKeyPattern.MatchString(value)
}

func newSafetyReviewEffect() (domain.PolicyEffect, error) {
	requirement, err := domain.NewSafetyReviewRequirement(domain.SafetyReviewHigh, nil)
	if err != nil {
		return nil, err
	}
	effect, err := domain.NewCreateSafetyReviewEffect(requirement)
	if err != nil {
		return nil, err
	}
	return effect, nil
}
