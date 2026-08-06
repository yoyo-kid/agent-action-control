package embedded

import (
	"context"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

const Version = "embedded-mvp-v1"

const (
	rulePermissionMismatch = "mvp.permission-mismatch"
	ruleExternalSend       = "mvp.external-send-approval"
	ruleVisibilityExpand   = "mvp.visibility-expansion-approval"
	ruleDestructiveDelete  = "mvp.destructive-delete-approval"
	ruleSecretReview       = "mvp.secret-payload-review"
)

var _ application.PolicyEvaluator = Evaluator{}

// Evaluator implements deterministic local M1 policy rules. It emits stable
// reasons and internal effects; DecisionComposer owns public required actions.
type Evaluator struct{}

func (Evaluator) Evaluate(
	_ context.Context,
	action domain.ProposedAction,
) (application.PolicyEvaluation, error) {
	evaluation := application.PolicyEvaluation{PolicyVersion: Version}

	evidence := action.AuthorizationEvidence()
	if len(evidence) > 0 && !hasMatchingRuntimeEvidence(action, evidence) {
		evaluation.DenyReasonCodes = append(evaluation.DenyReasonCodes, domain.ReasonActorNotAuthorized)
		evaluation.MatchedRuleIDs = append(evaluation.MatchedRuleIDs, rulePermissionMismatch)
	} else {
		evaluateActionRules(action, evidence, &evaluation)
	}

	if containsClassification(action.Payload().Classification(), "SECRET") {
		references := make([]string, 0, len(evidence))
		for _, item := range evidence {
			references = append(references, item.ID())
		}
		requirement, err := domain.NewSafetyReviewRequirement(domain.SafetyReviewHigh, references)
		if err != nil {
			return application.PolicyEvaluation{}, err
		}
		effect, err := domain.NewCreateSafetyReviewEffect(requirement)
		if err != nil {
			return application.PolicyEvaluation{}, err
		}
		evaluation.Effects = append(evaluation.Effects, effect)
		evaluation.MatchedRuleIDs = append(evaluation.MatchedRuleIDs, ruleSecretReview)
	}

	return evaluation, nil
}

func evaluateActionRules(
	action domain.ProposedAction,
	evidence []domain.AuthorizationEvidence,
	evaluation *application.PolicyEvaluation,
) {
	switch parameters := action.Parameters().(type) {
	case domain.ExternalSendParameters:
		if parameters.DestinationScope() == domain.DestinationExternal && len(evidence) == 0 {
			evaluation.DenyReasonCodes = append(
				evaluation.DenyReasonCodes,
				domain.ReasonDelegatorApprovalRequired,
				domain.ReasonExternalDestination,
			)
			evaluation.MatchedRuleIDs = append(evaluation.MatchedRuleIDs, ruleExternalSend)
		}
	case domain.UpdateResourceAccessParameters:
		if isHighImpactVisibilityExpansion(parameters.CurrentScope(), parameters.RequestedScope()) {
			evaluation.DenyReasonCodes = append(
				evaluation.DenyReasonCodes,
				domain.ReasonDelegatorApprovalRequired,
				domain.ReasonVisibilityExpansion,
			)
			evaluation.MatchedRuleIDs = append(evaluation.MatchedRuleIDs, ruleVisibilityExpand)
		}
	case domain.DeleteParameters:
		if parameters.Mode() == domain.DeleteHard || !parameters.Recoverable() {
			evaluation.DenyReasonCodes = append(
				evaluation.DenyReasonCodes,
				domain.ReasonDelegatorApprovalRequired,
				domain.ReasonDestructiveOperation,
			)
			evaluation.MatchedRuleIDs = append(evaluation.MatchedRuleIDs, ruleDestructiveDelete)
		}
	}
}

func hasMatchingRuntimeEvidence(
	action domain.ProposedAction,
	evidence []domain.AuthorizationEvidence,
) bool {
	for _, item := range evidence {
		issuer := item.IssuedBy()
		if issuer.Type() != domain.PrincipalRuntime || issuer.ID() != action.Actor().RuntimeID() {
			continue
		}
		if scopeMatchesAction(item.Scope(), action) {
			return true
		}
	}
	return false
}

func scopeMatchesAction(scope domain.AuthorizationScope, action domain.ProposedAction) bool {
	if scope.ActionType() != action.Type() {
		return false
	}
	switch parameters := action.Parameters().(type) {
	case domain.ExternalSendParameters:
		return scope.DestinationScope() == parameters.DestinationScope()
	case domain.UpdateResourceAccessParameters:
		return scope.RequestedScope() == parameters.RequestedScope()
	case domain.DeleteParameters:
		return scope.DeleteMode() == parameters.Mode()
	default:
		return false
	}
}

func isHighImpactVisibilityExpansion(current, requested domain.AccessScope) bool {
	return current == domain.AccessPrivate &&
		(requested == domain.AccessWorkspace || requested == domain.AccessPublic)
}

func containsClassification(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
