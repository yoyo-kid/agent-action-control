package application

import "github.com/yoyo-kid/agent-action-control/internal/domain"

// DecisionComposer applies fixed M1 precedence to policy output. Policy
// evaluators describe why an action is blocked; the composer owns the public
// decision and minimal required-action shape.
type DecisionComposer struct{}

func (DecisionComposer) Compose(evaluation PolicyEvaluation) (domain.Decision, error) {
	reasons := evaluation.DenyReasonCodes
	if len(reasons) == 0 {
		return domain.NewAllowDecision(), nil
	}

	if containsTerminalReason(reasons) {
		return domain.NewDenyDecision(withoutReason(reasons, domain.ReasonDelegatorApprovalRequired), nil)
	}
	if containsReason(reasons, domain.ReasonDelegatorApprovalRequired) {
		return domain.NewDenyDecision(reasons, []domain.RequiredAction{domain.NewRequireApprovalAction()})
	}
	return domain.NewDenyDecision(reasons, nil)
}

func containsReason(reasons []domain.ReasonCode, target domain.ReasonCode) bool {
	for _, reason := range reasons {
		if reason == target {
			return true
		}
	}
	return false
}

func containsTerminalReason(reasons []domain.ReasonCode) bool {
	for _, reason := range reasons {
		switch reason {
		case domain.ReasonDelegatorApprovalRequired,
			domain.ReasonExternalDestination,
			domain.ReasonVisibilityExpansion,
			domain.ReasonDestructiveOperation:
			continue
		default:
			return true
		}
	}
	return false
}

func withoutReason(reasons []domain.ReasonCode, excluded domain.ReasonCode) []domain.ReasonCode {
	filtered := make([]domain.ReasonCode, 0, len(reasons))
	for _, reason := range reasons {
		if reason != excluded {
			filtered = append(filtered, reason)
		}
	}
	return filtered
}
