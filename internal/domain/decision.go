package domain

import "fmt"

// DecisionType answers whether one exact proposed action may execute now.
type DecisionType string

const (
	DecisionAllow DecisionType = "ALLOW"
	DecisionDeny  DecisionType = "DENY"
)

func ParseDecisionType(value string) (DecisionType, error) {
	typ := DecisionType(value)
	if !typ.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidDecisionType, value)
	}
	return typ, nil
}

func (typ DecisionType) Valid() bool {
	return typ == DecisionAllow || typ == DecisionDeny
}

// Decision is an immutable policy result plus typed upstream instructions.
type Decision struct {
	typ             DecisionType
	reasonCodes     []ReasonCode
	requiredActions []RequiredAction
}

// NewAllowDecision constructs an executable M1 decision. Normal allows do not
// expose policy reasons or internal background effects to upstream callers.
func NewAllowDecision() Decision {
	return Decision{typ: DecisionAllow}
}

// NewDenyDecision constructs a non-executable decision. Repeated reasons and
// required-action types are normalized in first-seen order.
func NewDenyDecision(reasonCodes []ReasonCode, requiredActions []RequiredAction) (Decision, error) {
	if len(reasonCodes) == 0 {
		return Decision{}, fmt.Errorf("%w: deny decision requires at least one reason code", ErrInvalidArgument)
	}

	normalizedReasons := make([]ReasonCode, 0, len(reasonCodes))
	seenReasons := make(map[ReasonCode]struct{}, len(reasonCodes))
	for _, code := range reasonCodes {
		if !code.Valid() {
			return Decision{}, fmt.Errorf("%w: %q", ErrInvalidReasonCode, code)
		}
		if _, exists := seenReasons[code]; exists {
			continue
		}
		seenReasons[code] = struct{}{}
		normalizedReasons = append(normalizedReasons, code)
	}

	normalizedActions := make([]RequiredAction, 0, len(requiredActions))
	seenActions := make(map[RequiredActionType]struct{}, len(requiredActions))
	for _, action := range requiredActions {
		if !action.valid() {
			return Decision{}, fmt.Errorf("%w: %q", ErrInvalidRequiredActionType, action.Type())
		}
		if _, exists := seenActions[action.Type()]; exists {
			continue
		}
		seenActions[action.Type()] = struct{}{}
		normalizedActions = append(normalizedActions, action)
	}

	hasApprovalReason := false
	for _, code := range normalizedReasons {
		if code == ReasonDelegatorApprovalRequired {
			hasApprovalReason = true
			break
		}
	}
	if len(normalizedActions) > 0 && !hasApprovalReason {
		return Decision{}, fmt.Errorf("%w: required approval needs delegator approval reason", ErrInvariantViolation)
	}
	if hasApprovalReason && len(normalizedActions) == 0 {
		return Decision{}, fmt.Errorf("%w: delegator approval reason needs required approval", ErrInvariantViolation)
	}

	return Decision{
		typ:             DecisionDeny,
		reasonCodes:     normalizedReasons,
		requiredActions: normalizedActions,
	}, nil
}

func (decision Decision) Type() DecisionType { return decision.typ }
func (decision Decision) ReasonCodes() []ReasonCode {
	return append([]ReasonCode(nil), decision.reasonCodes...)
}
func (decision Decision) RequiredActions() []RequiredAction {
	return append([]RequiredAction(nil), decision.requiredActions...)
}
