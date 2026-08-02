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
	typ         DecisionType
	reasonCodes []ReasonCode
	actions     []PolicyAction
}

// NewAllowDecision constructs an executable decision. Its typed action input
// makes REQUIRE_APPROVAL structurally unrepresentable on an ALLOW decision.
func NewAllowDecision(reasonCodes []ReasonCode, safetyReviews []CreateSafetyReviewAction) (Decision, error) {
	actions := make([]PolicyAction, len(safetyReviews))
	for index, review := range safetyReviews {
		actions[index] = review
	}
	return newDecision(DecisionAllow, reasonCodes, actions)
}

// NewDenyDecision constructs a non-executable decision with the follow-up
// requirements produced by policy. Distinct requirements of the same type are
// preserved so DecisionComposer can aggregate them without losing authority or
// review context.
func NewDenyDecision(reasonCodes []ReasonCode, actions []PolicyAction) (Decision, error) {
	return newDecision(DecisionDeny, reasonCodes, actions)
}

func newDecision(typ DecisionType, reasonCodes []ReasonCode, actions []PolicyAction) (Decision, error) {
	if len(reasonCodes) == 0 {
		return Decision{}, fmt.Errorf("%w: at least one reason code is required", ErrInvalidArgument)
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

	for _, action := range actions {
		if action == nil {
			return Decision{}, fmt.Errorf("%w: policy action cannot be nil", ErrInvalidArgument)
		}
		if err := action.validate(); err != nil {
			return Decision{}, err
		}
		actionType := action.Type()
		if !actionType.Valid() {
			return Decision{}, fmt.Errorf("%w: %q", ErrInvalidPolicyActionType, actionType)
		}
	}

	return Decision{
		typ:         typ,
		reasonCodes: normalizedReasons,
		actions:     append([]PolicyAction(nil), actions...),
	}, nil
}

func (decision Decision) Type() DecisionType { return decision.typ }
func (decision Decision) ReasonCodes() []ReasonCode {
	return append([]ReasonCode(nil), decision.reasonCodes...)
}
func (decision Decision) Actions() []PolicyAction {
	return append([]PolicyAction(nil), decision.actions...)
}
