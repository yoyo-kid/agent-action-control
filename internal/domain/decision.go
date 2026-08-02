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

func NewDecision(typ DecisionType, reasonCodes []ReasonCode, actions []PolicyAction) (Decision, error) {
	if !typ.Valid() {
		return Decision{}, fmt.Errorf("%w: %q", ErrInvalidDecisionType, typ)
	}
	if len(reasonCodes) == 0 {
		return Decision{}, fmt.Errorf("%w: at least one reason code is required", ErrInvalidArgument)
	}

	seenReasons := make(map[ReasonCode]struct{}, len(reasonCodes))
	for _, code := range reasonCodes {
		if !code.Valid() {
			return Decision{}, fmt.Errorf("%w: %q", ErrInvalidReasonCode, code)
		}
		if _, exists := seenReasons[code]; exists {
			return Decision{}, fmt.Errorf("%w: %q", ErrDuplicateReasonCode, code)
		}
		seenReasons[code] = struct{}{}
	}

	seenActions := make(map[PolicyActionType]struct{}, len(actions))
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
		if _, exists := seenActions[actionType]; exists {
			return Decision{}, fmt.Errorf("%w: %q", ErrDuplicatePolicyAction, actionType)
		}
		seenActions[actionType] = struct{}{}
		if typ == DecisionAllow && actionType == PolicyActionRequireApproval {
			return Decision{}, ErrAllowCannotRequireApproval
		}
	}

	return Decision{
		typ:         typ,
		reasonCodes: append([]ReasonCode(nil), reasonCodes...),
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
