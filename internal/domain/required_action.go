package domain

import "fmt"

// RequiredActionType identifies blocking work upstream must complete before
// an action can become executable.
type RequiredActionType string

const RequiredActionRequireApproval RequiredActionType = "REQUIRE_APPROVAL"

func ParseRequiredActionType(value string) (RequiredActionType, error) {
	typ := RequiredActionType(value)
	if !typ.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidRequiredActionType, value)
	}
	return typ, nil
}

func (typ RequiredActionType) Valid() bool {
	return typ == RequiredActionRequireApproval
}

// RequiredAction is a typed M1 instruction returned to upstream. Approval
// workflow identity, authority context, and expiration belong to M2.
type RequiredAction struct {
	typ RequiredActionType
}

func NewRequireApprovalAction() RequiredAction {
	return RequiredAction{typ: RequiredActionRequireApproval}
}

func (action RequiredAction) Type() RequiredActionType { return action.typ }

func (action RequiredAction) valid() bool { return action.typ.Valid() }
