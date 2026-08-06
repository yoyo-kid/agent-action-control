package domain

import "fmt"

// ReasonCode is a stable machine-readable explanation for a decision.
type ReasonCode string

const (
	ReasonDelegatorApprovalRequired ReasonCode = "DELEGATOR_APPROVAL_REQUIRED"
	ReasonExternalDestination       ReasonCode = "EXTERNAL_DESTINATION"
	ReasonVisibilityExpansion       ReasonCode = "VISIBILITY_EXPANSION"
	ReasonDestructiveOperation      ReasonCode = "DESTRUCTIVE_OPERATION"
	ReasonActorNotAuthorized        ReasonCode = "ACTOR_NOT_AUTHORIZED"
	ReasonPolicyUnavailable         ReasonCode = "POLICY_UNAVAILABLE"
)

func ParseReasonCode(value string) (ReasonCode, error) {
	code := ReasonCode(value)
	if !code.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidReasonCode, value)
	}
	return code, nil
}

func (code ReasonCode) Valid() bool {
	switch code {
	case ReasonDelegatorApprovalRequired,
		ReasonExternalDestination,
		ReasonVisibilityExpansion,
		ReasonDestructiveOperation,
		ReasonActorNotAuthorized,
		ReasonPolicyUnavailable:
		return true
	default:
		return false
	}
}
