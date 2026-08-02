package domain

import "fmt"

// ReasonCode is a stable machine-readable explanation for a decision.
type ReasonCode string

const (
	ReasonExistingDelegationSufficient       ReasonCode = "EXISTING_DELEGATION_SUFFICIENT"
	ReasonDelegatorApprovalRequired          ReasonCode = "DELEGATOR_APPROVAL_REQUIRED"
	ReasonExternalDestination                ReasonCode = "EXTERNAL_DESTINATION"
	ReasonVisibilityExpansion                ReasonCode = "VISIBILITY_EXPANSION"
	ReasonDestructiveOperation               ReasonCode = "DESTRUCTIVE_OPERATION"
	ReasonActorNotAuthorized                 ReasonCode = "ACTOR_NOT_AUTHORIZED"
	ReasonDelegatorApprovalVerified          ReasonCode = "DELEGATOR_APPROVAL_VERIFIED"
	ReasonApprovalRejected                   ReasonCode = "APPROVAL_REJECTED"
	ReasonApprovalExpired                    ReasonCode = "APPROVAL_EXPIRED"
	ReasonActionDigestMismatch               ReasonCode = "ACTION_DIGEST_MISMATCH"
	ReasonActionIDReusedWithDifferentContent ReasonCode = "ACTION_ID_REUSED_WITH_DIFFERENT_CONTENT"
	ReasonSafetyReviewRequested              ReasonCode = "SAFETY_REVIEW_REQUESTED"
	ReasonPolicyUnavailable                  ReasonCode = "POLICY_UNAVAILABLE"
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
	case ReasonExistingDelegationSufficient,
		ReasonDelegatorApprovalRequired,
		ReasonExternalDestination,
		ReasonVisibilityExpansion,
		ReasonDestructiveOperation,
		ReasonActorNotAuthorized,
		ReasonDelegatorApprovalVerified,
		ReasonApprovalRejected,
		ReasonApprovalExpired,
		ReasonActionDigestMismatch,
		ReasonActionIDReusedWithDifferentContent,
		ReasonSafetyReviewRequested,
		ReasonPolicyUnavailable:
		return true
	default:
		return false
	}
}
