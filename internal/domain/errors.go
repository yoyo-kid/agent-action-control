package domain

import "errors"

var (
	ErrInvalidActionType         = errors.New("invalid action type")
	ErrInvalidDecisionType       = errors.New("invalid decision type")
	ErrInvalidRequiredActionType = errors.New("invalid required action type")
	ErrInvalidPolicyEffectType   = errors.New("invalid policy effect type")
	ErrInvalidReasonCode         = errors.New("invalid reason code")
	ErrInvalidPrincipalType      = errors.New("invalid principal type")
	ErrInvalidDigest             = errors.New("invalid action digest")
	ErrInvalidArgument           = errors.New("invalid argument")
	ErrInvariantViolation        = errors.New("domain invariant violation")
)
