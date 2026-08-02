package domain

import (
	"fmt"
	"strings"
	"time"
)

// PolicyActionType identifies work upstream must perform after a decision.
type PolicyActionType string

const (
	PolicyActionRequireApproval PolicyActionType = "REQUIRE_APPROVAL"
)

func ParsePolicyActionType(value string) (PolicyActionType, error) {
	typ := PolicyActionType(value)
	if !typ.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidPolicyActionType, value)
	}
	return typ, nil
}

func (typ PolicyActionType) Valid() bool {
	return typ == PolicyActionRequireApproval
}

// PolicyAction is a closed set of typed instructions returned with a decision.
type PolicyAction interface {
	ID() string
	Type() PolicyActionType
	validate() error
	isPolicyAction()
}

// RequiredAuthorityType identifies who may resolve an approval requirement.
type RequiredAuthorityType string

const RequiredAuthorityDelegator RequiredAuthorityType = "DELEGATOR"

// RequiredAuthority identifies the principal whose approval is required.
type RequiredAuthority struct {
	typ         RequiredAuthorityType
	principalID string
}

func NewDelegatorAuthority(principalID string) (RequiredAuthority, error) {
	if strings.TrimSpace(principalID) == "" {
		return RequiredAuthority{}, fmt.Errorf("%w: required authority principal id is required", ErrInvalidArgument)
	}
	return RequiredAuthority{typ: RequiredAuthorityDelegator, principalID: principalID}, nil
}

func (authority RequiredAuthority) Type() RequiredAuthorityType { return authority.typ }
func (authority RequiredAuthority) PrincipalID() string         { return authority.principalID }

// ApprovalRequirement contains the M1 approval challenge emitted to upstream.
type ApprovalRequirement struct {
	approvalRequestID string
	authority         RequiredAuthority
	actionDigest      ActionDigest
	expiresAt         time.Time
}

func NewApprovalRequirement(
	approvalRequestID string,
	authority RequiredAuthority,
	actionDigest ActionDigest,
	expiresAt time.Time,
) (ApprovalRequirement, error) {
	if strings.TrimSpace(approvalRequestID) == "" {
		return ApprovalRequirement{}, fmt.Errorf("%w: approval request id is required", ErrInvalidArgument)
	}
	if authority.typ != RequiredAuthorityDelegator || strings.TrimSpace(authority.principalID) == "" {
		return ApprovalRequirement{}, fmt.Errorf("%w: valid required authority is required", ErrInvalidArgument)
	}
	if !actionDigest.Valid() {
		return ApprovalRequirement{}, ErrInvalidDigest
	}
	if expiresAt.IsZero() {
		return ApprovalRequirement{}, fmt.Errorf("%w: approval expiration is required", ErrInvalidArgument)
	}
	return ApprovalRequirement{
		approvalRequestID: approvalRequestID,
		authority:         authority,
		actionDigest:      actionDigest,
		expiresAt:         expiresAt,
	}, nil
}

func (requirement ApprovalRequirement) ApprovalRequestID() string {
	return requirement.approvalRequestID
}
func (requirement ApprovalRequirement) RequiredAuthority() RequiredAuthority {
	return requirement.authority
}
func (requirement ApprovalRequirement) ActionDigest() ActionDigest { return requirement.actionDigest }
func (requirement ApprovalRequirement) ExpiresAt() time.Time       { return requirement.expiresAt }

type RequireApprovalAction struct {
	id          string
	requirement ApprovalRequirement
}

func NewRequireApprovalAction(id string, requirement ApprovalRequirement) (RequireApprovalAction, error) {
	action := RequireApprovalAction{id: id, requirement: requirement}
	if err := action.validate(); err != nil {
		return RequireApprovalAction{}, err
	}
	return action, nil
}

func (action RequireApprovalAction) ID() string                       { return action.id }
func (action RequireApprovalAction) Type() PolicyActionType           { return PolicyActionRequireApproval }
func (action RequireApprovalAction) Requirement() ApprovalRequirement { return action.requirement }
func (RequireApprovalAction) isPolicyAction()                         {}
func (action RequireApprovalAction) validate() error {
	if strings.TrimSpace(action.id) == "" {
		return fmt.Errorf("%w: policy action id is required", ErrInvalidArgument)
	}
	if strings.TrimSpace(action.requirement.approvalRequestID) == "" ||
		action.requirement.authority.typ != RequiredAuthorityDelegator ||
		!action.requirement.actionDigest.Valid() || action.requirement.expiresAt.IsZero() {
		return fmt.Errorf("%w: invalid approval requirement", ErrInvalidArgument)
	}
	return nil
}
