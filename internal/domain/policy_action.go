package domain

import (
	"fmt"
	"strings"
	"time"
)

// PolicyActionType identifies work upstream must perform after a decision.
type PolicyActionType string

const (
	PolicyActionRequireApproval    PolicyActionType = "REQUIRE_APPROVAL"
	PolicyActionCreateSafetyReview PolicyActionType = "CREATE_SAFETY_REVIEW"
)

func ParsePolicyActionType(value string) (PolicyActionType, error) {
	typ := PolicyActionType(value)
	if !typ.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidPolicyActionType, value)
	}
	return typ, nil
}

func (typ PolicyActionType) Valid() bool {
	return typ == PolicyActionRequireApproval || typ == PolicyActionCreateSafetyReview
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

// SafetyReviewPriority controls asynchronous review urgency.
type SafetyReviewPriority string

const (
	SafetyReviewLow      SafetyReviewPriority = "LOW"
	SafetyReviewMedium   SafetyReviewPriority = "MEDIUM"
	SafetyReviewHigh     SafetyReviewPriority = "HIGH"
	SafetyReviewCritical SafetyReviewPriority = "CRITICAL"
)

func (priority SafetyReviewPriority) Valid() bool {
	switch priority {
	case SafetyReviewLow, SafetyReviewMedium, SafetyReviewHigh, SafetyReviewCritical:
		return true
	default:
		return false
	}
}

type SafetyReviewRequirement struct {
	reviewRequestID string
	priority        SafetyReviewPriority
	evidenceRefs    []string
}

func NewSafetyReviewRequirement(
	reviewRequestID string,
	priority SafetyReviewPriority,
	evidenceRefs []string,
) (SafetyReviewRequirement, error) {
	if strings.TrimSpace(reviewRequestID) == "" {
		return SafetyReviewRequirement{}, fmt.Errorf("%w: review request id is required", ErrInvalidArgument)
	}
	if !priority.Valid() {
		return SafetyReviewRequirement{}, fmt.Errorf("%w: invalid safety review priority %q", ErrInvalidArgument, priority)
	}
	seenEvidence := make(map[string]struct{}, len(evidenceRefs))
	for _, ref := range evidenceRefs {
		if strings.TrimSpace(ref) == "" {
			return SafetyReviewRequirement{}, fmt.Errorf("%w: evidence reference cannot be empty", ErrInvalidArgument)
		}
		if _, exists := seenEvidence[ref]; exists {
			return SafetyReviewRequirement{}, fmt.Errorf("%w: duplicate evidence reference %q", ErrInvalidArgument, ref)
		}
		seenEvidence[ref] = struct{}{}
	}
	return SafetyReviewRequirement{
		reviewRequestID: reviewRequestID,
		priority:        priority,
		evidenceRefs:    append([]string(nil), evidenceRefs...),
	}, nil
}

func (requirement SafetyReviewRequirement) ReviewRequestID() string {
	return requirement.reviewRequestID
}
func (requirement SafetyReviewRequirement) Priority() SafetyReviewPriority {
	return requirement.priority
}
func (requirement SafetyReviewRequirement) EvidenceRefs() []string {
	return append([]string(nil), requirement.evidenceRefs...)
}

type CreateSafetyReviewAction struct {
	id          string
	requirement SafetyReviewRequirement
}

func NewCreateSafetyReviewAction(id string, requirement SafetyReviewRequirement) (CreateSafetyReviewAction, error) {
	action := CreateSafetyReviewAction{id: id, requirement: requirement}
	if err := action.validate(); err != nil {
		return CreateSafetyReviewAction{}, err
	}
	return action, nil
}

func (action CreateSafetyReviewAction) ID() string             { return action.id }
func (action CreateSafetyReviewAction) Type() PolicyActionType { return PolicyActionCreateSafetyReview }
func (action CreateSafetyReviewAction) Requirement() SafetyReviewRequirement {
	return action.requirement
}
func (CreateSafetyReviewAction) isPolicyAction() {}
func (action CreateSafetyReviewAction) validate() error {
	if strings.TrimSpace(action.id) == "" {
		return fmt.Errorf("%w: policy action id is required", ErrInvalidArgument)
	}
	if strings.TrimSpace(action.requirement.reviewRequestID) == "" || !action.requirement.priority.Valid() {
		return fmt.Errorf("%w: invalid safety review requirement", ErrInvalidArgument)
	}
	return nil
}
