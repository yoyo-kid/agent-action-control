package domain

import (
	"fmt"
	"strings"
)

// PolicyEffectType identifies background work owned by Action Control rather
// than an instruction that the upstream runtime must execute.
type PolicyEffectType string

const PolicyEffectCreateSafetyReview PolicyEffectType = "CREATE_SAFETY_REVIEW"

func ParsePolicyEffectType(value string) (PolicyEffectType, error) {
	typ := PolicyEffectType(value)
	if !typ.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidPolicyEffectType, value)
	}
	return typ, nil
}

func (typ PolicyEffectType) Valid() bool {
	return typ == PolicyEffectCreateSafetyReview
}

// PolicyEffect is a closed set of internal asynchronous effects.
type PolicyEffect interface {
	Type() PolicyEffectType
	validate() error
	isPolicyEffect()
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

// CreateSafetyReviewEffect records internal review work without exposing it as
// an upstream action in the public decision response.
type CreateSafetyReviewEffect struct {
	requirement SafetyReviewRequirement
}

func NewCreateSafetyReviewEffect(requirement SafetyReviewRequirement) (CreateSafetyReviewEffect, error) {
	effect := CreateSafetyReviewEffect{requirement: requirement}
	if err := effect.validate(); err != nil {
		return CreateSafetyReviewEffect{}, err
	}
	return effect, nil
}

func (CreateSafetyReviewEffect) Type() PolicyEffectType { return PolicyEffectCreateSafetyReview }
func (effect CreateSafetyReviewEffect) Requirement() SafetyReviewRequirement {
	return effect.requirement
}
func (CreateSafetyReviewEffect) isPolicyEffect() {}
func (effect CreateSafetyReviewEffect) validate() error {
	if strings.TrimSpace(effect.requirement.reviewRequestID) == "" || !effect.requirement.priority.Valid() {
		return fmt.Errorf("%w: invalid safety review requirement", ErrInvalidArgument)
	}
	return nil
}
