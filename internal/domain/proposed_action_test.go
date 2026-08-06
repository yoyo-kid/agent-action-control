package domain

import (
	"errors"
	"testing"
	"time"
)

type testActionParameters struct {
	typ    ActionType
	values []string
}

func (parameters testActionParameters) ActionType() ActionType { return parameters.typ }
func (parameters testActionParameters) validate() error {
	if !parameters.typ.Valid() {
		return ErrInvalidActionType
	}
	return nil
}
func (parameters testActionParameters) clone() ActionParameters {
	parameters.values = append([]string(nil), parameters.values...)
	return parameters
}

func TestNewProposedAction(t *testing.T) {
	t.Parallel()

	actor, err := NewActor("agent_123", "runtime_123", "session_123")
	if err != nil {
		t.Fatalf("new actor: %v", err)
	}
	delegator, err := NewPrincipal(PrincipalUser, "user_123")
	if err != nil {
		t.Fatalf("new delegator: %v", err)
	}
	delegation, err := NewDelegation("delegation_123", delegator)
	if err != nil {
		t.Fatalf("new delegation: %v", err)
	}
	target, err := NewTarget("DOCUMENT", "document_123")
	if err != nil {
		t.Fatalf("new target: %v", err)
	}
	digest, err := ParsePayloadDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	parameters := testActionParameters{typ: ActionExternalSend, values: []string{"customer@example.com"}}
	payload, err := NewPayloadFacts(digest, nil, nil)
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}

	action, err := NewProposedAction(
		ActionExternalSend,
		time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC),
		actor,
		delegation,
		target,
		parameters,
		payload,
		nil,
	)
	if err != nil {
		t.Fatalf("new proposed action: %v", err)
	}
	if action.Type() != ActionExternalSend || action.PayloadDigest() != digest {
		t.Fatalf("unexpected action: type=%q digest=%q", action.Type(), action.PayloadDigest())
	}

	parameters.values[0] = "mutated@example.com"
	stored := action.Parameters().(testActionParameters)
	if stored.values[0] != "customer@example.com" {
		t.Fatalf("parameters mutated after construction: %q", stored.values[0])
	}
	stored.values[0] = "mutated-again@example.com"
	if got := action.Parameters().(testActionParameters).values[0]; got != "customer@example.com" {
		t.Fatalf("parameters mutated through getter: %q", got)
	}
}

func TestNewProposedActionRejectsMismatchedParameters(t *testing.T) {
	t.Parallel()

	digest, err := ParsePayloadDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	payload, err := NewPayloadFacts(digest, nil, nil)
	if err != nil {
		t.Fatalf("new payload: %v", err)
	}
	_, err = NewProposedAction(
		ActionDelete,
		time.Date(2026, time.August, 2, 12, 0, 0, 0, time.UTC),
		Actor{agentID: "agent_123", runtimeID: "runtime_123"},
		Delegation{id: "delegation_123", delegator: Principal{typ: PrincipalUser, id: "user_123"}},
		Target{resourceType: "DOCUMENT", resourceID: "document_123"},
		testActionParameters{typ: ActionExternalSend},
		payload,
		nil,
	)
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidArgument)
	}
}

func TestSafetyReviewRequirementOwnsEvidenceReferences(t *testing.T) {
	t.Parallel()

	references := []string{"message_123"}
	requirement, err := NewSafetyReviewRequirement(SafetyReviewHigh, references)
	if err != nil {
		t.Fatalf("new safety review requirement: %v", err)
	}
	effect, err := NewCreateSafetyReviewEffect(requirement)
	if err != nil {
		t.Fatalf("new safety review effect: %v", err)
	}
	if effect.Type() != PolicyEffectCreateSafetyReview {
		t.Fatalf("effect type = %q", effect.Type())
	}
	references[0] = "mutated"
	if got := effect.Requirement().EvidenceRefs()[0]; got != "message_123" {
		t.Fatalf("stored reference = %q", got)
	}
	returned := requirement.EvidenceRefs()
	returned[0] = "mutated-again"
	if got := requirement.EvidenceRefs()[0]; got != "message_123" {
		t.Fatalf("reference mutated through getter: %q", got)
	}
}
