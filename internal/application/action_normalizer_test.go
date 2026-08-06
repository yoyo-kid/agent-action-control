package application

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

func TestActionNormalizerNormalizesExternalSend(t *testing.T) {
	t.Parallel()

	size := int64(4280)
	input := validInput(ExternalSendInput{
		DestinationScope: " external ",
		Recipients:       []string{"z@example.com", " customer@example.com ", "z@example.com"},
	})
	input.Actor.RuntimeID = " runtime_456 "
	input.Payload.Classification = []string{" SECRET ", "CONFIDENTIAL", "SECRET"}
	input.Payload.SizeBytes = &size
	input.AuthorizationEvidence = []AuthorizationEvidenceInput{
		{
			Type:       " system_assertion ",
			EvidenceID: " evidence_123 ",
			IssuedBy:   PrincipalInput{Type: domain.PrincipalRuntime, ID: " runtime_456 "},
			Scope: AuthorizationScopeInput{
				ActionType:       domain.ActionExternalSend,
				DestinationScope: "external",
			},
		},
	}

	action, err := (ActionNormalizer{}).Normalize(
		mustAuthenticatedRuntime(t, " runtime_456 "),
		input,
	)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if action.Actor().RuntimeID() != "runtime_456" || action.Actor().AgentID() != "agent_123" {
		t.Fatalf("actor = %#v", action.Actor())
	}
	if action.RequestedAt().Location() != time.UTC {
		t.Fatalf("requested time location = %v", action.RequestedAt().Location())
	}
	parameters := action.Parameters().(domain.ExternalSendParameters)
	wantRecipients := []string{"customer@example.com", "z@example.com"}
	if got := parameters.Recipients(); !reflect.DeepEqual(got, wantRecipients) {
		t.Fatalf("recipients = %v, want %v", got, wantRecipients)
	}
	wantLabels := []string{"CONFIDENTIAL", "SECRET"}
	if got := action.Payload().Classification(); !reflect.DeepEqual(got, wantLabels) {
		t.Fatalf("classification = %v, want %v", got, wantLabels)
	}
	if got := action.AuthorizationEvidence(); len(got) != 1 || got[0].ID() != "evidence_123" {
		t.Fatalf("authorization evidence = %#v", got)
	}
}

func TestActionNormalizerRejectsRuntimeIdentityConflict(t *testing.T) {
	t.Parallel()

	input := validInput(ExternalSendInput{
		DestinationScope: "EXTERNAL",
		Recipients:       []string{"customer@example.com"},
	})
	input.Actor.RuntimeID = "runtime_attacker"

	_, err := (ActionNormalizer{}).Normalize(
		mustAuthenticatedRuntime(t, "runtime_456"),
		input,
	)
	if !errors.Is(err, ErrRuntimeIdentityConflict) {
		t.Fatalf("error = %v, want %v", err, ErrRuntimeIdentityConflict)
	}
}

func TestActionNormalizerSuppliesAuthenticatedRuntimeWhenBodyOmitsIt(t *testing.T) {
	t.Parallel()

	input := validInput(ExternalSendInput{
		DestinationScope: "INTERNAL",
		Recipients:       []string{"team@example.com"},
	})
	input.Actor.RuntimeID = ""

	action, err := (ActionNormalizer{}).Normalize(
		mustAuthenticatedRuntime(t, "runtime_456"),
		input,
	)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got := action.Actor().RuntimeID(); got != "runtime_456" {
		t.Fatalf("runtime id = %q, want runtime_456", got)
	}
}

func TestActionNormalizerSupportsAllActionVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		typ        domain.ActionType
		parameters ActionParametersInput
	}{
		{
			name: "update resource access",
			typ:  domain.ActionUpdateResourceAccess,
			parameters: UpdateResourceAccessInput{
				CurrentScope:   "private",
				RequestedScope: "shared",
				TargetPrincipals: []PrincipalInput{
					{Type: domain.PrincipalUser, ID: "user_789"},
				},
			},
		},
		{
			name:       "delete",
			typ:        domain.ActionDelete,
			parameters: DeleteInput{DeleteMode: "hard", Recoverable: false},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validInput(test.parameters)
			input.Type = test.typ
			action, err := (ActionNormalizer{}).Normalize(
				mustAuthenticatedRuntime(t, "runtime_456"),
				input,
			)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if action.Type() != test.typ || action.Parameters().ActionType() != test.typ {
				t.Fatalf("action type = %q, parameter type = %q", action.Type(), action.Parameters().ActionType())
			}
		})
	}
}

func TestActionNormalizerRejectsInvalidActionFacts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ProposedActionInput)
	}{
		{name: "missing authenticated runtime", mutate: func(input *ProposedActionInput) {}},
		{name: "missing requested time", mutate: func(input *ProposedActionInput) { input.RequestedAt = time.Time{} }},
		{name: "missing recipients", mutate: func(input *ProposedActionInput) {
			input.Parameters = ExternalSendInput{DestinationScope: "EXTERNAL"}
		}},
		{name: "parameter mismatch", mutate: func(input *ProposedActionInput) {
			input.Type = domain.ActionDelete
		}},
		{name: "negative payload size", mutate: func(input *ProposedActionInput) {
			size := int64(-1)
			input.Payload.SizeBytes = &size
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input := validInput(ExternalSendInput{
				DestinationScope: "EXTERNAL",
				Recipients:       []string{"customer@example.com"},
			})
			test.mutate(&input)
			caller := mustAuthenticatedRuntime(t, "runtime_456")
			if test.name == "missing authenticated runtime" {
				caller = AuthenticatedRuntime{}
			}
			if _, err := (ActionNormalizer{}).Normalize(caller, input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}

func mustAuthenticatedRuntime(t *testing.T, runtimeID string) AuthenticatedRuntime {
	t.Helper()
	runtime, err := NewAuthenticatedRuntime(runtimeID)
	if err != nil {
		t.Fatalf("new authenticated runtime: %v", err)
	}
	return runtime
}

func validInput(parameters ActionParametersInput) ProposedActionInput {
	return ProposedActionInput{
		Type:        parameters.actionType(),
		RequestedAt: time.Date(2026, time.August, 2, 12, 0, 0, 0, time.FixedZone("test", -7*60*60)),
		Actor: ActorInput{
			AgentID:   " agent_123 ",
			RuntimeID: "runtime_456",
			SessionID: " session_123 ",
		},
		Delegation: DelegationInput{
			ID: " delegation_123 ",
			Delegator: PrincipalInput{
				Type: domain.PrincipalUser,
				ID:   " user_456 ",
			},
		},
		Target: TargetInput{
			ResourceType: " DOCUMENT ",
			ResourceID:   " document_123 ",
		},
		Parameters: parameters,
		Payload: PayloadInput{
			Digest: " sha256:1111111111111111111111111111111111111111111111111111111111111111 ",
		},
	}
}
