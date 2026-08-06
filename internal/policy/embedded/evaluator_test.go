package embedded

import (
	"context"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

func TestEvaluatorAndComposerScenarios(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		action      domain.ProposedAction
		wantType    domain.DecisionType
		wantReasons []domain.ReasonCode
		wantActions int
		wantEffects int
	}{
		{
			name:     "direct allow",
			action:   externalSendAction(t, domain.DestinationInternal, false, false, false),
			wantType: domain.DecisionAllow,
		},
		{
			name:        "external send requires approval",
			action:      externalSendAction(t, domain.DestinationExternal, false, false, false),
			wantType:    domain.DecisionDeny,
			wantReasons: []domain.ReasonCode{domain.ReasonDelegatorApprovalRequired, domain.ReasonExternalDestination},
			wantActions: 1,
		},
		{
			name:     "matching runtime evidence allows external send",
			action:   externalSendAction(t, domain.DestinationExternal, true, false, false),
			wantType: domain.DecisionAllow,
		},
		{
			name:        "permission mismatch is terminal",
			action:      externalSendAction(t, domain.DestinationExternal, false, true, false),
			wantType:    domain.DecisionDeny,
			wantReasons: []domain.ReasonCode{domain.ReasonActorNotAuthorized},
		},
		{
			name:        "private to public requires approval",
			action:      accessAction(t, domain.AccessPrivate, domain.AccessPublic),
			wantType:    domain.DecisionDeny,
			wantReasons: []domain.ReasonCode{domain.ReasonDelegatorApprovalRequired, domain.ReasonVisibilityExpansion},
			wantActions: 1,
		},
		{
			name:        "destructive delete requires approval",
			action:      deleteAction(t, domain.DeleteHard, false),
			wantType:    domain.DecisionDeny,
			wantReasons: []domain.ReasonCode{domain.ReasonDelegatorApprovalRequired, domain.ReasonDestructiveOperation},
			wantActions: 1,
		},
		{
			name:        "internal safety review only",
			action:      externalSendAction(t, domain.DestinationInternal, false, false, true),
			wantType:    domain.DecisionAllow,
			wantEffects: 1,
		},
		{
			name:        "approval plus internal review",
			action:      externalSendAction(t, domain.DestinationExternal, false, false, true),
			wantType:    domain.DecisionDeny,
			wantReasons: []domain.ReasonCode{domain.ReasonDelegatorApprovalRequired, domain.ReasonExternalDestination},
			wantActions: 1,
			wantEffects: 1,
		},
	}

	evaluator := Evaluator{}
	composer := application.DecisionComposer{}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			evaluation, err := evaluator.Evaluate(context.Background(), test.action)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			decision, err := composer.Compose(evaluation)
			if err != nil {
				t.Fatalf("compose: %v", err)
			}
			if decision.Type() != test.wantType {
				t.Fatalf("decision type = %q, want %q", decision.Type(), test.wantType)
			}
			if !equalReasons(decision.ReasonCodes(), test.wantReasons) {
				t.Fatalf("reason codes = %v, want %v", decision.ReasonCodes(), test.wantReasons)
			}
			if got := len(decision.RequiredActions()); got != test.wantActions {
				t.Fatalf("required actions = %d, want %d", got, test.wantActions)
			}
			if got := len(evaluation.Effects); got != test.wantEffects {
				t.Fatalf("effects = %d, want %d", got, test.wantEffects)
			}
			if evaluation.PolicyVersion != Version {
				t.Fatalf("policy version = %q", evaluation.PolicyVersion)
			}
		})
	}
}

func externalSendAction(
	t *testing.T,
	scope domain.DestinationScope,
	matchingEvidence bool,
	mismatchedEvidence bool,
	secret bool,
) domain.ProposedAction {
	t.Helper()
	parameters, err := domain.NewExternalSendParameters(scope, []string{"customer@example.com"})
	if err != nil {
		t.Fatalf("new external send parameters: %v", err)
	}
	var evidence []domain.AuthorizationEvidence
	if matchingEvidence || mismatchedEvidence {
		runtimeID := "runtime_123"
		if mismatchedEvidence {
			runtimeID = "runtime_other"
		}
		issuer, _ := domain.NewPrincipal(domain.PrincipalRuntime, runtimeID)
		evidenceScope, _ := domain.NewAuthorizationScope(domain.ActionExternalSend, scope, "", "")
		item, _ := domain.NewAuthorizationEvidence(domain.EvidenceUserInstruction, "message_123", issuer, evidenceScope)
		evidence = []domain.AuthorizationEvidence{item}
	}
	classification := []string(nil)
	if secret {
		classification = []string{"SECRET"}
	}
	return proposedAction(t, domain.ActionExternalSend, parameters, classification, evidence)
}

func accessAction(t *testing.T, current, requested domain.AccessScope) domain.ProposedAction {
	t.Helper()
	parameters, err := domain.NewUpdateResourceAccessParameters(current, requested, nil)
	if err != nil {
		t.Fatalf("new access parameters: %v", err)
	}
	return proposedAction(t, domain.ActionUpdateResourceAccess, parameters, nil, nil)
}

func deleteAction(t *testing.T, mode domain.DeleteMode, recoverable bool) domain.ProposedAction {
	t.Helper()
	parameters, err := domain.NewDeleteParameters(mode, recoverable)
	if err != nil {
		t.Fatalf("new delete parameters: %v", err)
	}
	return proposedAction(t, domain.ActionDelete, parameters, nil, nil)
}

func proposedAction(
	t *testing.T,
	typ domain.ActionType,
	parameters domain.ActionParameters,
	classification []string,
	evidence []domain.AuthorizationEvidence,
) domain.ProposedAction {
	t.Helper()
	actor, _ := domain.NewActor("agent_123", "runtime_123", "session_123")
	delegator, _ := domain.NewPrincipal(domain.PrincipalUser, "user_123")
	delegation, _ := domain.NewDelegation("delegation_123", delegator)
	target, _ := domain.NewTarget("DOCUMENT", "document_123")
	digest, _ := domain.ParsePayloadDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	payload, _ := domain.NewPayloadFacts(digest, classification, nil)
	action, err := domain.NewProposedAction(
		typ,
		time.Date(2026, time.August, 5, 12, 0, 0, 0, time.UTC),
		actor,
		delegation,
		target,
		parameters,
		payload,
		evidence,
	)
	if err != nil {
		t.Fatalf("new proposed action: %v", err)
	}
	return action
}

func equalReasons(left, right []domain.ReasonCode) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
