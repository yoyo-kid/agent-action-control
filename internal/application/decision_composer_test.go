package application

import (
	"testing"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

func TestDecisionComposerPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		reasons     []domain.ReasonCode
		wantType    domain.DecisionType
		wantReasons []domain.ReasonCode
		wantActions int
	}{
		{name: "direct allow", wantType: domain.DecisionAllow},
		{
			name: "delegator approval",
			reasons: []domain.ReasonCode{
				domain.ReasonDelegatorApprovalRequired,
				domain.ReasonExternalDestination,
			},
			wantType:    domain.DecisionDeny,
			wantReasons: []domain.ReasonCode{domain.ReasonDelegatorApprovalRequired, domain.ReasonExternalDestination},
			wantActions: 1,
		},
		{
			name: "terminal deny overrides approval",
			reasons: []domain.ReasonCode{
				domain.ReasonDelegatorApprovalRequired,
				domain.ReasonActorNotAuthorized,
			},
			wantType:    domain.DecisionDeny,
			wantReasons: []domain.ReasonCode{domain.ReasonActorNotAuthorized},
		},
		{
			name:        "reason without approval signal is terminal",
			reasons:     []domain.ReasonCode{domain.ReasonExternalDestination},
			wantType:    domain.DecisionDeny,
			wantReasons: []domain.ReasonCode{domain.ReasonExternalDestination},
		},
	}

	composer := DecisionComposer{}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decision, err := composer.Compose(PolicyEvaluation{DenyReasonCodes: test.reasons})
			if err != nil {
				t.Fatalf("compose decision: %v", err)
			}
			if decision.Type() != test.wantType {
				t.Fatalf("decision type = %q, want %q", decision.Type(), test.wantType)
			}
			if !equalReasonCodes(decision.ReasonCodes(), test.wantReasons) {
				t.Fatalf("reason codes = %v, want %v", decision.ReasonCodes(), test.wantReasons)
			}
			if got := len(decision.RequiredActions()); got != test.wantActions {
				t.Fatalf("required actions = %d, want %d", got, test.wantActions)
			}
		})
	}
}

func equalReasonCodes(left, right []domain.ReasonCode) bool {
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

func TestDecisionComposerDeduplicatesReasons(t *testing.T) {
	t.Parallel()

	decision, err := (DecisionComposer{}).Compose(PolicyEvaluation{DenyReasonCodes: []domain.ReasonCode{
		domain.ReasonDelegatorApprovalRequired,
		domain.ReasonExternalDestination,
		domain.ReasonDelegatorApprovalRequired,
	}})
	if err != nil {
		t.Fatalf("compose decision: %v", err)
	}
	if got := decision.ReasonCodes(); len(got) != 2 || got[0] != domain.ReasonDelegatorApprovalRequired || got[1] != domain.ReasonExternalDestination {
		t.Fatalf("reason codes = %v", got)
	}
	if got := decision.RequiredActions(); len(got) != 1 || got[0].Type() != domain.RequiredActionRequireApproval {
		t.Fatalf("required actions = %v", got)
	}
}

func TestDecisionComposerDoesNotExposeInternalEffects(t *testing.T) {
	t.Parallel()

	requirement, err := domain.NewSafetyReviewRequirement(domain.SafetyReviewHigh, []string{"message_123"})
	if err != nil {
		t.Fatalf("new safety review requirement: %v", err)
	}
	effect, err := domain.NewCreateSafetyReviewEffect(requirement)
	if err != nil {
		t.Fatalf("new safety review effect: %v", err)
	}
	decision, err := (DecisionComposer{}).Compose(PolicyEvaluation{Effects: []domain.PolicyEffect{effect}})
	if err != nil {
		t.Fatalf("compose decision: %v", err)
	}
	if decision.Type() != domain.DecisionAllow || len(decision.RequiredActions()) != 0 {
		t.Fatalf("decision = %q, required actions = %v", decision.Type(), decision.RequiredActions())
	}
}
