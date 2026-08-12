package osprey

import (
	"context"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

func TestEvaluatorIntegratesWithDecisionServiceAndLedger(t *testing.T) {
	verdicts := []string{
		"require_delegator_approval.external_send",
		"create_safety_review.secret_payload",
	}
	evaluator := newTestEvaluator(t, &fakeCoordinator{response: validResponse(verdicts...)}, time.Second)
	ledger := &recordingLedger{}
	service, err := application.NewDecisionService(
		evaluator,
		ledger,
		fixedClock{value: time.Date(2026, time.August, 12, 13, 0, 0, 0, time.UTC)},
		fixedIDs{},
	)
	if err != nil {
		t.Fatalf("new decision service: %v", err)
	}
	runtime, err := application.NewAuthenticatedRuntime("runtime-1")
	if err != nil {
		t.Fatal(err)
	}
	record, err := service.Evaluate(context.Background(), runtime, testCommand())
	if err != nil {
		t.Fatalf("evaluate decision: %v", err)
	}
	if record.Decision.Type() != domain.DecisionDeny ||
		len(record.Decision.RequiredActions()) != 1 ||
		record.Decision.RequiredActions()[0].Type() != domain.RequiredActionRequireApproval {
		t.Fatalf("decision = %#v", record.Decision)
	}
	if len(ledger.commits) != 1 {
		t.Fatalf("commits = %d", len(ledger.commits))
	}
	commit := ledger.commits[0]
	if commit.PolicyVersion != testPolicyVersion || len(commit.MatchedRuleIDs) != 2 ||
		commit.MatchedRuleIDs[0] != verdicts[0] || commit.MatchedRuleIDs[1] != verdicts[1] {
		t.Fatalf("policy audit fields = %#v", commit)
	}
	if len(commit.Effects) != 1 || commit.Effects[0].Effect.Type() != domain.PolicyEffectCreateSafetyReview {
		t.Fatalf("effects = %#v", commit.Effects)
	}
}

func testCommand() application.EvaluateActionCommand {
	size := int64(42)
	return application.EvaluateActionCommand{
		RequestID: "request-1",
		ProposedAction: application.ProposedActionInput{
			Type:        domain.ActionExternalSend,
			RequestedAt: time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC),
			Actor: application.ActorInput{
				AgentID:   "agent-1",
				RuntimeID: "runtime-1",
				SessionID: "session-1",
			},
			Delegation: application.DelegationInput{
				ID: "delegation-1",
				Delegator: application.PrincipalInput{
					Type: domain.PrincipalUser,
					ID:   "user-1",
				},
			},
			Target: application.TargetInput{ResourceType: "EMAIL_DRAFT", ResourceID: "draft-1"},
			Parameters: application.ExternalSendInput{
				DestinationScope: string(domain.DestinationExternal),
				Recipients:       []string{"customer@example.com"},
			},
			Payload: application.PayloadInput{
				Digest:         "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Classification: []string{"CONFIDENTIAL"},
				SizeBytes:      &size,
			},
		},
	}
}

type recordingLedger struct {
	commits []application.EvaluationCommit
}

func (*recordingLedger) GetEvaluationByRequestID(
	context.Context,
	string,
	string,
) (*application.StoredEvaluation, error) {
	return nil, application.ErrEvaluationNotFound
}

func (ledger *recordingLedger) CommitEvaluation(
	_ context.Context,
	commit application.EvaluationCommit,
) (application.DecisionRecord, error) {
	ledger.commits = append(ledger.commits, commit)
	return application.DecisionRecord{
		DecisionID:     commit.DecisionID,
		Decision:       commit.Decision,
		ActionDigest:   commit.ActionDigest,
		PolicyVersion:  commit.PolicyVersion,
		MatchedRuleIDs: append([]string(nil), commit.MatchedRuleIDs...),
		EvaluatedAt:    commit.EvaluatedAt,
	}, nil
}

type fixedClock struct{ value time.Time }

func (clock fixedClock) Now() time.Time { return clock.value }

type fixedIDs struct{}

func (fixedIDs) NewID(kind application.IDKind) (string, error) {
	switch kind {
	case application.IDDecision:
		return "decision-1", nil
	case application.IDPolicyEffect:
		return "effect-1", nil
	default:
		return "", nil
	}
}
