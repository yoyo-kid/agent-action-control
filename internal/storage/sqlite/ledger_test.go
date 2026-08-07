package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

func TestDecisionLedgerCommitAndReadReconstructsDomainValues(t *testing.T) {
	ledger, database := openTestLedger(t)
	commit := testCommit(t, "runtime-1", "request-1", "decision-1", "effect-1", "first@example.com")

	record, err := ledger.CommitEvaluation(context.Background(), commit)
	if err != nil {
		t.Fatalf("commit evaluation: %v", err)
	}
	if record.DecisionID != commit.DecisionID || record.ActionDigest != commit.ActionDigest {
		t.Fatalf("unexpected committed record: %#v", record)
	}

	stored, err := ledger.GetEvaluationByRequestID(context.Background(), commit.RuntimeID, commit.RequestID)
	if err != nil {
		t.Fatalf("read evaluation: %v", err)
	}
	if stored.RuntimeID != commit.RuntimeID || stored.RequestID != commit.RequestID {
		t.Fatalf("unexpected stored identity: %#v", stored)
	}
	if stored.Action.Actor().RuntimeID() != commit.RuntimeID || stored.Action.Type() != domain.ActionExternalSend {
		t.Fatalf("unexpected reconstructed action: %#v", stored.Action)
	}
	parameters, ok := stored.Action.Parameters().(domain.ExternalSendParameters)
	if !ok || len(parameters.Recipients()) != 1 || parameters.Recipients()[0] != "first@example.com" {
		t.Fatalf("unexpected reconstructed parameters: %#v", stored.Action.Parameters())
	}
	if stored.Decision.Decision.Type() != domain.DecisionAllow || stored.Decision.PolicyVersion != "policy-v1" {
		t.Fatalf("unexpected reconstructed decision: %#v", stored.Decision)
	}
	assertTableCount(t, database, "action_requests", 1)
	assertTableCount(t, database, "decisions", 1)
	assertTableCount(t, database, "policy_effects", 1)
}

func TestDecisionLedgerReconstructsDelegatorApprovalDecision(t *testing.T) {
	ledger, _ := openTestLedger(t)
	commit := testCommit(t, "runtime-1", "request-1", "decision-1", "effect-1", "first@example.com")
	decision, err := domain.NewDenyDecision(
		[]domain.ReasonCode{domain.ReasonExternalDestination, domain.ReasonDelegatorApprovalRequired},
		[]domain.RequiredAction{domain.NewRequireApprovalAction()},
	)
	if err != nil {
		t.Fatalf("create deny decision: %v", err)
	}
	commit.Decision = decision
	if _, err := ledger.CommitEvaluation(context.Background(), commit); err != nil {
		t.Fatalf("commit evaluation: %v", err)
	}

	stored, err := ledger.GetEvaluationByRequestID(context.Background(), commit.RuntimeID, commit.RequestID)
	if err != nil {
		t.Fatalf("read evaluation: %v", err)
	}
	got := stored.Decision.Decision
	if got.Type() != domain.DecisionDeny {
		t.Fatalf("decision type = %q, want DENY", got.Type())
	}
	if reasons := got.ReasonCodes(); len(reasons) != 2 || reasons[1] != domain.ReasonDelegatorApprovalRequired {
		t.Fatalf("unexpected reasons: %#v", reasons)
	}
	if actions := got.RequiredActions(); len(actions) != 1 || actions[0].Type() != domain.RequiredActionRequireApproval {
		t.Fatalf("unexpected required actions: %#v", actions)
	}
}

func TestActionSerializationRoundTripsEverySupportedVariant(t *testing.T) {
	sharedPrincipal, err := domain.NewPrincipal(domain.PrincipalUser, "user-2")
	if err != nil {
		t.Fatalf("create target principal: %v", err)
	}
	external, err := domain.NewExternalSendParameters(domain.DestinationExternal, []string{"first@example.com", "second@example.com"})
	if err != nil {
		t.Fatalf("create external send parameters: %v", err)
	}
	access, err := domain.NewUpdateResourceAccessParameters(domain.AccessPrivate, domain.AccessShared, []domain.Principal{sharedPrincipal})
	if err != nil {
		t.Fatalf("create access parameters: %v", err)
	}
	deleteParameters, err := domain.NewDeleteParameters(domain.DeleteHard, false)
	if err != nil {
		t.Fatalf("create delete parameters: %v", err)
	}

	tests := []struct {
		name       string
		typ        domain.ActionType
		parameters domain.ActionParameters
	}{
		{name: "external send", typ: domain.ActionExternalSend, parameters: external},
		{name: "update resource access", typ: domain.ActionUpdateResourceAccess, parameters: access},
		{name: "delete", typ: domain.ActionDelete, parameters: deleteParameters},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			action := testActionWithParameters(t, "runtime-1", test.typ, test.parameters)
			encoded, err := domain.CanonicalActionBytes(action)
			if err != nil {
				t.Fatalf("encode action: %v", err)
			}
			decoded, err := decodeAction(encoded)
			if err != nil {
				t.Fatalf("decode action: %v", err)
			}
			roundTrip, err := domain.CanonicalActionBytes(decoded)
			if err != nil {
				t.Fatalf("re-encode action: %v", err)
			}
			if string(roundTrip) != string(encoded) {
				t.Fatalf("round-trip mismatch\n got: %s\nwant: %s", roundTrip, encoded)
			}
		})
	}
}

func TestDecisionLedgerExactRetryReturnsCommittedWinner(t *testing.T) {
	ledger, database := openTestLedger(t)
	first := testCommit(t, "runtime-1", "request-1", "decision-first", "effect-first", "first@example.com")
	winner, err := ledger.CommitEvaluation(context.Background(), first)
	if err != nil {
		t.Fatalf("commit first evaluation: %v", err)
	}

	retry := first
	retry.DecisionID = "decision-retry"
	retry.Effects = []application.PolicyEffectCommit{{EffectID: "effect-retry", Effect: testSafetyReviewEffect(t)}}
	resolved, err := ledger.CommitEvaluation(context.Background(), retry)
	if err != nil {
		t.Fatalf("commit retry: %v", err)
	}
	if resolved.DecisionID != winner.DecisionID {
		t.Fatalf("retry returned %q, want committed winner %q", resolved.DecisionID, winner.DecisionID)
	}
	assertTableCount(t, database, "action_requests", 1)
	assertTableCount(t, database, "decisions", 1)
	assertTableCount(t, database, "policy_effects", 1)
}

func TestDecisionLedgerRejectsRequestIDReusedForDifferentAction(t *testing.T) {
	ledger, database := openTestLedger(t)
	first := testCommit(t, "runtime-1", "request-1", "decision-1", "effect-1", "first@example.com")
	if _, err := ledger.CommitEvaluation(context.Background(), first); err != nil {
		t.Fatalf("commit first evaluation: %v", err)
	}

	conflict := testCommit(t, "runtime-1", "request-1", "decision-2", "effect-2", "other@example.com")
	if _, err := ledger.CommitEvaluation(context.Background(), conflict); !errors.Is(err, application.ErrRequestIDConflict) {
		t.Fatalf("got %v, want request ID conflict", err)
	}
	assertTableCount(t, database, "action_requests", 1)
	assertTableCount(t, database, "decisions", 1)
	assertTableCount(t, database, "policy_effects", 1)
}

func TestDecisionLedgerScopesRequestIDsByRuntime(t *testing.T) {
	ledger, database := openTestLedger(t)
	for index, runtimeID := range []string{"runtime-1", "runtime-2"} {
		commit := testCommit(
			t,
			runtimeID,
			"shared-request",
			fmt.Sprintf("decision-%d", index),
			fmt.Sprintf("effect-%d", index),
			fmt.Sprintf("recipient-%d@example.com", index),
		)
		if _, err := ledger.CommitEvaluation(context.Background(), commit); err != nil {
			t.Fatalf("commit evaluation for %s: %v", runtimeID, err)
		}
	}
	assertTableCount(t, database, "action_requests", 2)
	assertTableCount(t, database, "decisions", 2)
	assertTableCount(t, database, "policy_effects", 2)
}

func TestDecisionLedgerRollsBackWholeEvaluationWhenEffectInsertFails(t *testing.T) {
	ledger, database := openTestLedger(t)
	first := testCommit(t, "runtime-1", "request-1", "decision-1", "shared-effect", "first@example.com")
	if _, err := ledger.CommitEvaluation(context.Background(), first); err != nil {
		t.Fatalf("commit first evaluation: %v", err)
	}

	failing := testCommit(t, "runtime-1", "request-2", "decision-2", "shared-effect", "second@example.com")
	record, err := ledger.CommitEvaluation(context.Background(), failing)
	if !errors.Is(err, application.ErrLedgerFailure) {
		t.Fatalf("got record %#v and error %v, want ledger failure", record, err)
	}
	if record.Decision.Type().Valid() {
		t.Fatalf("failed commit exposed a decision: %#v", record)
	}
	if _, err := ledger.GetEvaluationByRequestID(context.Background(), failing.RuntimeID, failing.RequestID); !errors.Is(err, application.ErrEvaluationNotFound) {
		t.Fatalf("rolled-back evaluation lookup returned %v", err)
	}
	assertTableCount(t, database, "action_requests", 1)
	assertTableCount(t, database, "decisions", 1)
	assertTableCount(t, database, "policy_effects", 1)
}

func TestDecisionLedgerConcurrentIdenticalCommitsConverge(t *testing.T) {
	ledger, database := openTestLedger(t)
	const workers = 12
	start := make(chan struct{})
	results := make(chan application.DecisionRecord, workers)
	errorsChannel := make(chan error, workers)
	var waitGroup sync.WaitGroup

	for index := 0; index < workers; index++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			commit := testCommit(
				t,
				"runtime-1",
				"request-1",
				fmt.Sprintf("decision-%d", index),
				fmt.Sprintf("effect-%d", index),
				"first@example.com",
			)
			<-start
			record, err := ledger.CommitEvaluation(context.Background(), commit)
			if err != nil {
				errorsChannel <- err
				return
			}
			results <- record
		}(index)
	}
	close(start)
	waitGroup.Wait()
	close(results)
	close(errorsChannel)

	for err := range errorsChannel {
		t.Errorf("concurrent commit failed: %v", err)
	}
	var winnerID string
	for record := range results {
		if winnerID == "" {
			winnerID = record.DecisionID
		}
		if record.DecisionID != winnerID {
			t.Errorf("got decision %q, want winner %q", record.DecisionID, winnerID)
		}
	}
	if winnerID == "" {
		t.Fatal("no concurrent commit succeeded")
	}
	assertTableCount(t, database, "action_requests", 1)
	assertTableCount(t, database, "decisions", 1)
	assertTableCount(t, database, "policy_effects", 1)
}

func TestDecisionLedgerRejectsInvalidCommitBeforeWriting(t *testing.T) {
	ledger, database := openTestLedger(t)
	commit := testCommit(t, "runtime-1", "request-1", "decision-1", "effect-1", "first@example.com")
	commit.RuntimeID = "another-runtime"

	if _, err := ledger.CommitEvaluation(context.Background(), commit); !errors.Is(err, application.ErrInvalidInput) {
		t.Fatalf("got %v, want invalid input", err)
	}
	assertTableCount(t, database, "action_requests", 0)
	assertTableCount(t, database, "decisions", 0)
	assertTableCount(t, database, "policy_effects", 0)
}

func openTestLedger(t *testing.T) (*DecisionLedger, *sql.DB) {
	t.Helper()
	database, err := Open(context.Background(), filepath.Join(t.TempDir(), "ledger.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ledger, err := NewDecisionLedger(database)
	if err != nil {
		t.Fatalf("create ledger: %v", err)
	}
	return ledger, database
}

func testCommit(
	t *testing.T,
	runtimeID string,
	requestID string,
	decisionID string,
	effectID string,
	recipient string,
) application.EvaluationCommit {
	t.Helper()
	action := testAction(t, runtimeID, recipient)
	digest, err := domain.ComputeActionDigest(action)
	if err != nil {
		t.Fatalf("compute action digest: %v", err)
	}
	return application.EvaluationCommit{
		RuntimeID:      runtimeID,
		RequestID:      requestID,
		Action:         action,
		ActionDigest:   digest,
		DecisionID:     decisionID,
		Decision:       domain.NewAllowDecision(),
		PolicyVersion:  "policy-v1",
		MatchedRuleIDs: []string{"rule-1"},
		Effects: []application.PolicyEffectCommit{{
			EffectID: effectID,
			Effect:   testSafetyReviewEffect(t),
		}},
		EvaluatedAt: time.Date(2026, 8, 6, 12, 0, 0, 123, time.UTC),
	}
}

func testAction(t *testing.T, runtimeID string, recipient string) domain.ProposedAction {
	t.Helper()
	parameters, err := domain.NewExternalSendParameters(domain.DestinationExternal, []string{recipient})
	if err != nil {
		t.Fatalf("create parameters: %v", err)
	}
	return testActionWithParameters(t, runtimeID, domain.ActionExternalSend, parameters)
}

func testActionWithParameters(
	t *testing.T,
	runtimeID string,
	typ domain.ActionType,
	parameters domain.ActionParameters,
) domain.ProposedAction {
	t.Helper()
	actor, err := domain.NewActor("agent-1", runtimeID, "session-1")
	if err != nil {
		t.Fatalf("create actor: %v", err)
	}
	delegator, err := domain.NewPrincipal(domain.PrincipalUser, "user-1")
	if err != nil {
		t.Fatalf("create delegator: %v", err)
	}
	delegation, err := domain.NewDelegation("delegation-1", delegator)
	if err != nil {
		t.Fatalf("create delegation: %v", err)
	}
	target, err := domain.NewTarget("resource", "resource-1")
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	payloadDigest, err := domain.ParsePayloadDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("parse payload digest: %v", err)
	}
	size := int64(42)
	payload, err := domain.NewPayloadFacts(payloadDigest, []string{"EMAIL"}, &size)
	if err != nil {
		t.Fatalf("create payload: %v", err)
	}
	var destinationScope domain.DestinationScope
	var requestedScope domain.AccessScope
	var deleteMode domain.DeleteMode
	switch typed := parameters.(type) {
	case domain.ExternalSendParameters:
		destinationScope = typed.DestinationScope()
	case domain.UpdateResourceAccessParameters:
		requestedScope = typed.RequestedScope()
	case domain.DeleteParameters:
		deleteMode = typed.Mode()
	}
	authorizationScope, err := domain.NewAuthorizationScope(typ, destinationScope, requestedScope, deleteMode)
	if err != nil {
		t.Fatalf("create authorization scope: %v", err)
	}
	evidence, err := domain.NewAuthorizationEvidence(
		domain.EvidenceDelegationGrant,
		"evidence-1",
		delegator,
		authorizationScope,
	)
	if err != nil {
		t.Fatalf("create authorization evidence: %v", err)
	}
	action, err := domain.NewProposedAction(
		typ,
		time.Date(2026, 8, 6, 11, 0, 0, 0, time.UTC),
		actor,
		delegation,
		target,
		parameters,
		payload,
		[]domain.AuthorizationEvidence{evidence},
	)
	if err != nil {
		t.Fatalf("create action: %v", err)
	}
	return action
}

func testSafetyReviewEffect(t *testing.T) domain.CreateSafetyReviewEffect {
	t.Helper()
	requirement, err := domain.NewSafetyReviewRequirement(domain.SafetyReviewHigh, []string{"evidence-1"})
	if err != nil {
		t.Fatalf("create safety review requirement: %v", err)
	}
	effect, err := domain.NewCreateSafetyReviewEffect(requirement)
	if err != nil {
		t.Fatalf("create safety review effect: %v", err)
	}
	return effect
}

func assertTableCount(t *testing.T, database *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s count = %d, want %d", table, got, want)
	}
}
