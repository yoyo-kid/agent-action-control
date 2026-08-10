package application

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

func TestDecisionServiceEvaluatesAndCommitsAuthoritativeDecision(t *testing.T) {
	events := make([]string, 0)
	effect := newTestSafetyReviewEffect(t)
	policy := &recordingPolicyEvaluator{
		events: &events,
		evaluation: PolicyEvaluation{
			DenyReasonCodes: []domain.ReasonCode{
				domain.ReasonDelegatorApprovalRequired,
				domain.ReasonExternalDestination,
			},
			Effects:        []domain.PolicyEffect{effect},
			MatchedRuleIDs: []string{"rule-external", "rule-review"},
			PolicyVersion:  "policy-v1",
		},
	}
	ledger := &recordingDecisionLedger{events: &events}
	clock := &recordingClock{events: &events, value: testEvaluatedAt()}
	ids := &recordingIDGenerator{
		events: &events,
		values: map[IDKind][]string{
			IDDecision:     {"decision-1"},
			IDPolicyEffect: {"effect-1"},
		},
	}
	service := newTestDecisionService(t, policy, ledger, clock, ids)

	record, err := service.Evaluate(
		context.Background(),
		mustAuthenticatedRuntime(t, "runtime-1"),
		EvaluateActionCommand{RequestID: " request-1 ", ProposedAction: serviceTestInput("runtime-1")},
	)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if record.DecisionID != "decision-1" || record.Decision.Type() != domain.DecisionDeny {
		t.Fatalf("unexpected decision record: %#v", record)
	}
	if reasons := record.Decision.ReasonCodes(); len(reasons) != 2 || reasons[0] != domain.ReasonDelegatorApprovalRequired {
		t.Fatalf("unexpected reasons: %v", reasons)
	}
	if actions := record.Decision.RequiredActions(); len(actions) != 1 || actions[0].Type() != domain.RequiredActionRequireApproval {
		t.Fatalf("unexpected required actions: %v", actions)
	}
	if len(ledger.commits) != 1 {
		t.Fatalf("commit calls = %d, want 1", len(ledger.commits))
	}
	commit := ledger.commits[0]
	if commit.RuntimeID != "runtime-1" || commit.RequestID != "request-1" {
		t.Fatalf("unexpected commit identity: %#v", commit)
	}
	if !commit.ActionDigest.Valid() || commit.Action.Actor().RuntimeID() != "runtime-1" {
		t.Fatalf("action was not normalized and hashed: %#v", commit)
	}
	if len(commit.Effects) != 1 || commit.Effects[0].EffectID != "effect-1" {
		t.Fatalf("unexpected committed effects: %#v", commit.Effects)
	}
	if !reflect.DeepEqual(events, []string{
		"ledger.lookup",
		"policy.evaluate",
		"id.DECISION",
		"id.POLICY_EFFECT",
		"clock.now",
		"ledger.commit",
	}) {
		t.Fatalf("operation order = %v", events)
	}
}

func TestDecisionServiceExactRetryReturnsBeforePolicyEvaluation(t *testing.T) {
	input := serviceTestInput("runtime-1")
	action, digest := normalizedTestAction(t, "runtime-1", input)
	winner := DecisionRecord{
		DecisionID:    "decision-winner",
		Decision:      domain.NewAllowDecision(),
		ActionDigest:  digest,
		PolicyVersion: "policy-v1",
		EvaluatedAt:   testEvaluatedAt(),
	}
	ledger := &recordingDecisionLedger{stored: &StoredEvaluation{
		RuntimeID: "runtime-1",
		RequestID: "request-1",
		Action:    action,
		Decision:  winner,
	}}
	policy := &recordingPolicyEvaluator{}
	clock := &recordingClock{value: testEvaluatedAt()}
	ids := &recordingIDGenerator{}
	service := newTestDecisionService(t, policy, ledger, clock, ids)

	record, err := service.Evaluate(
		context.Background(),
		mustAuthenticatedRuntime(t, "runtime-1"),
		EvaluateActionCommand{RequestID: "request-1", ProposedAction: input},
	)
	if err != nil {
		t.Fatalf("evaluate retry: %v", err)
	}
	if record.DecisionID != winner.DecisionID {
		t.Fatalf("decision id = %q, want %q", record.DecisionID, winner.DecisionID)
	}
	if policy.calls != 0 || ids.calls != 0 || clock.calls != 0 || len(ledger.commits) != 0 {
		t.Fatalf("retry performed new work: policy=%d ids=%d clock=%d commits=%d", policy.calls, ids.calls, clock.calls, len(ledger.commits))
	}
}

func TestDecisionServiceRejectsRequestIDConflictBeforePolicyEvaluation(t *testing.T) {
	input := serviceTestInput("runtime-1")
	action, _ := normalizedTestAction(t, "runtime-1", input)
	otherInput := input
	otherInput.Parameters = ExternalSendInput{
		DestinationScope: "EXTERNAL",
		Recipients:       []string{"other@example.com"},
	}
	_, otherDigest := normalizedTestAction(t, "runtime-1", otherInput)
	ledger := &recordingDecisionLedger{stored: &StoredEvaluation{
		RuntimeID: "runtime-1",
		RequestID: "request-1",
		Action:    action,
		Decision: DecisionRecord{
			DecisionID:    "decision-existing",
			Decision:      domain.NewAllowDecision(),
			ActionDigest:  otherDigest,
			PolicyVersion: "policy-v1",
			EvaluatedAt:   testEvaluatedAt(),
		},
	}}
	policy := &recordingPolicyEvaluator{}
	service := newTestDecisionService(
		t,
		policy,
		ledger,
		&recordingClock{value: testEvaluatedAt()},
		&recordingIDGenerator{},
	)

	record, err := service.Evaluate(
		context.Background(),
		mustAuthenticatedRuntime(t, "runtime-1"),
		EvaluateActionCommand{RequestID: "request-1", ProposedAction: input},
	)
	if !errors.Is(err, ErrRequestIDConflict) {
		t.Fatalf("got record %#v and error %v, want request ID conflict", record, err)
	}
	if record.Decision.Type().Valid() || policy.calls != 0 || len(ledger.commits) != 0 {
		t.Fatalf("conflict produced executable work: record=%#v policy=%d commits=%d", record, policy.calls, len(ledger.commits))
	}
}

func TestDecisionServiceScopesSameRequestIDByRuntime(t *testing.T) {
	ledger := &recordingDecisionLedger{}
	policy := &recordingPolicyEvaluator{evaluation: PolicyEvaluation{PolicyVersion: "policy-v1"}}
	service := newTestDecisionService(
		t,
		policy,
		ledger,
		&recordingClock{value: testEvaluatedAt()},
		&recordingIDGenerator{values: map[IDKind][]string{IDDecision: {"decision-1", "decision-2"}}},
	)

	for _, runtimeID := range []string{"runtime-1", "runtime-2"} {
		_, err := service.Evaluate(
			context.Background(),
			mustAuthenticatedRuntime(t, runtimeID),
			EvaluateActionCommand{RequestID: "shared-request", ProposedAction: serviceTestInput(runtimeID)},
		)
		if err != nil {
			t.Fatalf("evaluate for %s: %v", runtimeID, err)
		}
	}
	if !reflect.DeepEqual(ledger.lookupRuntimeIDs, []string{"runtime-1", "runtime-2"}) {
		t.Fatalf("lookup runtime IDs = %v", ledger.lookupRuntimeIDs)
	}
	if len(ledger.commits) != 2 || ledger.commits[0].RuntimeID == ledger.commits[1].RuntimeID {
		t.Fatalf("cross-runtime commits = %#v", ledger.commits)
	}
}

func TestDecisionServiceFailsClosedOnDependencyErrors(t *testing.T) {
	dependencyError := errors.New("dependency failed")
	tests := []struct {
		name       string
		policy     *recordingPolicyEvaluator
		ledger     *recordingDecisionLedger
		ids        *recordingIDGenerator
		want       error
		wantPolicy int
		wantCommit int
	}{
		{
			name:   "ledger lookup",
			policy: &recordingPolicyEvaluator{},
			ledger: &recordingDecisionLedger{lookupErr: dependencyError},
			ids:    &recordingIDGenerator{},
			want:   ErrLedgerFailure,
		},
		{
			name:       "policy evaluator",
			policy:     &recordingPolicyEvaluator{err: dependencyError},
			ledger:     &recordingDecisionLedger{},
			ids:        &recordingIDGenerator{},
			want:       ErrPolicyUnavailable,
			wantPolicy: 1,
		},
		{
			name:       "decision ID",
			policy:     &recordingPolicyEvaluator{evaluation: PolicyEvaluation{PolicyVersion: "policy-v1"}},
			ledger:     &recordingDecisionLedger{},
			ids:        &recordingIDGenerator{err: dependencyError},
			want:       ErrIDGeneration,
			wantPolicy: 1,
		},
		{
			name:       "ledger commit",
			policy:     &recordingPolicyEvaluator{evaluation: PolicyEvaluation{PolicyVersion: "policy-v1"}},
			ledger:     &recordingDecisionLedger{commitErr: dependencyError},
			ids:        &recordingIDGenerator{values: map[IDKind][]string{IDDecision: {"decision-1"}}},
			want:       ErrLedgerFailure,
			wantPolicy: 1,
			wantCommit: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newTestDecisionService(
				t,
				test.policy,
				test.ledger,
				&recordingClock{value: testEvaluatedAt()},
				test.ids,
			)
			record, err := service.Evaluate(
				context.Background(),
				mustAuthenticatedRuntime(t, "runtime-1"),
				EvaluateActionCommand{RequestID: "request-1", ProposedAction: serviceTestInput("runtime-1")},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("got record %#v and error %v, want %v", record, err, test.want)
			}
			if record.Decision.Type().Valid() {
				t.Fatalf("failure exposed executable decision: %#v", record)
			}
			if test.policy.calls != test.wantPolicy || len(test.ledger.commits) != test.wantCommit {
				t.Fatalf("calls: policy=%d commits=%d", test.policy.calls, len(test.ledger.commits))
			}
		})
	}
}

func TestDecisionServiceRejectsInvalidPolicyOutput(t *testing.T) {
	tests := []struct {
		name       string
		evaluation PolicyEvaluation
	}{
		{name: "missing policy version", evaluation: PolicyEvaluation{}},
		{
			name: "empty matched rule ID",
			evaluation: PolicyEvaluation{
				PolicyVersion:  "policy-v1",
				MatchedRuleIDs: []string{" "},
			},
		},
		{
			name: "nil policy effect",
			evaluation: PolicyEvaluation{
				PolicyVersion: "policy-v1",
				Effects:       []domain.PolicyEffect{(*domain.CreateSafetyReviewEffect)(nil)},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger := &recordingDecisionLedger{}
			ids := &recordingIDGenerator{values: map[IDKind][]string{IDDecision: {"decision-1"}}}
			service := newTestDecisionService(
				t,
				&recordingPolicyEvaluator{evaluation: test.evaluation},
				ledger,
				&recordingClock{value: testEvaluatedAt()},
				ids,
			)
			record, err := service.Evaluate(
				context.Background(),
				mustAuthenticatedRuntime(t, "runtime-1"),
				EvaluateActionCommand{RequestID: "request-1", ProposedAction: serviceTestInput("runtime-1")},
			)
			if !errors.Is(err, ErrPolicyUnavailable) || record.Decision.Type().Valid() {
				t.Fatalf("got record %#v and error %v, want fail-closed policy error", record, err)
			}
			if ids.calls != 0 || len(ledger.commits) != 0 {
				t.Fatalf("invalid policy output reached persistence: ids=%d commits=%d", ids.calls, len(ledger.commits))
			}
		})
	}
}

func TestDecisionServiceFailsClosedOnInvalidClockOrLedgerResult(t *testing.T) {
	t.Run("zero clock", func(t *testing.T) {
		ledger := &recordingDecisionLedger{}
		service := newTestDecisionService(
			t,
			&recordingPolicyEvaluator{evaluation: PolicyEvaluation{PolicyVersion: "policy-v1"}},
			ledger,
			&recordingClock{},
			&recordingIDGenerator{values: map[IDKind][]string{IDDecision: {"decision-1"}}},
		)
		record, err := service.Evaluate(
			context.Background(),
			mustAuthenticatedRuntime(t, "runtime-1"),
			EvaluateActionCommand{RequestID: "request-1", ProposedAction: serviceTestInput("runtime-1")},
		)
		if !errors.Is(err, ErrClockFailure) || record.Decision.Type().Valid() || len(ledger.commits) != 0 {
			t.Fatalf("got record %#v, error %v, commits %d", record, err, len(ledger.commits))
		}
	})

	t.Run("invalid committed record", func(t *testing.T) {
		ledger := &recordingDecisionLedger{commitRecord: &DecisionRecord{}}
		service := newTestDecisionService(
			t,
			&recordingPolicyEvaluator{evaluation: PolicyEvaluation{PolicyVersion: "policy-v1"}},
			ledger,
			&recordingClock{value: testEvaluatedAt()},
			&recordingIDGenerator{values: map[IDKind][]string{IDDecision: {"decision-1"}}},
		)
		record, err := service.Evaluate(
			context.Background(),
			mustAuthenticatedRuntime(t, "runtime-1"),
			EvaluateActionCommand{RequestID: "request-1", ProposedAction: serviceTestInput("runtime-1")},
		)
		if !errors.Is(err, ErrLedgerFailure) || record.Decision.Type().Valid() {
			t.Fatalf("got record %#v and error %v, want fail-closed ledger error", record, err)
		}
	})
}

func TestNewDecisionServiceRequiresDependencies(t *testing.T) {
	policy := &recordingPolicyEvaluator{}
	ledger := &recordingDecisionLedger{}
	clock := &recordingClock{value: testEvaluatedAt()}
	ids := &recordingIDGenerator{}
	tests := []struct {
		name   string
		policy PolicyEvaluator
		ledger DecisionLedger
		clock  Clock
		ids    IDGenerator
	}{
		{name: "policy", ledger: ledger, clock: clock, ids: ids},
		{name: "ledger", policy: policy, clock: clock, ids: ids},
		{name: "clock", policy: policy, ledger: ledger, ids: ids},
		{name: "ids", policy: policy, ledger: ledger, clock: clock},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := NewDecisionService(test.policy, test.ledger, test.clock, test.ids)
			if service != nil || !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("service=%#v error=%v", service, err)
			}
		})
	}
}

func TestDecisionServicePreservesConflictDiscoveredDuringCommit(t *testing.T) {
	ledger := &recordingDecisionLedger{commitErr: ErrRequestIDConflict}
	service := newTestDecisionService(
		t,
		&recordingPolicyEvaluator{evaluation: PolicyEvaluation{PolicyVersion: "policy-v1"}},
		ledger,
		&recordingClock{value: testEvaluatedAt()},
		&recordingIDGenerator{values: map[IDKind][]string{IDDecision: {"decision-1"}}},
	)

	_, err := service.Evaluate(
		context.Background(),
		mustAuthenticatedRuntime(t, "runtime-1"),
		EvaluateActionCommand{RequestID: "request-1", ProposedAction: serviceTestInput("runtime-1")},
	)
	if !errors.Is(err, ErrRequestIDConflict) || errors.Is(err, ErrLedgerFailure) {
		t.Fatalf("error = %v, want only request ID conflict", err)
	}
}

func TestDecisionServiceRejectsInvalidInputBeforeDependencies(t *testing.T) {
	policy := &recordingPolicyEvaluator{}
	ledger := &recordingDecisionLedger{}
	service := newTestDecisionService(
		t,
		policy,
		ledger,
		&recordingClock{value: testEvaluatedAt()},
		&recordingIDGenerator{},
	)

	_, err := service.Evaluate(
		context.Background(),
		mustAuthenticatedRuntime(t, "runtime-1"),
		EvaluateActionCommand{RequestID: " ", ProposedAction: serviceTestInput("runtime-1")},
	)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want invalid input", err)
	}
	if ledger.lookupCalls != 0 || policy.calls != 0 {
		t.Fatalf("invalid input reached dependencies: lookups=%d policy=%d", ledger.lookupCalls, policy.calls)
	}
}

func newTestDecisionService(
	t *testing.T,
	policy PolicyEvaluator,
	ledger DecisionLedger,
	clock Clock,
	ids IDGenerator,
) *DecisionService {
	t.Helper()
	service, err := NewDecisionService(policy, ledger, clock, ids)
	if err != nil {
		t.Fatalf("new decision service: %v", err)
	}
	return service
}

func serviceTestInput(runtimeID string) ProposedActionInput {
	input := validInput(ExternalSendInput{
		DestinationScope: " EXTERNAL ",
		Recipients:       []string{" customer@example.com "},
	})
	input.Actor.RuntimeID = runtimeID
	return input
}

func normalizedTestAction(
	t *testing.T,
	runtimeID string,
	input ProposedActionInput,
) (domain.ProposedAction, domain.ActionDigest) {
	t.Helper()
	action, err := (ActionNormalizer{}).Normalize(mustAuthenticatedRuntime(t, runtimeID), input)
	if err != nil {
		t.Fatalf("normalize test action: %v", err)
	}
	digest, err := domain.ComputeActionDigest(action)
	if err != nil {
		t.Fatalf("compute test digest: %v", err)
	}
	return action, digest
}

func newTestSafetyReviewEffect(t *testing.T) domain.CreateSafetyReviewEffect {
	t.Helper()
	requirement, err := domain.NewSafetyReviewRequirement(domain.SafetyReviewHigh, []string{"evidence-1"})
	if err != nil {
		t.Fatalf("new safety review requirement: %v", err)
	}
	effect, err := domain.NewCreateSafetyReviewEffect(requirement)
	if err != nil {
		t.Fatalf("new safety review effect: %v", err)
	}
	return effect
}

func testEvaluatedAt() time.Time {
	return time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
}

type recordingPolicyEvaluator struct {
	events     *[]string
	evaluation PolicyEvaluation
	err        error
	calls      int
}

func (evaluator *recordingPolicyEvaluator) Evaluate(
	_ context.Context,
	_ domain.ProposedAction,
) (PolicyEvaluation, error) {
	evaluator.calls++
	appendTestEvent(evaluator.events, "policy.evaluate")
	return evaluator.evaluation, evaluator.err
}

type recordingDecisionLedger struct {
	events           *[]string
	stored           *StoredEvaluation
	lookupErr        error
	commitErr        error
	commitRecord     *DecisionRecord
	lookupCalls      int
	lookupRuntimeIDs []string
	commits          []EvaluationCommit
}

func (ledger *recordingDecisionLedger) GetEvaluationByRequestID(
	_ context.Context,
	runtimeID string,
	_ string,
) (*StoredEvaluation, error) {
	ledger.lookupCalls++
	ledger.lookupRuntimeIDs = append(ledger.lookupRuntimeIDs, runtimeID)
	appendTestEvent(ledger.events, "ledger.lookup")
	if ledger.lookupErr != nil {
		return nil, ledger.lookupErr
	}
	if ledger.stored != nil {
		return ledger.stored, nil
	}
	return nil, ErrEvaluationNotFound
}

func (ledger *recordingDecisionLedger) CommitEvaluation(
	_ context.Context,
	commit EvaluationCommit,
) (DecisionRecord, error) {
	ledger.commits = append(ledger.commits, commit)
	appendTestEvent(ledger.events, "ledger.commit")
	if ledger.commitErr != nil {
		return DecisionRecord{}, ledger.commitErr
	}
	if ledger.commitRecord != nil {
		return *ledger.commitRecord, nil
	}
	return DecisionRecord{
		DecisionID:     commit.DecisionID,
		Decision:       commit.Decision,
		ActionDigest:   commit.ActionDigest,
		PolicyVersion:  commit.PolicyVersion,
		MatchedRuleIDs: append([]string(nil), commit.MatchedRuleIDs...),
		EvaluatedAt:    commit.EvaluatedAt,
	}, nil
}

type recordingClock struct {
	events *[]string
	value  time.Time
	calls  int
}

func (clock *recordingClock) Now() time.Time {
	clock.calls++
	appendTestEvent(clock.events, "clock.now")
	return clock.value
}

type recordingIDGenerator struct {
	events *[]string
	values map[IDKind][]string
	err    error
	calls  int
}

func (generator *recordingIDGenerator) NewID(kind IDKind) (string, error) {
	generator.calls++
	appendTestEvent(generator.events, fmt.Sprintf("id.%s", kind))
	if generator.err != nil {
		return "", generator.err
	}
	values := generator.values[kind]
	if len(values) == 0 {
		return "", ErrIDGeneration
	}
	value := values[0]
	generator.values[kind] = values[1:]
	return value, nil
}

func appendTestEvent(events *[]string, value string) {
	if events != nil {
		*events = append(*events, value)
	}
}
