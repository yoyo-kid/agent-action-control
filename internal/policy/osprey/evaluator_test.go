package osprey

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

const testPolicyVersion = "osprey-bundle-2026-08-12"

func TestNewEvaluatorValidatesConfiguration(t *testing.T) {
	valid := Config{Coordinator: &fakeCoordinator{}, PolicyVersion: testPolicyVersion, Timeout: time.Second}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "missing coordinator", mutate: func(config *Config) { config.Coordinator = nil }},
		{name: "missing policy version", mutate: func(config *Config) { config.PolicyVersion = " " }},
		{name: "missing timeout", mutate: func(config *Config) { config.Timeout = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewEvaluator(config); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}

func TestEvaluatorMapsSupportedVerdictFamilies(t *testing.T) {
	tests := []struct {
		name        string
		verdicts    []string
		wantReasons []domain.ReasonCode
		wantEffects int
	}{
		{name: "allow", verdicts: []string{}},
		{
			name:        "terminal deny",
			verdicts:    []string{"deny.actor_not_authorized"},
			wantReasons: []domain.ReasonCode{domain.ReasonActorNotAuthorized},
		},
		{
			name:        "delegator approval",
			verdicts:    []string{"require_delegator_approval.external_send"},
			wantReasons: []domain.ReasonCode{domain.ReasonDelegatorApprovalRequired},
		},
		{
			name:        "internal safety review",
			verdicts:    []string{"create_safety_review.secret_payload"},
			wantEffects: 1,
		},
		{
			name: "combined and deduplicated",
			verdicts: []string{
				"require_delegator_approval.external_send",
				"create_safety_review.secret_payload",
				"create_safety_review.secret_payload",
			},
			wantReasons: []domain.ReasonCode{domain.ReasonDelegatorApprovalRequired},
			wantEffects: 1,
		},
		{
			name: "distinct safety review signals share one effect",
			verdicts: []string{
				"create_safety_review.secret_payload",
				"create_safety_review.suspicious_destination",
			},
			wantEffects: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			coordinator := &fakeCoordinator{verdicts: test.verdicts}
			evaluator := newTestEvaluator(t, coordinator, time.Second)
			evaluation, err := evaluator.Evaluate(context.Background(), testAction(t))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if evaluation.PolicyVersion != testPolicyVersion {
				t.Fatalf("policy version = %q", evaluation.PolicyVersion)
			}
			assertReasons(t, evaluation.DenyReasonCodes, test.wantReasons)
			if len(evaluation.Effects) != test.wantEffects {
				t.Fatalf("effects = %#v", evaluation.Effects)
			}
			if len(evaluation.MatchedRuleIDs) != len(test.verdicts)-duplicateCount(test.verdicts) {
				t.Fatalf("matched rules = %v", evaluation.MatchedRuleIDs)
			}
			for _, effect := range evaluation.Effects {
				review, ok := effect.(domain.CreateSafetyReviewEffect)
				if !ok || review.Requirement().Priority() != domain.SafetyReviewHigh {
					t.Fatalf("effect = %#v", effect)
				}
			}
		})
	}
}

func TestEvaluatorFailsClosedForUncertainPolicyResults(t *testing.T) {
	coordinatorFailure := errors.New("coordinator unavailable")
	tests := []struct {
		name     string
		verdicts []string
		err      error
	}{
		{name: "coordinator unavailable", err: coordinatorFailure},
		{name: "unknown verdict", verdicts: []string{"block.everything"}},
		{name: "unknown deny reason", verdicts: []string{"deny.not_registered"}},
		{name: "empty approval key", verdicts: []string{"require_delegator_approval."}},
		{name: "noncanonical policy key", verdicts: []string{"create_safety_review.Secret"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := newTestEvaluator(t, &fakeCoordinator{verdicts: test.verdicts, err: test.err}, time.Second)
			evaluation, err := evaluator.Evaluate(context.Background(), testAction(t))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			assertReasons(t, evaluation.DenyReasonCodes, []domain.ReasonCode{domain.ReasonPolicyUnavailable})
			if evaluation.PolicyVersion != testPolicyVersion || len(evaluation.MatchedRuleIDs) != 0 || len(evaluation.Effects) != 0 {
				t.Fatalf("fail-closed evaluation = %#v", evaluation)
			}
		})
	}
}

func TestEvaluatorAppliesCoordinatorTimeout(t *testing.T) {
	coordinator := &fakeCoordinator{process: func(ctx context.Context, _ CoordinatorRequest) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	evaluator := newTestEvaluator(t, coordinator, time.Millisecond)
	evaluation, err := evaluator.Evaluate(context.Background(), testAction(t))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	assertReasons(t, evaluation.DenyReasonCodes, []domain.ReasonCode{domain.ReasonPolicyUnavailable})
}

func TestEvaluatorSendsNormalizedActionFacts(t *testing.T) {
	coordinator := &fakeCoordinator{}
	evaluator := newTestEvaluator(t, coordinator, time.Second)
	action := testAction(t)
	if _, err := evaluator.Evaluate(context.Background(), action); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(coordinator.requests) != 1 {
		t.Fatalf("requests = %d", len(coordinator.requests))
	}
	request := coordinator.requests[0]
	if !request.Timestamp.Equal(action.RequestedAt()) {
		t.Fatalf("request = %#v", request)
	}
	var facts map[string]any
	if err := json.Unmarshal([]byte(request.ActionDataJSON), &facts); err != nil {
		t.Fatalf("decode action data: %v", err)
	}
	if facts["apiVersion"] != actionFactsVersion || facts["type"] != string(domain.ActionExternalSend) {
		t.Fatalf("action facts = %#v", facts)
	}
	payload := facts["payload"].(map[string]any)
	if payload["digest"] != action.PayloadDigest().String() {
		t.Fatalf("payload = %#v", payload)
	}
}

type fakeCoordinator struct {
	verdicts []string
	err      error
	requests []CoordinatorRequest
	process  func(context.Context, CoordinatorRequest) ([]string, error)
}

func (coordinator *fakeCoordinator) ProcessAction(
	ctx context.Context,
	request CoordinatorRequest,
) ([]string, error) {
	coordinator.requests = append(coordinator.requests, request)
	if coordinator.process != nil {
		return coordinator.process(ctx, request)
	}
	return coordinator.verdicts, coordinator.err
}

func newTestEvaluator(t *testing.T, coordinator Coordinator, timeout time.Duration) *Evaluator {
	t.Helper()
	evaluator, err := NewEvaluator(Config{
		Coordinator:   coordinator,
		PolicyVersion: testPolicyVersion,
		Timeout:       timeout,
	})
	if err != nil {
		t.Fatalf("new evaluator: %v", err)
	}
	return evaluator
}

func testAction(t *testing.T) domain.ProposedAction {
	t.Helper()
	actor, err := domain.NewActor("agent-1", "runtime-1", "session-1")
	if err != nil {
		t.Fatal(err)
	}
	delegator, err := domain.NewPrincipal(domain.PrincipalUser, "user-1")
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := domain.NewDelegation("delegation-1", delegator)
	if err != nil {
		t.Fatal(err)
	}
	target, err := domain.NewTarget("EMAIL_DRAFT", "draft-1")
	if err != nil {
		t.Fatal(err)
	}
	parameters, err := domain.NewExternalSendParameters(domain.DestinationExternal, []string{"customer@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := domain.ParsePayloadDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	size := int64(42)
	payload, err := domain.NewPayloadFacts(digest, []string{"CONFIDENTIAL"}, &size)
	if err != nil {
		t.Fatal(err)
	}
	action, err := domain.NewProposedAction(
		domain.ActionExternalSend,
		time.Date(2026, time.August, 12, 12, 0, 0, 0, time.UTC),
		actor,
		delegation,
		target,
		parameters,
		payload,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return action
}

func assertReasons(t *testing.T, got, want []domain.ReasonCode) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("reasons = %v, want %v", got, want)
		}
	}
}

func duplicateCount(values []string) int {
	seen := make(map[string]struct{}, len(values))
	duplicates := 0
	for _, value := range values {
		if _, exists := seen[value]; exists {
			duplicates++
		}
		seen[value] = struct{}{}
	}
	return duplicates
}
