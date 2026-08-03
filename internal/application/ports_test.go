package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

var (
	_ Clock           = fixedClock{}
	_ IDGenerator     = sequenceIDGenerator{}
	_ PolicyEvaluator = fakePolicyEvaluator{}
	_ DecisionLedger  = fakeDecisionLedger{}
)

func TestAuthenticatedRuntimeIsNormalizedTrustedContext(t *testing.T) {
	t.Parallel()

	runtime, err := NewAuthenticatedRuntime(" runtime_123 ")
	if err != nil {
		t.Fatalf("new authenticated runtime: %v", err)
	}
	if got := runtime.RuntimeID(); got != "runtime_123" {
		t.Fatalf("runtime id = %q", got)
	}

	for _, value := range []string{"", "   ", strings.Repeat("x", 257)} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			_, err := NewAuthenticatedRuntime(value)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidInput)
			}
		})
	}
}

func TestClockAndIDGeneratorAreDeterministicSeams(t *testing.T) {
	t.Parallel()

	wantTime := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	clock := fixedClock{value: wantTime}
	if got := clock.Now(); !got.Equal(wantTime) {
		t.Fatalf("clock = %v, want %v", got, wantTime)
	}

	ids := sequenceIDGenerator{values: map[IDKind]string{
		IDDecision:        "dec_123",
		IDPolicyAction:    "act_123",
		IDApprovalRequest: "apr_123",
		IDPolicyEffect:    "effect_123",
	}}
	for kind, want := range ids.values {
		got, err := ids.NewID(kind)
		if err != nil {
			t.Fatalf("new %s id: %v", kind, err)
		}
		if got != want {
			t.Fatalf("%s id = %q, want %q", kind, got, want)
		}
	}
}

func TestIDKindIsClosed(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		string(IDDecision),
		string(IDPolicyAction),
		string(IDApprovalRequest),
		string(IDPolicyEffect),
	} {
		if _, err := ParseIDKind(value); err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
	}
	if _, err := ParseIDKind("EXECUTION"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidInput)
	}
}

func TestApplicationErrorTaxonomyIsDistinct(t *testing.T) {
	t.Parallel()

	errorsToCheck := []error{
		ErrInvalidInput,
		ErrActionIDConflict,
		ErrPolicyUnavailable,
		ErrLedgerFailure,
		ErrActionNotFound,
		ErrIDGeneration,
		domain.ErrInvariantViolation,
	}
	for index, target := range errorsToCheck {
		wrapped := fmt.Errorf("operation failed: %w", target)
		if !errors.Is(wrapped, target) {
			t.Fatalf("wrapped error does not match %v", target)
		}
		for otherIndex, other := range errorsToCheck {
			if index != otherIndex && errors.Is(wrapped, other) {
				t.Fatalf("%v unexpectedly matches %v", target, other)
			}
		}
	}
}

type fixedClock struct {
	value time.Time
}

func (clock fixedClock) Now() time.Time { return clock.value }

type sequenceIDGenerator struct {
	values map[IDKind]string
}

func (generator sequenceIDGenerator) NewID(kind IDKind) (string, error) {
	value, ok := generator.values[kind]
	if !ok {
		return "", ErrIDGeneration
	}
	return value, nil
}

type fakePolicyEvaluator struct{}

func (fakePolicyEvaluator) Evaluate(context.Context, domain.ProposedAction) (PolicyEvaluation, error) {
	return PolicyEvaluation{PolicyVersion: "policy-test"}, nil
}

type fakeDecisionLedger struct{}

func (fakeDecisionLedger) FindAction(context.Context, string) (*StoredEvaluation, error) {
	return nil, ErrActionNotFound
}

func (fakeDecisionLedger) CommitEvaluation(
	_ context.Context,
	commit EvaluationCommit,
) (DecisionRecord, error) {
	return DecisionRecord{
		DecisionID:    commit.DecisionID,
		Decision:      commit.Decision,
		ActionDigest:  commit.ActionDigest,
		PolicyVersion: commit.PolicyVersion,
		EvaluatedAt:   commit.EvaluatedAt,
	}, nil
}
