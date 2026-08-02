package domain

import (
	"errors"
	"testing"
	"time"
)

func TestParseTypesRejectUnknownValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		parse func() error
		want  error
	}{
		{name: "proposed action", parse: func() error { _, err := ParseActionType("TRANSFER_FUNDS"); return err }, want: ErrInvalidActionType},
		{name: "decision", parse: func() error { _, err := ParseDecisionType("REVIEW"); return err }, want: ErrInvalidDecisionType},
		{name: "policy action", parse: func() error { _, err := ParsePolicyActionType("WARN"); return err }, want: ErrInvalidPolicyActionType},
		{name: "policy effect", parse: func() error { _, err := ParsePolicyEffectType("NOTIFY"); return err }, want: ErrInvalidPolicyEffectType},
		{name: "reason code", parse: func() error { _, err := ParseReasonCode("UNKNOWN_REASON"); return err }, want: ErrInvalidReasonCode},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.parse(); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestAllowDecisionHasNoReasonsOrUpstreamActions(t *testing.T) {
	t.Parallel()

	decision := NewAllowDecision()
	if decision.Type() != DecisionAllow {
		t.Fatalf("decision type = %q, want %q", decision.Type(), DecisionAllow)
	}
	if got := decision.ReasonCodes(); len(got) != 0 {
		t.Fatalf("allow reasons = %v, want none", got)
	}
	if got := decision.Actions(); len(got) != 0 {
		t.Fatalf("allow actions = %v, want none", got)
	}
}

func TestDenyDecisionComposition(t *testing.T) {
	t.Parallel()

	approval := mustApprovalAction(t)
	tests := []struct {
		name    string
		actions []PolicyAction
	}{
		{name: "terminal deny"},
		{name: "deny requiring approval", actions: []PolicyAction{approval}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decision, err := NewDenyDecision([]ReasonCode{ReasonDelegatorApprovalRequired}, test.actions)
			if err != nil {
				t.Fatalf("new deny decision: %v", err)
			}
			if decision.Type() != DecisionDeny {
				t.Fatalf("decision type = %q, want %q", decision.Type(), DecisionDeny)
			}
		})
	}
}

func TestDenyDecisionRejectsInvalidMembers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		reasons []ReasonCode
		actions []PolicyAction
		wantErr error
	}{
		{name: "no reasons", wantErr: ErrInvalidArgument},
		{name: "unknown reason", reasons: []ReasonCode{"UNKNOWN"}, wantErr: ErrInvalidReasonCode},
		{name: "nil action", reasons: []ReasonCode{ReasonPolicyUnavailable}, actions: []PolicyAction{nil}, wantErr: ErrInvalidArgument},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewDenyDecision(test.reasons, test.actions)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestDenyDecisionNormalizesRepeatedInputs(t *testing.T) {
	t.Parallel()

	firstApproval := mustApprovalAction(t)
	secondApproval := mustApprovalActionWithID(t, "action_approval_456", "approval_456", "user_456")
	decision, err := NewDenyDecision(
		[]ReasonCode{
			ReasonDelegatorApprovalRequired,
			ReasonExternalDestination,
			ReasonDelegatorApprovalRequired,
		},
		[]PolicyAction{firstApproval, secondApproval},
	)
	if err != nil {
		t.Fatalf("new deny decision: %v", err)
	}
	if got := decision.ReasonCodes(); len(got) != 2 || got[0] != ReasonDelegatorApprovalRequired || got[1] != ReasonExternalDestination {
		t.Fatalf("normalized reasons = %v", got)
	}
	if got := decision.Actions(); len(got) != 2 {
		t.Fatalf("actions = %v, want both approval requirements preserved for composition", got)
	}
}

func TestDenyDecisionOwnsItsSlices(t *testing.T) {
	t.Parallel()

	reasons := []ReasonCode{ReasonDelegatorApprovalRequired}
	actions := []PolicyAction{mustApprovalAction(t)}
	decision, err := NewDenyDecision(reasons, actions)
	if err != nil {
		t.Fatalf("new decision: %v", err)
	}

	reasons[0] = ReasonPolicyUnavailable
	actions[0] = nil
	if got := decision.ReasonCodes()[0]; got != ReasonDelegatorApprovalRequired {
		t.Fatalf("stored reason = %q", got)
	}
	if got := decision.Actions()[0].Type(); got != PolicyActionRequireApproval {
		t.Fatalf("stored action type = %q", got)
	}

	returnedReasons := decision.ReasonCodes()
	returnedReasons[0] = ReasonPolicyUnavailable
	if got := decision.ReasonCodes()[0]; got != ReasonDelegatorApprovalRequired {
		t.Fatalf("reason mutated through getter: %q", got)
	}
}

func TestParseActionDigest(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "md5:abc", "sha256:", "sha256:not valid"} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseActionDigest(value); !errors.Is(err, ErrInvalidDigest) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidDigest)
			}
		})
	}
	if digest, err := ParseActionDigest("sha256:abc_123-Z"); err != nil || digest.String() != "sha256:abc_123-Z" {
		t.Fatalf("valid digest = %q, %v", digest, err)
	}
}

func mustApprovalAction(t *testing.T) RequireApprovalAction {
	t.Helper()
	return mustApprovalActionWithID(t, "action_approval_123", "approval_123", "user_123")
}

func mustApprovalActionWithID(t *testing.T, actionID, approvalID, principalID string) RequireApprovalAction {
	t.Helper()

	authority, err := NewDelegatorAuthority(principalID)
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	digest, err := ParseActionDigest("sha256:action123")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	requirement, err := NewApprovalRequirement(approvalID, authority, digest, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("new approval requirement: %v", err)
	}
	action, err := NewRequireApprovalAction(actionID, requirement)
	if err != nil {
		t.Fatalf("new approval action: %v", err)
	}
	return action
}
