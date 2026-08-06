package domain

import (
	"errors"
	"testing"
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
		{name: "required action", parse: func() error { _, err := ParseRequiredActionType("WARN"); return err }, want: ErrInvalidRequiredActionType},
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

func TestAllowDecisionHasNoReasonsOrRequiredActions(t *testing.T) {
	t.Parallel()

	decision := NewAllowDecision()
	if decision.Type() != DecisionAllow {
		t.Fatalf("decision type = %q, want %q", decision.Type(), DecisionAllow)
	}
	if got := decision.ReasonCodes(); len(got) != 0 {
		t.Fatalf("allow reasons = %v, want none", got)
	}
	if got := decision.RequiredActions(); len(got) != 0 {
		t.Fatalf("allow required actions = %v, want none", got)
	}
}

func TestDenyDecisionComposition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		actions []RequiredAction
	}{
		{name: "terminal deny", actions: nil},
		{name: "deny requiring approval", actions: []RequiredAction{NewRequireApprovalAction()}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reasons := []ReasonCode{ReasonPolicyUnavailable}
			if len(test.actions) > 0 {
				reasons = []ReasonCode{ReasonDelegatorApprovalRequired}
			}
			decision, err := NewDenyDecision(reasons, test.actions)
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
		actions []RequiredAction
		wantErr error
	}{
		{name: "no reasons", wantErr: ErrInvalidArgument},
		{name: "unknown reason", reasons: []ReasonCode{"UNKNOWN"}, wantErr: ErrInvalidReasonCode},
		{name: "unknown action", reasons: []ReasonCode{ReasonDelegatorApprovalRequired}, actions: []RequiredAction{{typ: "WARN"}}, wantErr: ErrInvalidRequiredActionType},
		{name: "approval action without approval reason", reasons: []ReasonCode{ReasonPolicyUnavailable}, actions: []RequiredAction{NewRequireApprovalAction()}, wantErr: ErrInvariantViolation},
		{name: "approval reason without approval action", reasons: []ReasonCode{ReasonDelegatorApprovalRequired}, wantErr: ErrInvariantViolation},
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

	decision, err := NewDenyDecision(
		[]ReasonCode{
			ReasonDelegatorApprovalRequired,
			ReasonExternalDestination,
			ReasonDelegatorApprovalRequired,
		},
		[]RequiredAction{NewRequireApprovalAction(), NewRequireApprovalAction()},
	)
	if err != nil {
		t.Fatalf("new deny decision: %v", err)
	}
	if got := decision.ReasonCodes(); len(got) != 2 || got[0] != ReasonDelegatorApprovalRequired || got[1] != ReasonExternalDestination {
		t.Fatalf("normalized reasons = %v", got)
	}
	if got := decision.RequiredActions(); len(got) != 1 || got[0].Type() != RequiredActionRequireApproval {
		t.Fatalf("normalized required actions = %v", got)
	}
}

func TestDenyDecisionOwnsItsSlices(t *testing.T) {
	t.Parallel()

	reasons := []ReasonCode{ReasonDelegatorApprovalRequired}
	actions := []RequiredAction{NewRequireApprovalAction()}
	decision, err := NewDenyDecision(reasons, actions)
	if err != nil {
		t.Fatalf("new decision: %v", err)
	}

	reasons[0] = ReasonPolicyUnavailable
	actions[0] = RequiredAction{}
	if got := decision.ReasonCodes()[0]; got != ReasonDelegatorApprovalRequired {
		t.Fatalf("stored reason = %q", got)
	}
	if got := decision.RequiredActions()[0].Type(); got != RequiredActionRequireApproval {
		t.Fatalf("stored required action type = %q", got)
	}

	returnedReasons := decision.ReasonCodes()
	returnedReasons[0] = ReasonPolicyUnavailable
	if got := decision.ReasonCodes()[0]; got != ReasonDelegatorApprovalRequired {
		t.Fatalf("reason mutated through getter: %q", got)
	}
}

func TestParseActionDigest(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"",
		"md5:abc",
		"sha256:",
		"sha256:not valid",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseActionDigest(value); !errors.Is(err, ErrInvalidDigest) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidDigest)
			}
		})
	}
	if digest, err := ParseActionDigest("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"); err != nil || digest.String() != "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		t.Fatalf("valid digest = %q, %v", digest, err)
	}
}
