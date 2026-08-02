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

func TestDecisionCompositionInvariants(t *testing.T) {
	t.Parallel()

	approval := mustApprovalAction(t)
	review := mustSafetyReviewAction(t)

	tests := []struct {
		name    string
		typ     DecisionType
		actions []PolicyAction
		wantErr error
	}{
		{name: "direct allow", typ: DecisionAllow},
		{name: "terminal deny", typ: DecisionDeny},
		{name: "deny requiring approval", typ: DecisionDeny, actions: []PolicyAction{approval}},
		{name: "allow creating safety review", typ: DecisionAllow, actions: []PolicyAction{review}},
		{name: "deny creating safety review", typ: DecisionDeny, actions: []PolicyAction{review}},
		{name: "deny with both actions", typ: DecisionDeny, actions: []PolicyAction{approval, review}},
		{name: "allow requiring approval", typ: DecisionAllow, actions: []PolicyAction{approval}, wantErr: ErrAllowCannotRequireApproval},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			decision, err := NewDecision(test.typ, []ReasonCode{ReasonExistingDelegationSufficient}, test.actions)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && decision.Type() != test.typ {
				t.Fatalf("decision type = %q, want %q", decision.Type(), test.typ)
			}
		})
	}
}

func TestDecisionRejectsInvalidAndDuplicateMembers(t *testing.T) {
	t.Parallel()

	approval := mustApprovalAction(t)
	tests := []struct {
		name    string
		typ     DecisionType
		reasons []ReasonCode
		actions []PolicyAction
		wantErr error
	}{
		{name: "unknown decision", typ: DecisionType("UNKNOWN"), reasons: []ReasonCode{ReasonPolicyUnavailable}, wantErr: ErrInvalidDecisionType},
		{name: "no reasons", typ: DecisionDeny, wantErr: ErrInvalidArgument},
		{name: "unknown reason", typ: DecisionDeny, reasons: []ReasonCode{"UNKNOWN"}, wantErr: ErrInvalidReasonCode},
		{name: "duplicate reasons", typ: DecisionDeny, reasons: []ReasonCode{ReasonPolicyUnavailable, ReasonPolicyUnavailable}, wantErr: ErrDuplicateReasonCode},
		{name: "duplicate actions", typ: DecisionDeny, reasons: []ReasonCode{ReasonDelegatorApprovalRequired}, actions: []PolicyAction{approval, approval}, wantErr: ErrDuplicatePolicyAction},
		{name: "nil action", typ: DecisionDeny, reasons: []ReasonCode{ReasonPolicyUnavailable}, actions: []PolicyAction{nil}, wantErr: ErrInvalidArgument},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewDecision(test.typ, test.reasons, test.actions)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestDecisionOwnsItsSlices(t *testing.T) {
	t.Parallel()

	reasons := []ReasonCode{ReasonExistingDelegationSufficient}
	actions := []PolicyAction{mustSafetyReviewAction(t)}
	decision, err := NewDecision(DecisionAllow, reasons, actions)
	if err != nil {
		t.Fatalf("new decision: %v", err)
	}

	reasons[0] = ReasonPolicyUnavailable
	actions[0] = nil
	if got := decision.ReasonCodes()[0]; got != ReasonExistingDelegationSufficient {
		t.Fatalf("stored reason = %q", got)
	}
	if got := decision.Actions()[0].Type(); got != PolicyActionCreateSafetyReview {
		t.Fatalf("stored action type = %q", got)
	}

	returnedReasons := decision.ReasonCodes()
	returnedReasons[0] = ReasonPolicyUnavailable
	if got := decision.ReasonCodes()[0]; got != ReasonExistingDelegationSufficient {
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

	authority, err := NewDelegatorAuthority("user_123")
	if err != nil {
		t.Fatalf("new authority: %v", err)
	}
	digest, err := ParseActionDigest("sha256:action123")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	requirement, err := NewApprovalRequirement("approval_123", authority, digest, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("new approval requirement: %v", err)
	}
	action, err := NewRequireApprovalAction("action_approval_123", requirement)
	if err != nil {
		t.Fatalf("new approval action: %v", err)
	}
	return action
}

func mustSafetyReviewAction(t *testing.T) CreateSafetyReviewAction {
	t.Helper()

	requirement, err := NewSafetyReviewRequirement("review_123", SafetyReviewHigh, []string{"evidence_123"})
	if err != nil {
		t.Fatalf("new safety review requirement: %v", err)
	}
	action, err := NewCreateSafetyReviewAction("action_review_123", requirement)
	if err != nil {
		t.Fatalf("new safety review action: %v", err)
	}
	return action
}
