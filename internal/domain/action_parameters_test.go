package domain

import (
	"errors"
	"reflect"
	"testing"
)

func TestExternalSendParametersNormalizeSetFacts(t *testing.T) {
	t.Parallel()

	parameters, err := NewExternalSendParameters(
		DestinationScope(" external "),
		[]string{" z@example.com ", "a@example.com", "a@example.com"},
	)
	if err != nil {
		t.Fatalf("new external send parameters: %v", err)
	}
	if parameters.DestinationScope() != DestinationExternal {
		t.Fatalf("destination scope = %q", parameters.DestinationScope())
	}
	want := []string{"a@example.com", "z@example.com"}
	if got := parameters.Recipients(); !reflect.DeepEqual(got, want) {
		t.Fatalf("recipients = %v, want %v", got, want)
	}

	returned := parameters.Recipients()
	returned[0] = "mutated@example.com"
	if got := parameters.Recipients()[0]; got != "a@example.com" {
		t.Fatalf("recipient mutated through getter: %q", got)
	}
}

func TestUpdateResourceAccessParametersNormalizePrincipals(t *testing.T) {
	t.Parallel()

	userB, _ := NewPrincipal(PrincipalUser, " user_b ")
	userA, _ := NewPrincipal(PrincipalUser, "user_a")
	parameters, err := NewUpdateResourceAccessParameters(
		AccessScope(" private "),
		AccessScope(" shared "),
		[]Principal{userB, userA, userA},
	)
	if err != nil {
		t.Fatalf("new update access parameters: %v", err)
	}
	if parameters.CurrentScope() != "PRIVATE" || parameters.RequestedScope() != "SHARED" {
		t.Fatalf("scopes = %q -> %q", parameters.CurrentScope(), parameters.RequestedScope())
	}
	principals := parameters.TargetPrincipals()
	if len(principals) != 2 || principals[0].ID() != "user_a" || principals[1].ID() != "user_b" {
		t.Fatalf("target principals = %#v", principals)
	}
}

func TestUpdateResourceAccessParametersRejectInvalidTransitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		current    AccessScope
		requested  AccessScope
		principals []Principal
	}{
		{name: "no change", current: "PRIVATE", requested: "private"},
		{name: "shared without principals", current: "PRIVATE", requested: "SHARED"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewUpdateResourceAccessParameters(test.current, test.requested, test.principals)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("error = %v, want %v", err, ErrInvalidArgument)
			}
		})
	}
}

func TestPayloadFactsAreNormalizedAndImmutable(t *testing.T) {
	t.Parallel()

	digest, _ := ParsePayloadDigest("sha256:payload123")
	size := int64(42)
	payload, err := NewPayloadFacts(digest, []string{" SECRET ", "CONFIDENTIAL", "SECRET"}, &size)
	if err != nil {
		t.Fatalf("new payload facts: %v", err)
	}
	wantLabels := []string{"CONFIDENTIAL", "SECRET"}
	if got := payload.Classification(); !reflect.DeepEqual(got, wantLabels) {
		t.Fatalf("classification = %v, want %v", got, wantLabels)
	}
	size = 99
	if got := *payload.SizeBytes(); got != 42 {
		t.Fatalf("size = %d, want 42", got)
	}
}

func TestNormalizeAuthorizationEvidenceRejectsConflictingReuse(t *testing.T) {
	t.Parallel()

	issuer, _ := NewPrincipal(PrincipalRuntime, "runtime_123")
	internalScope, _ := NewAuthorizationScope(ActionExternalSend, DestinationInternal, "", "")
	externalScope, _ := NewAuthorizationScope(ActionExternalSend, DestinationExternal, "", "")
	internalEvidence, _ := NewAuthorizationEvidence(EvidenceSystemAssertion, "evidence_123", issuer, internalScope)
	externalEvidence, _ := NewAuthorizationEvidence(EvidenceSystemAssertion, "evidence_123", issuer, externalScope)

	_, err := NormalizeAuthorizationEvidence([]AuthorizationEvidence{internalEvidence, externalEvidence})
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("error = %v, want %v", err, ErrInvalidArgument)
	}
}

func TestNormalizeAuthorizationEvidenceSortsAndDeduplicates(t *testing.T) {
	t.Parallel()

	issuer, _ := NewPrincipal(PrincipalRuntime, "runtime_123")
	scope, _ := NewAuthorizationScope(ActionExternalSend, DestinationExternal, "", "")
	evidenceB, _ := NewAuthorizationEvidence(EvidenceSystemAssertion, "evidence_b", issuer, scope)
	evidenceA, _ := NewAuthorizationEvidence(EvidenceSystemAssertion, "evidence_a", issuer, scope)

	got, err := NormalizeAuthorizationEvidence([]AuthorizationEvidence{evidenceB, evidenceA, evidenceA})
	if err != nil {
		t.Fatalf("normalize authorization evidence: %v", err)
	}
	if len(got) != 2 || got[0].ID() != "evidence_a" || got[1].ID() != "evidence_b" {
		t.Fatalf("authorization evidence = %#v", got)
	}
}
