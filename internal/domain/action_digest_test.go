package domain

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalActionGoldenVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		stem   string
		action ProposedAction
	}{
		{name: "external send", stem: "external_send_v1", action: externalActionFixture(t, nil)},
		{name: "update resource access", stem: "update_resource_access_v1", action: accessActionFixture(t, "PUBLIC", nil)},
		{name: "delete", stem: "delete_v1", action: deleteActionFixture(t, DeleteHard, false)},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			canonical, err := CanonicalActionBytes(test.action)
			if err != nil {
				t.Fatalf("canonical action bytes: %v", err)
			}
			wantCanonical := bytes.TrimSpace(readDigestGolden(t, test.stem+".json"))
			if !bytes.Equal(canonical, wantCanonical) {
				t.Fatalf("canonical bytes mismatch\n got: %s\nwant: %s", canonical, wantCanonical)
			}

			digest, err := ComputeActionDigest(test.action)
			if err != nil {
				t.Fatalf("compute action digest: %v", err)
			}
			wantDigest := strings.TrimSpace(string(readDigestGolden(t, test.stem+".sha256")))
			if digest.String() != wantDigest {
				t.Fatalf("digest = %q, want %q", digest, wantDigest)
			}
		})
	}
}

func TestActionDigestChangesWithExternalSendSecurityFacts(t *testing.T) {
	t.Parallel()

	base := mustComputeActionDigest(t, externalActionFixture(t, nil))
	tests := []struct {
		name   string
		mutate func(*externalDigestFixture)
	}{
		{name: "payload", mutate: func(value *externalDigestFixture) { value.payloadDigest = strings.Repeat("2", 64) }},
		{name: "recipient", mutate: func(value *externalDigestFixture) { value.recipients = []string{"other@example.com"} }},
		{name: "destination", mutate: func(value *externalDigestFixture) { value.destinationScope = DestinationInternal }},
		{name: "target", mutate: func(value *externalDigestFixture) { value.targetID = "draft_456" }},
		{name: "actor", mutate: func(value *externalDigestFixture) { value.agentID = "agent_456" }},
		{name: "runtime", mutate: func(value *externalDigestFixture) { value.runtimeID = "runtime_456" }},
		{name: "session", mutate: func(value *externalDigestFixture) { value.sessionID = "session_456" }},
		{name: "delegation", mutate: func(value *externalDigestFixture) { value.delegationID = "delegation_456" }},
		{name: "delegator", mutate: func(value *externalDigestFixture) { value.delegatorID = "user_456" }},
		{name: "requested time", mutate: func(value *externalDigestFixture) { value.requestedAt = value.requestedAt.Add(time.Second) }},
		{name: "classification", mutate: func(value *externalDigestFixture) { value.classification = []string{"PUBLIC"} }},
		{name: "evidence", mutate: func(value *externalDigestFixture) { value.evidenceID = "message_456" }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := mustComputeActionDigest(t, externalActionFixture(t, test.mutate))
			if got == base {
				t.Fatalf("digest did not change: %q", got)
			}
		})
	}
}

func TestActionDigestChangesWithAccessAndDeleteParameters(t *testing.T) {
	t.Parallel()

	publicAccess := accessActionFixture(t, "PUBLIC", nil)
	internalAccess := accessActionFixture(t, "INTERNAL", nil)
	if mustComputeActionDigest(t, publicAccess) == mustComputeActionDigest(t, internalAccess) {
		t.Fatal("permission scope did not change digest")
	}

	userOne, _ := NewPrincipal(PrincipalUser, "user_1")
	userTwo, _ := NewPrincipal(PrincipalUser, "user_2")
	sharedOne := accessActionFixture(t, "SHARED", []Principal{userOne})
	sharedTwo := accessActionFixture(t, "SHARED", []Principal{userTwo})
	if mustComputeActionDigest(t, sharedOne) == mustComputeActionDigest(t, sharedTwo) {
		t.Fatal("permission target did not change digest")
	}

	hardDelete := deleteActionFixture(t, DeleteHard, false)
	softDelete := deleteActionFixture(t, DeleteSoft, false)
	if mustComputeActionDigest(t, hardDelete) == mustComputeActionDigest(t, softDelete) {
		t.Fatal("delete mode did not change digest")
	}
	recoverableDelete := deleteActionFixture(t, DeleteHard, true)
	if mustComputeActionDigest(t, hardDelete) == mustComputeActionDigest(t, recoverableDelete) {
		t.Fatal("recoverability did not change digest")
	}
}

func TestActionDigestIgnoresSetOrderingAndDuplicates(t *testing.T) {
	t.Parallel()

	base := mustComputeActionDigest(t, externalActionFixture(t, nil))
	reordered := externalActionFixture(t, func(value *externalDigestFixture) {
		value.recipients = []string{"z@example.com", "customer@example.com", "z@example.com"}
		value.classification = []string{"SECRET", "CONFIDENTIAL", "SECRET"}
		value.reverseEvidence = true
	})
	if got := mustComputeActionDigest(t, reordered); got != base {
		t.Fatalf("digest = %q, want %q", got, base)
	}
}

func TestActionDigestExcludesProposedActionID(t *testing.T) {
	t.Parallel()

	base := mustComputeActionDigest(t, externalActionFixture(t, nil))
	changedID := externalActionFixture(t, func(value *externalDigestFixture) {
		value.actionID = "proposed_456"
	})
	if got := mustComputeActionDigest(t, changedID); got != base {
		t.Fatalf("digest = %q, want %q", got, base)
	}
}

type externalDigestFixture struct {
	actionID         string
	requestedAt      time.Time
	agentID          string
	runtimeID        string
	sessionID        string
	delegationID     string
	delegatorID      string
	targetID         string
	destinationScope DestinationScope
	recipients       []string
	payloadDigest    string
	classification   []string
	evidenceID       string
	reverseEvidence  bool
}

func externalActionFixture(t *testing.T, mutate func(*externalDigestFixture)) ProposedAction {
	t.Helper()
	fixture := externalDigestFixture{
		actionID:         "proposed_123",
		requestedAt:      time.Date(2026, time.August, 3, 12, 34, 56, 123456789, time.UTC),
		agentID:          "agent_123",
		runtimeID:        "runtime_123",
		sessionID:        "session_123",
		delegationID:     "delegation_123",
		delegatorID:      "user_123",
		targetID:         "draft_123",
		destinationScope: DestinationExternal,
		recipients:       []string{"customer@example.com", "z@example.com"},
		payloadDigest:    "1111111111111111111111111111111111111111111111111111111111111111",
		classification:   []string{"CONFIDENTIAL", "SECRET"},
		evidenceID:       "message_123",
	}
	if mutate != nil {
		mutate(&fixture)
	}
	actor, _ := NewActor(fixture.agentID, fixture.runtimeID, fixture.sessionID)
	delegator, _ := NewPrincipal(PrincipalUser, fixture.delegatorID)
	delegation, _ := NewDelegation(fixture.delegationID, delegator)
	target, _ := NewTarget("EMAIL_DRAFT", fixture.targetID)
	parameters, err := NewExternalSendParameters(fixture.destinationScope, fixture.recipients)
	if err != nil {
		t.Fatalf("new external send parameters: %v", err)
	}
	payloadDigest, err := ParsePayloadDigest("sha256:" + fixture.payloadDigest)
	if err != nil {
		t.Fatalf("parse payload digest: %v", err)
	}
	size := int64(4280)
	payload, _ := NewPayloadFacts(payloadDigest, fixture.classification, &size)
	runtimeIssuer, _ := NewPrincipal(PrincipalRuntime, fixture.runtimeID)
	userIssuer, _ := NewPrincipal(PrincipalUser, fixture.delegatorID)
	scope, _ := NewAuthorizationScope(ActionExternalSend, fixture.destinationScope, "", "")
	messageEvidence, _ := NewAuthorizationEvidence(EvidenceUserInstruction, fixture.evidenceID, runtimeIssuer, scope)
	grantEvidence, _ := NewAuthorizationEvidence(EvidenceDelegationGrant, "grant_123", userIssuer, scope)
	evidence := []AuthorizationEvidence{messageEvidence, grantEvidence}
	if fixture.reverseEvidence {
		evidence = []AuthorizationEvidence{grantEvidence, messageEvidence, grantEvidence}
	}
	action, err := NewProposedAction(
		fixture.actionID,
		ActionExternalSend,
		fixture.requestedAt,
		actor,
		delegation,
		target,
		parameters,
		payload,
		evidence,
	)
	if err != nil {
		t.Fatalf("new external send action: %v", err)
	}
	return action
}

func accessActionFixture(t *testing.T, requestedScope AccessScope, principals []Principal) ProposedAction {
	t.Helper()
	parameters, err := NewUpdateResourceAccessParameters("PRIVATE", requestedScope, principals)
	if err != nil {
		t.Fatalf("new access parameters: %v", err)
	}
	return actionWithParameters(t, ActionUpdateResourceAccess, parameters)
}

func deleteActionFixture(t *testing.T, mode DeleteMode, recoverable bool) ProposedAction {
	t.Helper()
	parameters, err := NewDeleteParameters(mode, recoverable)
	if err != nil {
		t.Fatalf("new delete parameters: %v", err)
	}
	return actionWithParameters(t, ActionDelete, parameters)
}

func actionWithParameters(t *testing.T, actionType ActionType, parameters ActionParameters) ProposedAction {
	t.Helper()
	actor, _ := NewActor("agent_123", "runtime_123", "")
	delegator, _ := NewPrincipal(PrincipalUser, "user_123")
	delegation, _ := NewDelegation("delegation_123", delegator)
	target, _ := NewTarget("DOCUMENT", "document_123")
	payloadDigest, _ := ParsePayloadDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111")
	payload, _ := NewPayloadFacts(payloadDigest, nil, nil)
	action, err := NewProposedAction(
		"proposed_123",
		actionType,
		time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC),
		actor,
		delegation,
		target,
		parameters,
		payload,
		nil,
	)
	if err != nil {
		t.Fatalf("new proposed action: %v", err)
	}
	return action
}

func mustComputeActionDigest(t *testing.T, action ProposedAction) ActionDigest {
	t.Helper()
	digest, err := ComputeActionDigest(action)
	if err != nil {
		t.Fatalf("compute action digest: %v", err)
	}
	return digest
}

func readDigestGolden(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	return value
}
