package httptransport_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	httptransport "github.com/yoyo-kid/agent-action-control/internal/transport/http"
)

func TestEvaluateActionRequestGoldenRoundTrip(t *testing.T) {
	t.Parallel()

	fixtures := []string{
		"evaluate_external_send_request.json",
		"evaluate_update_resource_access_request.json",
		"evaluate_delete_request.json",
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			want := readGolden(t, fixture)
			request, err := httptransport.DecodeEvaluateActionRequest(bytes.NewReader(want))
			if err != nil {
				t.Fatalf("decode request: %v", err)
			}
			got, err := json.Marshal(request)
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			assertJSONEqual(t, got, want)
		})
	}
}

func TestDecisionResponseGoldenRoundTrip(t *testing.T) {
	t.Parallel()

	fixtures := []string{
		"decision_allow.json",
		"decision_deny.json",
		"decision_approval_required.json",
		"decision_safety_review.json",
		"decision_fail_closed.json",
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			want := readGolden(t, fixture)
			var response httptransport.DecisionResponse
			if err := json.Unmarshal(want, &response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if err := response.Validate(); err != nil {
				t.Fatalf("validate response: %v", err)
			}
			got, err := json.Marshal(response)
			if err != nil {
				t.Fatalf("marshal response: %v", err)
			}
			assertJSONEqual(t, got, want)
		})
	}
}

func TestErrorResponseGoldenRoundTrip(t *testing.T) {
	t.Parallel()

	want := readGolden(t, "error_action_id_conflict.json")
	var response httptransport.ErrorResponse
	if err := json.Unmarshal(want, &response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	got, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal error response: %v", err)
	}
	assertJSONEqual(t, got, want)
}

func TestDecodeEvaluateActionRequestRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	input := strings.Replace(
		string(readGolden(t, "evaluate_external_send_request.json")),
		`"runtimeId": "runtime_456"`,
		`"runtimeId": "runtime_456", "riskLevel": "LOW"`,
		1,
	)
	if _, err := httptransport.DecodeEvaluateActionRequest(strings.NewReader(input)); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
}

func TestDecodeEvaluateActionRequestRejectsUnknownParameterFields(t *testing.T) {
	t.Parallel()

	input := strings.Replace(
		string(readGolden(t, "evaluate_external_send_request.json")),
		`"recipients": ["customer@example.com"]`,
		`"recipients": ["customer@example.com"], "shouldApprove": true`,
		1,
	)
	if _, err := httptransport.DecodeEvaluateActionRequest(strings.NewReader(input)); err == nil {
		t.Fatal("expected unknown parameter field to be rejected")
	}
}

func TestDecisionResponseRejectsUnknownValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		decision httptransport.DecisionType
		actions  []httptransport.DecisionAction
	}{
		{name: "decision", decision: "REVIEW"},
		{
			name:     "action",
			decision: httptransport.DecisionDeny,
			actions: []httptransport.DecisionAction{{
				Type:    "WARN",
				Context: json.RawMessage(`{}`),
			}},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := httptransport.DecisionResponse{
				APIVersion: httptransport.APIVersionV1,
				Decision:   test.decision,
				Actions:    test.actions,
			}
			if err := response.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDecisionResponseRejectsAllowWithApproval(t *testing.T) {
	t.Parallel()

	response := httptransport.DecisionResponse{
		APIVersion: httptransport.APIVersionV1,
		Decision:   httptransport.DecisionAllow,
		Actions: []httptransport.DecisionAction{{
			Type: httptransport.ActionRequireApproval,
			Context: json.RawMessage(`{
				"approvalRequestId":"apr_123",
				"requiredAuthority":{"type":"DELEGATOR","principalId":"user_456"},
				"actionDigest":"sha256:def456",
				"expiresAt":"2026-08-01T20:00:00Z"
			}`),
		}},
	}
	if err := response.Validate(); err == nil {
		t.Fatal("expected ALLOW + REQUIRE_APPROVAL to be rejected")
	}
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden fixture: %v", err)
	}
	return data
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()
	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode actual JSON: %v", err)
	}
	var wantValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("decode expected JSON: %v", err)
	}
	gotJSON, _ := json.Marshal(gotValue)
	wantJSON, _ := json.Marshal(wantValue)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("JSON mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}
