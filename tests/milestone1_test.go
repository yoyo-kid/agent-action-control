package tests_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/auth"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
	"github.com/yoyo-kid/agent-action-control/internal/policy/embedded"
	ospreypolicy "github.com/yoyo-kid/agent-action-control/internal/policy/osprey"
	"github.com/yoyo-kid/agent-action-control/internal/storage/sqlite"
	httptransport "github.com/yoyo-kid/agent-action-control/internal/transport/http"
)

const (
	runtimeOneToken = "runtime-one-token"
	runtimeOneID    = "runtime_456"
	runtimeTwoToken = "runtime-two-token"
	runtimeTwoID    = "runtime_789"
)

var acceptanceTime = time.Date(2026, time.August, 21, 12, 0, 0, 0, time.UTC)

func TestMilestone1DecisionOutcomes(t *testing.T) {
	safetyReview := newSafetyReviewEffect(t)
	tests := []struct {
		name                string
		evaluation          application.PolicyEvaluation
		wantDecision        httptransport.DecisionType
		wantReasons         []string
		wantRequiredActions int
		wantEffects         int
	}{
		{
			name:         "direct allow",
			evaluation:   policyEvaluation(nil, nil),
			wantDecision: httptransport.DecisionAllow,
		},
		{
			name: "terminal deny",
			evaluation: policyEvaluation(
				[]domain.ReasonCode{domain.ReasonActorNotAuthorized},
				nil,
			),
			wantDecision: httptransport.DecisionDeny,
			wantReasons:  []string{string(domain.ReasonActorNotAuthorized)},
		},
		{
			name: "delegator approval required",
			evaluation: policyEvaluation(
				[]domain.ReasonCode{domain.ReasonDelegatorApprovalRequired},
				nil,
			),
			wantDecision:        httptransport.DecisionDeny,
			wantReasons:         []string{string(domain.ReasonDelegatorApprovalRequired)},
			wantRequiredActions: 1,
		},
		{
			name:                "internal safety review only",
			evaluation:          policyEvaluation(nil, []domain.PolicyEffect{safetyReview}),
			wantDecision:        httptransport.DecisionAllow,
			wantRequiredActions: 0,
			wantEffects:         1,
		},
		{
			name: "approval and internal review",
			evaluation: policyEvaluation(
				[]domain.ReasonCode{domain.ReasonDelegatorApprovalRequired},
				[]domain.PolicyEffect{safetyReview},
			),
			wantDecision:        httptransport.DecisionDeny,
			wantReasons:         []string{string(domain.ReasonDelegatorApprovalRequired)},
			wantRequiredActions: 1,
			wantEffects:         1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newHarness(t, &staticEvaluator{evaluation: test.evaluation})
			response := harness.evaluate(t, runtimeOneToken, requestFixture(t, "evaluate_external_send_request.json"))

			if response.Decision != test.wantDecision {
				t.Fatalf("decision = %q, want %q", response.Decision, test.wantDecision)
			}
			if !slices.Equal(response.ReasonCodes, test.wantReasons) {
				t.Fatalf("reason codes = %v, want %v", response.ReasonCodes, test.wantReasons)
			}
			if len(response.RequiredActions) != test.wantRequiredActions {
				t.Fatalf("required actions = %v, want %d", response.RequiredActions, test.wantRequiredActions)
			}
			if test.wantRequiredActions == 1 && response.RequiredActions[0].Type != httptransport.RequiredActionRequireApproval {
				t.Fatalf("required action = %v", response.RequiredActions[0])
			}
			assertTableCount(t, harness.database, "policy_effects", test.wantEffects)
		})
	}
}

func TestMilestone1PublicActionShapes(t *testing.T) {
	harness := newHarness(t, &staticEvaluator{evaluation: policyEvaluation(nil, nil)})
	for _, fixture := range []string{
		"evaluate_external_send_request.json",
		"evaluate_update_resource_access_request.json",
		"evaluate_delete_request.json",
	} {
		t.Run(fixture, func(t *testing.T) {
			body := requestFixture(t, fixture)
			var envelope map[string]any
			mustUnmarshal(t, body, &envelope)
			action := envelope["proposedAction"].(map[string]any)
			if _, exists := action["id"]; exists {
				t.Fatal("proposedAction.id must not be required by the M1 contract")
			}
			response := harness.evaluate(t, runtimeOneToken, body)
			if response.Decision != httptransport.DecisionAllow {
				t.Fatalf("decision = %q", response.Decision)
			}
		})
	}
}

func TestMilestone1QuickstartRequest(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "examples", "external-send.json"))
	if err != nil {
		t.Fatalf("read quickstart request: %v", err)
	}
	harness := newHarness(t, embedded.Evaluator{})
	response := harness.evaluate(t, runtimeOneToken, body)
	if response.Decision != httptransport.DecisionAllow ||
		len(response.ReasonCodes) != 0 ||
		len(response.RequiredActions) != 0 {
		t.Fatalf("quickstart response = %#v", response)
	}
}

func TestMilestone1ActionDigestBoundary(t *testing.T) {
	baseBody := requestFixture(t, "evaluate_external_send_request.json")
	mutatedBody := mutateRequest(t, baseBody, func(request map[string]any) {
		request["requestId"] = "req_digest_mutation"
		action := request["proposedAction"].(map[string]any)
		payload := action["payload"].(map[string]any)
		payload["digest"] = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	})
	harness := newHarness(t, &staticEvaluator{evaluation: policyEvaluation(nil, nil)})
	base := harness.evaluate(t, runtimeOneToken, baseBody)
	mutated := harness.evaluate(t, runtimeOneToken, mutatedBody)
	if base.ActionDigest == mutated.ActionDigest {
		t.Fatalf("protected payload mutation did not change action digest %q", base.ActionDigest)
	}

	allowHarness := newHarness(t, &staticEvaluator{evaluation: policyEvaluation(nil, nil)})
	denyHarness := newHarness(t, &staticEvaluator{evaluation: policyEvaluation(
		[]domain.ReasonCode{domain.ReasonActorNotAuthorized}, nil,
	)})
	allow := allowHarness.evaluate(t, runtimeOneToken, baseBody)
	deny := denyHarness.evaluate(t, runtimeOneToken, baseBody)
	if allow.Decision == deny.Decision {
		t.Fatalf("test setup produced the same decision %q", allow.Decision)
	}
	if allow.ActionDigest != deny.ActionDigest {
		t.Fatalf("decision output changed action digest: allow=%q deny=%q", allow.ActionDigest, deny.ActionDigest)
	}
}

func TestMilestone1RuntimeScopedIdempotency(t *testing.T) {
	evaluator := &staticEvaluator{evaluation: policyEvaluation(nil, nil)}
	harness := newHarness(t, evaluator)
	body := requestFixture(t, "evaluate_external_send_request.json")

	first := harness.evaluate(t, runtimeOneToken, body)
	retry := harness.evaluate(t, runtimeOneToken, body)
	if first.DecisionID != retry.DecisionID || first.ActionDigest != retry.ActionDigest {
		t.Fatalf("exact retry was not stable: first=%#v retry=%#v", first, retry)
	}

	secondRuntimeBody := mutateRequest(t, body, func(request map[string]any) {
		action := request["proposedAction"].(map[string]any)
		actor := action["actor"].(map[string]any)
		actor["runtimeId"] = runtimeTwoID
		evidence := action["authorizationEvidence"].([]any)
		issuer := evidence[0].(map[string]any)["issuedBy"].(map[string]any)
		issuer["id"] = runtimeTwoID
	})
	secondRuntime := harness.evaluate(t, runtimeTwoToken, secondRuntimeBody)
	if secondRuntime.DecisionID == first.DecisionID {
		t.Fatalf("runtime-scoped request IDs shared decision %q", first.DecisionID)
	}

	conflictingBody := mutateRequest(t, body, func(request map[string]any) {
		action := request["proposedAction"].(map[string]any)
		target := action["target"].(map[string]any)
		target["resourceId"] = "draft_conflict"
	})
	recorder := harness.request(t, runtimeOneToken, conflictingBody)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("conflicting retry status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var errorResponse httptransport.ErrorResponse
	mustUnmarshal(t, recorder.Body.Bytes(), &errorResponse)
	if errorResponse.Error.Code != httptransport.ErrorRequestIDConflict {
		t.Fatalf("error code = %q", errorResponse.Error.Code)
	}
	if evaluator.callCount() != 2 {
		t.Fatalf("policy evaluations = %d, want 2; retries and conflicts must resolve from the ledger", evaluator.callCount())
	}
}

func TestMilestone1OspreyTimeoutFailsClosed(t *testing.T) {
	evaluator, err := ospreypolicy.NewEvaluator(ospreypolicy.Config{
		Coordinator:   timeoutCoordinator{},
		PolicyVersion: "osprey-acceptance-v1",
		Timeout:       time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new Osprey evaluator: %v", err)
	}
	harness := newHarness(t, evaluator)
	response := harness.evaluate(t, runtimeOneToken, requestFixture(t, "evaluate_external_send_request.json"))
	if response.Decision != httptransport.DecisionDeny ||
		!slices.Equal(response.ReasonCodes, []string{string(domain.ReasonPolicyUnavailable)}) ||
		len(response.RequiredActions) != 0 {
		t.Fatalf("timeout did not fail closed: %#v", response)
	}
}

func TestMilestone1SQLiteCommitFailureProducesNoDecisionOrEffect(t *testing.T) {
	harness := newHarness(t, &staticEvaluator{evaluation: policyEvaluation(
		nil,
		[]domain.PolicyEffect{newSafetyReviewEffect(t)},
	)})
	if _, err := harness.database.Exec(`
		CREATE TRIGGER fail_decision_insert
		BEFORE INSERT ON decisions
		BEGIN
			SELECT RAISE(ABORT, 'forced acceptance-test failure');
		END;
	`); err != nil {
		t.Fatalf("install failure trigger: %v", err)
	}

	recorder := harness.request(t, runtimeOneToken, requestFixture(t, "evaluate_external_send_request.json"))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("commit failure status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var errorResponse httptransport.ErrorResponse
	mustUnmarshal(t, recorder.Body.Bytes(), &errorResponse)
	if errorResponse.Error.Code != httptransport.ErrorInternal {
		t.Fatalf("error code = %q", errorResponse.Error.Code)
	}
	assertTableCount(t, harness.database, "action_requests", 0)
	assertTableCount(t, harness.database, "decisions", 0)
	assertTableCount(t, harness.database, "policy_effects", 0)
}

type acceptanceHarness struct {
	handler  http.Handler
	database *sql.DB
}

func newHarness(t *testing.T, evaluator application.PolicyEvaluator) acceptanceHarness {
	t.Helper()
	database, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "acceptance.db"))
	if err != nil {
		t.Fatalf("open SQLite: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ledger, err := sqlite.NewDecisionLedger(database)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	service, err := application.NewDecisionService(evaluator, ledger, fixedClock{}, &sequenceIDs{})
	if err != nil {
		t.Fatalf("new decision service: %v", err)
	}
	authenticator, err := auth.NewStaticRuntimeAuthenticator(map[string]string{
		runtimeOneToken: runtimeOneID,
		runtimeTwoToken: runtimeTwoID,
	})
	if err != nil {
		t.Fatalf("new runtime authenticator: %v", err)
	}
	handler, err := httptransport.NewHandler(httptransport.HandlerConfig{
		RuntimeAuthenticator: authenticator,
		DecisionEvaluator:    service,
		Logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new HTTP handler: %v", err)
	}
	return acceptanceHarness{handler: handler, database: database}
}

func (harness acceptanceHarness) evaluate(t *testing.T, token string, body []byte) httptransport.DecisionResponse {
	t.Helper()
	recorder := harness.request(t, token, body)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response httptransport.DecisionResponse
	mustUnmarshal(t, recorder.Body.Bytes(), &response)
	if err := response.Validate(); err != nil {
		t.Fatalf("invalid decision response: %v", err)
	}
	return response
}

func (harness acceptanceHarness) request(t *testing.T, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/action-decisions", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	harness.handler.ServeHTTP(recorder, request)
	return recorder
}

type staticEvaluator struct {
	mu         sync.Mutex
	evaluation application.PolicyEvaluation
	calls      int
}

func (evaluator *staticEvaluator) Evaluate(context.Context, domain.ProposedAction) (application.PolicyEvaluation, error) {
	evaluator.mu.Lock()
	defer evaluator.mu.Unlock()
	evaluator.calls++
	return evaluator.evaluation, nil
}

func (evaluator *staticEvaluator) callCount() int {
	evaluator.mu.Lock()
	defer evaluator.mu.Unlock()
	return evaluator.calls
}

type timeoutCoordinator struct{}

func (timeoutCoordinator) ProcessAction(ctx context.Context, _ ospreypolicy.CoordinatorRequest) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return acceptanceTime }

type sequenceIDs struct {
	mu   sync.Mutex
	next int
}

func (ids *sequenceIDs) NewID(kind application.IDKind) (string, error) {
	ids.mu.Lock()
	defer ids.mu.Unlock()
	ids.next++
	return fmt.Sprintf("%s-%d", kind, ids.next), nil
}

func policyEvaluation(reasons []domain.ReasonCode, effects []domain.PolicyEffect) application.PolicyEvaluation {
	return application.PolicyEvaluation{
		DenyReasonCodes: reasons,
		Effects:         effects,
		MatchedRuleIDs:  []string{"acceptance.rule"},
		PolicyVersion:   "acceptance-v1",
	}
}

func newSafetyReviewEffect(t *testing.T) domain.PolicyEffect {
	t.Helper()
	requirement, err := domain.NewSafetyReviewRequirement(domain.SafetyReviewHigh, []string{"evidence_123"})
	if err != nil {
		t.Fatalf("new safety review requirement: %v", err)
	}
	effect, err := domain.NewCreateSafetyReviewEffect(requirement)
	if err != nil {
		t.Fatalf("new safety review effect: %v", err)
	}
	return effect
}

func requestFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Join("..", "internal", "transport", "http", "testdata", name))
	if err != nil {
		t.Fatalf("read request fixture: %v", err)
	}
	return value
}

func mutateRequest(t *testing.T, body []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var request map[string]any
	mustUnmarshal(t, body, &request)
	mutate(request)
	mutated, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal mutated request: %v", err)
	}
	return mutated
}

func mustUnmarshal(t *testing.T, body []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
}

func assertTableCount(t *testing.T, database *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("%s rows = %d, want %d", table, got, want)
	}
}
