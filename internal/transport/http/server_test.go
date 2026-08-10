package httptransport_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/auth"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
	httptransport "github.com/yoyo-kid/agent-action-control/internal/transport/http"
)

func TestHealth(t *testing.T) {
	handler := newTestHTTPHandler(t, &fakeDecisionEvaluator{}, nil)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d content-type=%q", recorder.Code, recorder.Header().Get("Content-Type"))
	}
}

func TestHealthRejectsOtherMethods(t *testing.T) {
	handler := newTestHTTPHandler(t, &fakeDecisionEvaluator{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
}

func TestDecisionHandlerRequiresValidRuntimeAuthentication(t *testing.T) {
	handler := newTestHTTPHandler(t, &fakeDecisionEvaluator{}, nil)
	for _, credential := range []string{"", "Bearer wrong-token", "Basic token-1"} {
		request := decisionRequest(t, credential, readGolden(t, "evaluate_external_send_request.json"))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		assertErrorResponse(t, recorder, http.StatusUnauthorized, httptransport.ErrorAuthentication)
	}
}

func TestDecisionHandlerUsesAuthenticatedRuntimeContext(t *testing.T) {
	evaluator := &fakeDecisionEvaluator{evaluate: func(
		_ context.Context,
		runtime application.AuthenticatedRuntime,
		command application.EvaluateActionCommand,
	) (application.DecisionRecord, error) {
		if runtime.RuntimeID() != command.ProposedAction.Actor.RuntimeID {
			return application.DecisionRecord{}, application.ErrRuntimeIdentityConflict
		}
		return allowRecord(t, "decision-1"), nil
	}}
	handler := newTestHTTPHandlerWithTokens(t, evaluator, nil, map[string]string{"token-1": "runtime-other"})
	request := decisionRequest(t, "Bearer token-1", readGolden(t, "evaluate_external_send_request.json"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assertErrorResponse(t, recorder, http.StatusForbidden, httptransport.ErrorRuntimeForbidden)
}

func TestDecisionHandlerReturnsDecisionVariants(t *testing.T) {
	approval, err := domain.NewDenyDecision(
		[]domain.ReasonCode{domain.ReasonDelegatorApprovalRequired, domain.ReasonExternalDestination},
		[]domain.RequiredAction{domain.NewRequireApprovalAction()},
	)
	if err != nil {
		t.Fatalf("approval decision: %v", err)
	}
	terminal, err := domain.NewDenyDecision([]domain.ReasonCode{domain.ReasonActorNotAuthorized}, nil)
	if err != nil {
		t.Fatalf("terminal decision: %v", err)
	}
	tests := []struct {
		name             string
		decision         domain.Decision
		wantType         httptransport.DecisionType
		wantReasons      int
		wantRequirements int
	}{
		{name: "direct allow", decision: domain.NewAllowDecision(), wantType: httptransport.DecisionAllow},
		{name: "terminal deny", decision: terminal, wantType: httptransport.DecisionDeny, wantReasons: 1},
		{name: "approval required", decision: approval, wantType: httptransport.DecisionDeny, wantReasons: 2, wantRequirements: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := &fakeDecisionEvaluator{records: []application.DecisionRecord{decisionRecord(t, "decision-1", test.decision)}}
			handler := newTestHTTPHandler(t, evaluator, nil)
			request := decisionRequest(t, "Bearer token-1", readGolden(t, "evaluate_external_send_request.json"))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			var response httptransport.DecisionResponse
			if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if response.RequestID != "req_123" || response.DecisionID != "decision-1" || response.Decision != test.wantType {
				t.Fatalf("unexpected response: %#v", response)
			}
			if len(response.ReasonCodes) != test.wantReasons || len(response.RequiredActions) != test.wantRequirements {
				t.Fatalf("reasons=%v requiredActions=%v", response.ReasonCodes, response.RequiredActions)
			}
			if test.wantRequirements == 1 && response.RequiredActions[0].Type != httptransport.RequiredActionRequireApproval {
				t.Fatalf("required actions=%v", response.RequiredActions)
			}
		})
	}
}

func TestDecisionHandlerMapsAllActionVariants(t *testing.T) {
	tests := []struct {
		fixture string
		typ     domain.ActionType
	}{
		{fixture: "evaluate_external_send_request.json", typ: domain.ActionExternalSend},
		{fixture: "evaluate_update_resource_access_request.json", typ: domain.ActionUpdateResourceAccess},
		{fixture: "evaluate_delete_request.json", typ: domain.ActionDelete},
	}
	for _, test := range tests {
		t.Run(string(test.typ), func(t *testing.T) {
			evaluator := &fakeDecisionEvaluator{evaluate: func(
				_ context.Context,
				_ application.AuthenticatedRuntime,
				command application.EvaluateActionCommand,
			) (application.DecisionRecord, error) {
				if command.ProposedAction.Type != test.typ || command.ProposedAction.Parameters == nil {
					t.Fatalf("mapped command=%#v", command)
				}
				return allowRecord(t, "decision-1"), nil
			}}
			handler := newTestHTTPHandler(t, evaluator, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, decisionRequest(t, "Bearer token-1", readGolden(t, test.fixture)))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestDecisionHandlerRetriesEchoStableRequestID(t *testing.T) {
	winner := allowRecord(t, "decision-winner")
	evaluator := &fakeDecisionEvaluator{records: []application.DecisionRecord{winner, winner}}
	handler := newTestHTTPHandler(t, evaluator, nil)
	for index := 0; index < 2; index++ {
		request := decisionRequest(t, "Bearer token-1", readGolden(t, "evaluate_external_send_request.json"))
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("retry %d status=%d", index, recorder.Code)
		}
		var response httptransport.DecisionResponse
		_ = json.NewDecoder(recorder.Body).Decode(&response)
		if response.RequestID != "req_123" || response.DecisionID != "decision-winner" {
			t.Fatalf("retry response=%#v", response)
		}
	}
	if len(evaluator.commands) != 2 || evaluator.commands[0].RequestID != evaluator.commands[1].RequestID {
		t.Fatalf("commands=%#v", evaluator.commands)
	}
}

func TestDecisionHandlerMapsStableErrors(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		serviceErr error
		wantStatus int
		wantCode   httptransport.ErrorCode
	}{
		{name: "malformed", body: []byte(`{"apiVersion":`), wantStatus: http.StatusBadRequest, wantCode: httptransport.ErrorMalformedRequest},
		{name: "domain validation", body: readGolden(t, "evaluate_external_send_request.json"), serviceErr: application.ErrInvalidInput, wantStatus: http.StatusUnprocessableEntity, wantCode: httptransport.ErrorValidation},
		{name: "request conflict", body: readGolden(t, "evaluate_external_send_request.json"), serviceErr: application.ErrRequestIDConflict, wantStatus: http.StatusConflict, wantCode: httptransport.ErrorRequestIDConflict},
		{name: "internal", body: readGolden(t, "evaluate_external_send_request.json"), serviceErr: application.ErrLedgerFailure, wantStatus: http.StatusInternalServerError, wantCode: httptransport.ErrorInternal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evaluator := &fakeDecisionEvaluator{err: test.serviceErr}
			handler := newTestHTTPHandler(t, evaluator, nil)
			request := decisionRequest(t, "Bearer token-1", test.body)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assertErrorResponse(t, recorder, test.wantStatus, test.wantCode)
		})
	}
}

func TestDecisionHandlerRejectsUnknownSecurityFields(t *testing.T) {
	body := bytes.Replace(
		readGolden(t, "evaluate_external_send_request.json"),
		[]byte(`"runtimeId": "runtime_456"`),
		[]byte(`"runtimeId": "runtime_456", "trusted": true`),
		1,
	)
	handler := newTestHTTPHandler(t, &fakeDecisionEvaluator{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, decisionRequest(t, "Bearer token-1", body))
	assertErrorResponse(t, recorder, http.StatusBadRequest, httptransport.ErrorMalformedRequest)
}

func TestDecisionHandlerWritesStructuredDecisionLog(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := newTestHTTPHandler(t, &fakeDecisionEvaluator{records: []application.DecisionRecord{allowRecord(t, "decision-1")}}, logger)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, decisionRequest(t, "Bearer token-1", readGolden(t, "evaluate_external_send_request.json")))
	for _, value := range []string{`"runtime_id":"runtime_456"`, `"request_id":"req_123"`, `"decision_id":"decision-1"`, `"policy_version":"policy-v1"`} {
		if !strings.Contains(logs.String(), value) {
			t.Fatalf("log %s does not contain %s", logs.String(), value)
		}
	}
}

func newTestHTTPHandler(t *testing.T, evaluator httptransport.DecisionEvaluator, logger *slog.Logger) http.Handler {
	t.Helper()
	return newTestHTTPHandlerWithTokens(t, evaluator, logger, map[string]string{"token-1": "runtime_456"})
}

func newTestHTTPHandlerWithTokens(
	t *testing.T,
	evaluator httptransport.DecisionEvaluator,
	logger *slog.Logger,
	tokens map[string]string,
) http.Handler {
	t.Helper()
	authenticator, err := auth.NewStaticRuntimeAuthenticator(tokens)
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	handler, err := httptransport.NewHandler(httptransport.HandlerConfig{
		RuntimeAuthenticator: authenticator,
		DecisionEvaluator:    evaluator,
		Logger:               logger,
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	return handler
}

func decisionRequest(t *testing.T, authorization string, body []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/action-decisions", bytes.NewReader(body))
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	request.Header.Set("Content-Type", "application/json")
	return request
}

func allowRecord(t *testing.T, decisionID string) application.DecisionRecord {
	t.Helper()
	return decisionRecord(t, decisionID, domain.NewAllowDecision())
}

func decisionRecord(t *testing.T, decisionID string, decision domain.Decision) application.DecisionRecord {
	t.Helper()
	digest, err := domain.ParseActionDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("parse digest: %v", err)
	}
	return application.DecisionRecord{
		DecisionID:    decisionID,
		Decision:      decision,
		ActionDigest:  digest,
		PolicyVersion: "policy-v1",
		EvaluatedAt:   time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC),
	}
}

func assertErrorResponse(t *testing.T, recorder *httptest.ResponseRecorder, status int, code httptransport.ErrorCode) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d want=%d body=%s", recorder.Code, status, recorder.Body.String())
	}
	var response httptransport.ErrorResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if response.Error.Code != code {
		t.Fatalf("error code=%q want=%q", response.Error.Code, code)
	}
}

type fakeDecisionEvaluator struct {
	evaluate func(context.Context, application.AuthenticatedRuntime, application.EvaluateActionCommand) (application.DecisionRecord, error)
	records  []application.DecisionRecord
	err      error
	commands []application.EvaluateActionCommand
}

func (evaluator *fakeDecisionEvaluator) Evaluate(
	ctx context.Context,
	runtime application.AuthenticatedRuntime,
	command application.EvaluateActionCommand,
) (application.DecisionRecord, error) {
	evaluator.commands = append(evaluator.commands, command)
	if evaluator.evaluate != nil {
		return evaluator.evaluate(ctx, runtime, command)
	}
	if evaluator.err != nil {
		return application.DecisionRecord{}, evaluator.err
	}
	if len(evaluator.records) == 0 {
		return application.DecisionRecord{}, errors.New("no fake decision configured")
	}
	record := evaluator.records[0]
	evaluator.records = evaluator.records[1:]
	return record, nil
}
