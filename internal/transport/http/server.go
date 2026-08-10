// Package httptransport exposes the public HTTP surface for Agent Action Control.
package httptransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/auth"
)

const maximumDecisionRequestBytes = 1 << 20

type DecisionEvaluator interface {
	Evaluate(
		context.Context,
		application.AuthenticatedRuntime,
		application.EvaluateActionCommand,
	) (application.DecisionRecord, error)
}

type HandlerConfig struct {
	RuntimeAuthenticator auth.RuntimeAuthenticator
	DecisionEvaluator    DecisionEvaluator
	Logger               *slog.Logger
}

// NewHandler constructs the service HTTP handler with explicit replaceable
// authentication and application dependencies.
func NewHandler(config HandlerConfig) (http.Handler, error) {
	if config.RuntimeAuthenticator == nil || config.DecisionEvaluator == nil {
		return nil, fmt.Errorf("%w: HTTP handler dependencies are required", application.ErrInvalidInput)
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	handler := &handler{
		runtimeAuthenticator: config.RuntimeAuthenticator,
		decisionEvaluator:    config.DecisionEvaluator,
		logger:               logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("POST /v1/action-decisions", handler.evaluateAction)
	return mux, nil
}

type handler struct {
	runtimeAuthenticator auth.RuntimeAuthenticator
	decisionEvaluator    DecisionEvaluator
	logger               *slog.Logger
}

func health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (handler *handler) evaluateAction(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	credential, err := bearerCredential(request.Header.Get("Authorization"))
	if err != nil {
		handler.writeError(w, request, "", "", http.StatusUnauthorized, ErrorAuthentication, "Runtime authentication is required.", err)
		return
	}
	runtime, err := handler.runtimeAuthenticator.Authenticate(request.Context(), credential)
	if err != nil {
		handler.writeError(w, request, "", "", http.StatusUnauthorized, ErrorAuthentication, "Runtime authentication is required.", err)
		return
	}

	request.Body = http.MaxBytesReader(w, request.Body, maximumDecisionRequestBytes)
	decoded, err := DecodeEvaluateActionRequest(request.Body)
	if err != nil {
		handler.writeError(w, request, runtime.RuntimeID(), "", http.StatusBadRequest, ErrorMalformedRequest, "The request body is not valid JSON.", err)
		return
	}
	command, err := toEvaluateActionCommand(decoded)
	if err != nil {
		handler.writeError(w, request, runtime.RuntimeID(), decoded.RequestID, http.StatusUnprocessableEntity, ErrorValidation, "The proposed action is invalid.", err)
		return
	}
	record, err := handler.decisionEvaluator.Evaluate(request.Context(), runtime, command)
	if err != nil {
		handler.writeApplicationError(w, request, runtime.RuntimeID(), decoded.RequestID, err)
		return
	}
	response := toDecisionResponse(decoded.RequestID, record)
	if err := response.Validate(); err != nil {
		handler.writeError(w, request, runtime.RuntimeID(), decoded.RequestID, http.StatusInternalServerError, ErrorInternal, "No authoritative decision was produced.", err)
		return
	}
	handler.logger.InfoContext(
		request.Context(),
		"action decision evaluated",
		"runtime_id", runtime.RuntimeID(),
		"request_id", decoded.RequestID,
		"decision_id", record.DecisionID,
		"policy_version", record.PolicyVersion,
		"decision", record.Decision.Type(),
	)
	writeJSON(w, http.StatusOK, response)
}

func (handler *handler) writeApplicationError(
	w http.ResponseWriter,
	request *http.Request,
	runtimeID string,
	requestID string,
	err error,
) {
	switch {
	case errors.Is(err, application.ErrRuntimeIdentityConflict):
		handler.writeError(w, request, runtimeID, requestID, http.StatusForbidden, ErrorRuntimeForbidden, "The caller is not authorized for this runtime.", err)
	case errors.Is(err, application.ErrRequestIDConflict):
		handler.writeErrorWithDetails(
			w,
			request,
			runtimeID,
			requestID,
			http.StatusConflict,
			ErrorRequestIDConflict,
			"The request ID is already bound to a different action.",
			[]ErrorDetail{{Field: "requestId", Code: "IDEMPOTENCY_CONFLICT"}},
			err,
		)
	case errors.Is(err, application.ErrInvalidInput):
		handler.writeError(w, request, runtimeID, requestID, http.StatusUnprocessableEntity, ErrorValidation, "The proposed action is invalid.", err)
	default:
		handler.writeError(w, request, runtimeID, requestID, http.StatusInternalServerError, ErrorInternal, "No authoritative decision was produced.", err)
	}
}

func (handler *handler) writeError(
	w http.ResponseWriter,
	request *http.Request,
	runtimeID string,
	requestID string,
	status int,
	code ErrorCode,
	message string,
	err error,
) {
	handler.writeErrorWithDetails(w, request, runtimeID, requestID, status, code, message, nil, err)
}

func (handler *handler) writeErrorWithDetails(
	w http.ResponseWriter,
	request *http.Request,
	runtimeID string,
	requestID string,
	status int,
	code ErrorCode,
	message string,
	details []ErrorDetail,
	err error,
) {
	handler.logger.ErrorContext(
		request.Context(),
		"action decision failed",
		"runtime_id", runtimeID,
		"request_id", requestID,
		"error_code", code,
		"status", status,
		"error", err,
	)
	writeJSON(w, status, ErrorResponse{
		APIVersion: APIVersionV1,
		RequestID:  requestID,
		Error: ErrorPayload{
			Code:    code,
			Message: message,
			Details: details,
		},
	})
}

func bearerCredential(value string) (string, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", auth.ErrCredentialMissing
	}
	return parts[1], nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
