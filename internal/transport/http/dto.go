package httptransport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const APIVersionV1 = "v1"

type ProposedActionType string

const (
	ActionExternalSend         ProposedActionType = "EXTERNAL_SEND"
	ActionUpdateResourceAccess ProposedActionType = "UPDATE_RESOURCE_ACCESS"
	ActionDelete               ProposedActionType = "DELETE"
)

type DecisionType string

const (
	DecisionAllow DecisionType = "ALLOW"
	DecisionDeny  DecisionType = "DENY"
)

type RequiredActionType string

const (
	RequiredActionRequireApproval RequiredActionType = "REQUIRE_APPROVAL"
)

type ErrorCode string

const (
	ErrorMalformedRequest  ErrorCode = "MALFORMED_REQUEST"
	ErrorAuthentication    ErrorCode = "AUTHENTICATION_REQUIRED"
	ErrorRuntimeForbidden  ErrorCode = "RUNTIME_NOT_AUTHORIZED"
	ErrorRequestIDConflict ErrorCode = "REQUEST_ID_REUSED_WITH_DIFFERENT_ACTION"
	ErrorValidation        ErrorCode = "VALIDATION_FAILED"
	ErrorInternal          ErrorCode = "INTERNAL_ERROR"
)

type EvaluateActionRequest struct {
	APIVersion     string         `json:"apiVersion"`
	RequestID      string         `json:"requestId"`
	ProposedAction ProposedAction `json:"proposedAction"`
}

type ProposedAction struct {
	Type                  ProposedActionType      `json:"type"`
	RequestedAt           time.Time               `json:"requestedAt"`
	Actor                 Actor                   `json:"actor"`
	Delegation            Delegation              `json:"delegation"`
	Target                Target                  `json:"target"`
	Parameters            json.RawMessage         `json:"parameters"`
	Payload               Payload                 `json:"payload"`
	AuthorizationEvidence []AuthorizationEvidence `json:"authorizationEvidence,omitempty"`
}

type Actor struct {
	AgentID   string `json:"agentId"`
	RuntimeID string `json:"runtimeId"`
	SessionID string `json:"sessionId,omitempty"`
}

type Delegation struct {
	DelegationID string    `json:"delegationId"`
	Delegator    Principal `json:"delegator"`
}

type Principal struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Target struct {
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
}

type Payload struct {
	Digest         string   `json:"digest"`
	Classification []string `json:"classification,omitempty"`
	SizeBytes      *int64   `json:"sizeBytes,omitempty"`
}

type AuthorizationEvidence struct {
	Type       string             `json:"type"`
	EvidenceID string             `json:"evidenceId"`
	IssuedBy   Principal          `json:"issuedBy"`
	Scope      AuthorizationScope `json:"scope"`
}

type AuthorizationScope struct {
	ActionType       ProposedActionType `json:"actionType"`
	DestinationScope string             `json:"destinationScope,omitempty"`
	RequestedScope   string             `json:"requestedScope,omitempty"`
	DeleteMode       string             `json:"deleteMode,omitempty"`
}

type ExternalSendParameters struct {
	DestinationScope string   `json:"destinationScope"`
	Recipients       []string `json:"recipients"`
}

type UpdateResourceAccessParameters struct {
	CurrentScope     string      `json:"currentScope"`
	RequestedScope   string      `json:"requestedScope"`
	TargetPrincipals []Principal `json:"targetPrincipals,omitempty"`
}

type DeleteParameters struct {
	DeleteMode  string `json:"deleteMode"`
	Recoverable bool   `json:"recoverable"`
}

type DecisionResponse struct {
	APIVersion      string           `json:"apiVersion"`
	RequestID       string           `json:"requestId"`
	DecisionID      string           `json:"decisionId"`
	ActionDigest    string           `json:"actionDigest"`
	Decision        DecisionType     `json:"decision"`
	ReasonCodes     []string         `json:"reasonCodes"`
	RequiredActions []RequiredAction `json:"requiredActions"`
	Policy          PolicyMetadata   `json:"policy"`
	EvaluatedAt     time.Time        `json:"evaluatedAt"`
}

type RequiredAction struct {
	Type RequiredActionType `json:"type"`
}

type PolicyMetadata struct {
	Version string `json:"version"`
}

type ErrorResponse struct {
	APIVersion string       `json:"apiVersion"`
	RequestID  string       `json:"requestId,omitempty"`
	Error      ErrorPayload `json:"error"`
}

type ErrorPayload struct {
	Code    ErrorCode     `json:"code"`
	Message string        `json:"message"`
	Details []ErrorDetail `json:"details,omitempty"`
}

type ErrorDetail struct {
	Field string `json:"field,omitempty"`
	Code  string `json:"code"`
}

func DecodeEvaluateActionRequest(reader io.Reader) (EvaluateActionRequest, error) {
	var request EvaluateActionRequest
	if err := decodeStrict(reader, &request); err != nil {
		return EvaluateActionRequest{}, fmt.Errorf("decode action decision request: %w", err)
	}
	if request.APIVersion != APIVersionV1 {
		return EvaluateActionRequest{}, fmt.Errorf("unsupported apiVersion %q", request.APIVersion)
	}
	if err := request.ProposedAction.ValidateParameters(); err != nil {
		return EvaluateActionRequest{}, err
	}
	return request, nil
}

func (action ProposedAction) ValidateParameters() error {
	var target any
	switch action.Type {
	case ActionExternalSend:
		target = &ExternalSendParameters{}
	case ActionUpdateResourceAccess:
		target = &UpdateResourceAccessParameters{}
	case ActionDelete:
		target = &DeleteParameters{}
	default:
		return fmt.Errorf("unsupported proposed action type %q", action.Type)
	}
	if err := decodeStrict(bytes.NewReader(action.Parameters), target); err != nil {
		return fmt.Errorf("decode %s parameters: %w", action.Type, err)
	}
	return nil
}

func (response DecisionResponse) Validate() error {
	if response.APIVersion != APIVersionV1 {
		return fmt.Errorf("unsupported apiVersion %q", response.APIVersion)
	}
	if response.Decision != DecisionAllow && response.Decision != DecisionDeny {
		return fmt.Errorf("unsupported decision %q", response.Decision)
	}
	if response.Decision == DecisionAllow {
		if len(response.ReasonCodes) != 0 {
			return errors.New("ALLOW cannot include reason codes in v1")
		}
		if len(response.RequiredActions) != 0 {
			return errors.New("ALLOW cannot include required actions in v1")
		}
		return nil
	}
	if len(response.ReasonCodes) == 0 {
		return errors.New("DENY requires at least one reason code")
	}

	hasApprovalReason := false
	for _, reason := range response.ReasonCodes {
		if reason == "DELEGATOR_APPROVAL_REQUIRED" {
			hasApprovalReason = true
		}
	}

	for _, action := range response.RequiredActions {
		switch action.Type {
		case RequiredActionRequireApproval:
		default:
			return fmt.Errorf("unsupported required action type %q", action.Type)
		}
	}
	if hasApprovalReason != (len(response.RequiredActions) == 1) {
		return errors.New("DELEGATOR_APPROVAL_REQUIRED and REQUIRE_APPROVAL must appear together in v1")
	}
	return nil
}

func decodeStrict(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
