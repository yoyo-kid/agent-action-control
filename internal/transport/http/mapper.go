package httptransport

import (
	"bytes"
	"fmt"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

func toEvaluateActionCommand(request EvaluateActionRequest) (application.EvaluateActionCommand, error) {
	actionType, err := domain.ParseActionType(string(request.ProposedAction.Type))
	if err != nil {
		return application.EvaluateActionCommand{}, err
	}
	parameters, err := toActionParameters(request.ProposedAction)
	if err != nil {
		return application.EvaluateActionCommand{}, err
	}
	evidence := make([]application.AuthorizationEvidenceInput, 0, len(request.ProposedAction.AuthorizationEvidence))
	for _, item := range request.ProposedAction.AuthorizationEvidence {
		evidenceActionType, err := domain.ParseActionType(string(item.Scope.ActionType))
		if err != nil {
			return application.EvaluateActionCommand{}, fmt.Errorf("authorization evidence action type: %w", err)
		}
		issuerType, err := domain.ParsePrincipalType(item.IssuedBy.Type)
		if err != nil {
			return application.EvaluateActionCommand{}, fmt.Errorf("authorization evidence issuer: %w", err)
		}
		evidence = append(evidence, application.AuthorizationEvidenceInput{
			Type:       item.Type,
			EvidenceID: item.EvidenceID,
			IssuedBy: application.PrincipalInput{
				Type: issuerType,
				ID:   item.IssuedBy.ID,
			},
			Scope: application.AuthorizationScopeInput{
				ActionType:       evidenceActionType,
				DestinationScope: item.Scope.DestinationScope,
				RequestedScope:   item.Scope.RequestedScope,
				DeleteMode:       item.Scope.DeleteMode,
			},
		})
	}
	delegatorType, err := domain.ParsePrincipalType(request.ProposedAction.Delegation.Delegator.Type)
	if err != nil {
		return application.EvaluateActionCommand{}, fmt.Errorf("delegator: %w", err)
	}
	return application.EvaluateActionCommand{
		RequestID: request.RequestID,
		ProposedAction: application.ProposedActionInput{
			Type:        actionType,
			RequestedAt: request.ProposedAction.RequestedAt,
			Actor: application.ActorInput{
				AgentID:   request.ProposedAction.Actor.AgentID,
				RuntimeID: request.ProposedAction.Actor.RuntimeID,
				SessionID: request.ProposedAction.Actor.SessionID,
			},
			Delegation: application.DelegationInput{
				ID: request.ProposedAction.Delegation.DelegationID,
				Delegator: application.PrincipalInput{
					Type: delegatorType,
					ID:   request.ProposedAction.Delegation.Delegator.ID,
				},
			},
			Target: application.TargetInput{
				ResourceType: request.ProposedAction.Target.ResourceType,
				ResourceID:   request.ProposedAction.Target.ResourceID,
			},
			Parameters: parameters,
			Payload: application.PayloadInput{
				Digest:         request.ProposedAction.Payload.Digest,
				Classification: append([]string(nil), request.ProposedAction.Payload.Classification...),
				SizeBytes:      cloneInt64(request.ProposedAction.Payload.SizeBytes),
			},
			AuthorizationEvidence: evidence,
		},
	}, nil
}

func toActionParameters(action ProposedAction) (application.ActionParametersInput, error) {
	switch action.Type {
	case ActionExternalSend:
		var value ExternalSendParameters
		if err := decodeStrict(bytes.NewReader(action.Parameters), &value); err != nil {
			return nil, err
		}
		return application.ExternalSendInput{
			DestinationScope: value.DestinationScope,
			Recipients:       append([]string(nil), value.Recipients...),
		}, nil
	case ActionUpdateResourceAccess:
		var value UpdateResourceAccessParameters
		if err := decodeStrict(bytes.NewReader(action.Parameters), &value); err != nil {
			return nil, err
		}
		principals := make([]application.PrincipalInput, 0, len(value.TargetPrincipals))
		for _, item := range value.TargetPrincipals {
			typ, err := domain.ParsePrincipalType(item.Type)
			if err != nil {
				return nil, err
			}
			principals = append(principals, application.PrincipalInput{Type: typ, ID: item.ID})
		}
		return application.UpdateResourceAccessInput{
			CurrentScope:     value.CurrentScope,
			RequestedScope:   value.RequestedScope,
			TargetPrincipals: principals,
		}, nil
	case ActionDelete:
		var value DeleteParameters
		if err := decodeStrict(bytes.NewReader(action.Parameters), &value); err != nil {
			return nil, err
		}
		return application.DeleteInput{DeleteMode: value.DeleteMode, Recoverable: value.Recoverable}, nil
	default:
		return nil, fmt.Errorf("unsupported proposed action type %q", action.Type)
	}
}

func toDecisionResponse(requestID string, record application.DecisionRecord) DecisionResponse {
	reasons := record.Decision.ReasonCodes()
	reasonValues := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		reasonValues = append(reasonValues, string(reason))
	}
	actions := record.Decision.RequiredActions()
	requiredActions := make([]RequiredAction, 0, len(actions))
	for _, action := range actions {
		requiredActions = append(requiredActions, RequiredAction{Type: RequiredActionType(action.Type())})
	}
	return DecisionResponse{
		APIVersion:      APIVersionV1,
		RequestID:       requestID,
		DecisionID:      record.DecisionID,
		ActionDigest:    record.ActionDigest.String(),
		Decision:        DecisionType(record.Decision.Type()),
		ReasonCodes:     reasonValues,
		RequiredActions: requiredActions,
		Policy:          PolicyMetadata{Version: record.PolicyVersion},
		EvaluatedAt:     record.EvaluatedAt,
	}
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
