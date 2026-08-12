package osprey

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

const actionFactsVersion = "agent-action-control.osprey/v1"

type actionFacts struct {
	APIVersion            string                       `json:"apiVersion"`
	Type                  domain.ActionType            `json:"type"`
	RequestedAt           time.Time                    `json:"requestedAt"`
	Actor                 actorFacts                   `json:"actor"`
	Delegation            delegationFacts              `json:"delegation"`
	Target                targetFacts                  `json:"target"`
	Parameters            any                          `json:"parameters"`
	Payload               payloadFacts                 `json:"payload"`
	AuthorizationEvidence []authorizationEvidenceFacts `json:"authorizationEvidence"`
}

type actorFacts struct {
	AgentID   string `json:"agentId"`
	RuntimeID string `json:"runtimeId"`
	SessionID string `json:"sessionId,omitempty"`
}

type principalFacts struct {
	Type domain.PrincipalType `json:"type"`
	ID   string               `json:"id"`
}

type delegationFacts struct {
	DelegationID string         `json:"delegationId"`
	Delegator    principalFacts `json:"delegator"`
}

type targetFacts struct {
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
}

type payloadFacts struct {
	Digest         string   `json:"digest"`
	Classification []string `json:"classification"`
	SizeBytes      *int64   `json:"sizeBytes,omitempty"`
}

type authorizationEvidenceFacts struct {
	Type       domain.AuthorizationEvidenceType `json:"type"`
	EvidenceID string                           `json:"evidenceId"`
	IssuedBy   principalFacts                   `json:"issuedBy"`
	Scope      authorizationScopeFacts          `json:"scope"`
}

type authorizationScopeFacts struct {
	ActionType       domain.ActionType       `json:"actionType"`
	DestinationScope domain.DestinationScope `json:"destinationScope,omitempty"`
	RequestedScope   domain.AccessScope      `json:"requestedScope,omitempty"`
	DeleteMode       domain.DeleteMode       `json:"deleteMode,omitempty"`
}

type externalSendFacts struct {
	DestinationScope domain.DestinationScope `json:"destinationScope"`
	Recipients       []string                `json:"recipients"`
}

type updateResourceAccessFacts struct {
	CurrentScope     domain.AccessScope `json:"currentScope"`
	RequestedScope   domain.AccessScope `json:"requestedScope"`
	TargetPrincipals []principalFacts   `json:"targetPrincipals"`
}

type deleteFacts struct {
	DeleteMode  domain.DeleteMode `json:"deleteMode"`
	Recoverable bool              `json:"recoverable"`
}

func marshalAction(action domain.ProposedAction) ([]byte, error) {
	parameters, err := marshalParameters(action.Parameters())
	if err != nil {
		return nil, err
	}
	actor := action.Actor()
	delegation := action.Delegation()
	delegator := delegation.Delegator()
	target := action.Target()
	payload := action.Payload()
	evidence := action.AuthorizationEvidence()
	evidenceFacts := make([]authorizationEvidenceFacts, 0, len(evidence))
	for _, item := range evidence {
		issuer := item.IssuedBy()
		scope := item.Scope()
		evidenceFacts = append(evidenceFacts, authorizationEvidenceFacts{
			Type:       item.Type(),
			EvidenceID: item.ID(),
			IssuedBy:   principalFacts{Type: issuer.Type(), ID: issuer.ID()},
			Scope: authorizationScopeFacts{
				ActionType:       scope.ActionType(),
				DestinationScope: scope.DestinationScope(),
				RequestedScope:   scope.RequestedScope(),
				DeleteMode:       scope.DeleteMode(),
			},
		})
	}
	return json.Marshal(actionFacts{
		APIVersion:  actionFactsVersion,
		Type:        action.Type(),
		RequestedAt: action.RequestedAt(),
		Actor: actorFacts{
			AgentID:   actor.AgentID(),
			RuntimeID: actor.RuntimeID(),
			SessionID: actor.SessionID(),
		},
		Delegation: delegationFacts{
			DelegationID: delegation.ID(),
			Delegator:    principalFacts{Type: delegator.Type(), ID: delegator.ID()},
		},
		Target:     targetFacts{ResourceType: target.ResourceType(), ResourceID: target.ResourceID()},
		Parameters: parameters,
		Payload: payloadFacts{
			Digest:         payload.Digest().String(),
			Classification: payload.Classification(),
			SizeBytes:      payload.SizeBytes(),
		},
		AuthorizationEvidence: evidenceFacts,
	})
}

func marshalParameters(parameters domain.ActionParameters) (any, error) {
	switch value := parameters.(type) {
	case domain.ExternalSendParameters:
		return externalSendFacts{
			DestinationScope: value.DestinationScope(),
			Recipients:       value.Recipients(),
		}, nil
	case domain.UpdateResourceAccessParameters:
		principals := value.TargetPrincipals()
		facts := make([]principalFacts, 0, len(principals))
		for _, principal := range principals {
			facts = append(facts, principalFacts{Type: principal.Type(), ID: principal.ID()})
		}
		return updateResourceAccessFacts{
			CurrentScope:     value.CurrentScope(),
			RequestedScope:   value.RequestedScope(),
			TargetPrincipals: facts,
		}, nil
	case domain.DeleteParameters:
		return deleteFacts{DeleteMode: value.Mode(), Recoverable: value.Recoverable()}, nil
	default:
		return nil, fmt.Errorf("unsupported Osprey action parameters %T", parameters)
	}
}
