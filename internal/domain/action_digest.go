package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const canonicalActionSchemaV1 = "agent-action-control/action-digest/v1"

// CanonicalActionBytes serializes every security-relevant normalized action
// fact into the versioned byte representation used by ComputeActionDigest.
// Proposed-action ID is deliberately excluded: it is the ledger idempotency
// key, while this digest identifies the action's security semantics.
func CanonicalActionBytes(action ProposedAction) ([]byte, error) {
	normalized, err := NewProposedAction(
		action.id,
		action.typ,
		action.requestedAt,
		action.actor,
		action.delegation,
		action.target,
		action.parameters,
		action.payload,
		action.evidence,
	)
	if err != nil {
		return nil, fmt.Errorf("canonicalize proposed action: %w", err)
	}

	parameters, err := canonicalParameters(normalized.parameters)
	if err != nil {
		return nil, err
	}
	evidence := make([]canonicalAuthorizationEvidence, 0, len(normalized.evidence))
	for _, item := range normalized.evidence {
		evidence = append(evidence, canonicalEvidence(item))
	}

	value := canonicalAction{
		Schema:      canonicalActionSchemaV1,
		Type:        normalized.typ,
		RequestedAt: normalized.requestedAt.UTC().Format(canonicalTimeFormat),
		Actor: canonicalActor{
			AgentID:   normalized.actor.AgentID(),
			RuntimeID: normalized.actor.RuntimeID(),
			SessionID: normalized.actor.SessionID(),
		},
		Delegation: canonicalDelegation{
			ID:        normalized.delegation.ID(),
			Delegator: canonicalPrincipalValue(normalized.delegation.Delegator()),
		},
		Target: canonicalTarget{
			ResourceType: normalized.target.ResourceType(),
			ResourceID:   normalized.target.ResourceID(),
		},
		Parameters: parameters,
		Payload: canonicalPayload{
			Digest:         normalized.payload.Digest().String(),
			Classification: append([]string{}, normalized.payload.Classification()...),
			SizeBytes:      normalized.payload.SizeBytes(),
		},
		AuthorizationEvidence: evidence,
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical action: %w", err)
	}
	return result, nil
}

// ComputeActionDigest binds a decision to the canonical normalized action.
func ComputeActionDigest(action ProposedAction) (ActionDigest, error) {
	canonical, err := CanonicalActionBytes(action)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return ActionDigest("sha256:" + hex.EncodeToString(sum[:])), nil
}

const canonicalTimeFormat = "2006-01-02T15:04:05.000000000Z"

type canonicalAction struct {
	Schema                string                           `json:"schema"`
	Type                  ActionType                       `json:"type"`
	RequestedAt           string                           `json:"requestedAt"`
	Actor                 canonicalActor                   `json:"actor"`
	Delegation            canonicalDelegation              `json:"delegation"`
	Target                canonicalTarget                  `json:"target"`
	Parameters            any                              `json:"parameters"`
	Payload               canonicalPayload                 `json:"payload"`
	AuthorizationEvidence []canonicalAuthorizationEvidence `json:"authorizationEvidence"`
}

type canonicalActor struct {
	AgentID   string `json:"agentId"`
	RuntimeID string `json:"runtimeId"`
	SessionID string `json:"sessionId"`
}

type canonicalPrincipal struct {
	Type PrincipalType `json:"type"`
	ID   string        `json:"id"`
}

type canonicalDelegation struct {
	ID        string             `json:"id"`
	Delegator canonicalPrincipal `json:"delegator"`
}

type canonicalTarget struct {
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
}

type canonicalExternalSendParameters struct {
	DestinationScope DestinationScope `json:"destinationScope"`
	Recipients       []string         `json:"recipients"`
}

type canonicalUpdateResourceAccessParameters struct {
	CurrentScope     AccessScope          `json:"currentScope"`
	RequestedScope   AccessScope          `json:"requestedScope"`
	TargetPrincipals []canonicalPrincipal `json:"targetPrincipals"`
}

type canonicalDeleteParameters struct {
	DeleteMode  DeleteMode `json:"deleteMode"`
	Recoverable bool       `json:"recoverable"`
}

type canonicalPayload struct {
	Digest         string   `json:"digest"`
	Classification []string `json:"classification"`
	SizeBytes      *int64   `json:"sizeBytes"`
}

type canonicalAuthorizationEvidence struct {
	Type       AuthorizationEvidenceType   `json:"type"`
	EvidenceID string                      `json:"evidenceId"`
	IssuedBy   canonicalPrincipal          `json:"issuedBy"`
	Scope      canonicalAuthorizationScope `json:"scope"`
}

type canonicalAuthorizationScope struct {
	ActionType       ActionType       `json:"actionType"`
	DestinationScope DestinationScope `json:"destinationScope,omitempty"`
	RequestedScope   AccessScope      `json:"requestedScope,omitempty"`
	DeleteMode       DeleteMode       `json:"deleteMode,omitempty"`
}

func canonicalParameters(parameters ActionParameters) (any, error) {
	switch value := parameters.(type) {
	case ExternalSendParameters:
		return canonicalExternalSendParameters{
			DestinationScope: value.DestinationScope(),
			Recipients:       append([]string{}, value.Recipients()...),
		}, nil
	case UpdateResourceAccessParameters:
		principals := value.TargetPrincipals()
		canonicalPrincipals := make([]canonicalPrincipal, 0, len(principals))
		for _, principal := range principals {
			canonicalPrincipals = append(canonicalPrincipals, canonicalPrincipalValue(principal))
		}
		return canonicalUpdateResourceAccessParameters{
			CurrentScope:     value.CurrentScope(),
			RequestedScope:   value.RequestedScope(),
			TargetPrincipals: canonicalPrincipals,
		}, nil
	case DeleteParameters:
		return canonicalDeleteParameters{
			DeleteMode:  value.Mode(),
			Recoverable: value.Recoverable(),
		}, nil
	default:
		return nil, fmt.Errorf("%w: unsupported canonical action parameters", ErrInvalidArgument)
	}
}

func canonicalPrincipalValue(principal Principal) canonicalPrincipal {
	return canonicalPrincipal{Type: principal.Type(), ID: principal.ID()}
}

func canonicalEvidence(evidence AuthorizationEvidence) canonicalAuthorizationEvidence {
	scope := evidence.Scope()
	return canonicalAuthorizationEvidence{
		Type:       evidence.Type(),
		EvidenceID: evidence.ID(),
		IssuedBy:   canonicalPrincipalValue(evidence.IssuedBy()),
		Scope: canonicalAuthorizationScope{
			ActionType:       scope.ActionType(),
			DestinationScope: scope.DestinationScope(),
			RequestedScope:   scope.RequestedScope(),
			DeleteMode:       scope.DeleteMode(),
		},
	}
}
