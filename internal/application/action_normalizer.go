package application

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

var ErrRuntimeIdentityConflict = errors.New("runtime identity conflicts with authenticated caller")

// AuthenticatedRuntime is trusted context supplied by the authentication adapter.
type AuthenticatedRuntime struct {
	RuntimeID string
}

// ProposedActionInput is transport-independent, caller-supplied action data.
// RuntimeID is an assertion and is never trusted over AuthenticatedRuntime.
type ProposedActionInput struct {
	ID                    string
	Type                  domain.ActionType
	RequestedAt           time.Time
	Actor                 ActorInput
	Delegation            DelegationInput
	Target                TargetInput
	Parameters            ActionParametersInput
	Payload               PayloadInput
	AuthorizationEvidence []AuthorizationEvidenceInput
}

type ActorInput struct {
	AgentID   string
	RuntimeID string
	SessionID string
}

type DelegationInput struct {
	ID        string
	Delegator PrincipalInput
}

type PrincipalInput struct {
	Type domain.PrincipalType
	ID   string
}

type TargetInput struct {
	ResourceType string
	ResourceID   string
}

type PayloadInput struct {
	Digest         string
	Classification []string
	SizeBytes      *int64
}

type AuthorizationEvidenceInput struct {
	Type       string
	EvidenceID string
	IssuedBy   PrincipalInput
	Scope      AuthorizationScopeInput
}

type AuthorizationScopeInput struct {
	ActionType       domain.ActionType
	DestinationScope string
	RequestedScope   string
	DeleteMode       string
}

// ActionParametersInput is a closed set of supported v1 action facts.
type ActionParametersInput interface {
	actionType() domain.ActionType
}

type ExternalSendInput struct {
	DestinationScope string
	Recipients       []string
}

func (ExternalSendInput) actionType() domain.ActionType { return domain.ActionExternalSend }

type UpdateResourceAccessInput struct {
	CurrentScope     string
	RequestedScope   string
	TargetPrincipals []PrincipalInput
}

func (UpdateResourceAccessInput) actionType() domain.ActionType {
	return domain.ActionUpdateResourceAccess
}

type DeleteInput struct {
	DeleteMode  string
	Recoverable bool
}

func (DeleteInput) actionType() domain.ActionType { return domain.ActionDelete }

// ActionNormalizer deterministically converts untrusted input and trusted
// runtime identity into an immutable domain action. It has no dependencies.
type ActionNormalizer struct{}

func (ActionNormalizer) Normalize(
	caller AuthenticatedRuntime,
	input ProposedActionInput,
) (domain.ProposedAction, error) {
	runtimeID := strings.TrimSpace(caller.RuntimeID)
	if runtimeID == "" {
		return domain.ProposedAction{}, fmt.Errorf("%w: authenticated runtime id is required", domain.ErrInvalidArgument)
	}
	claimedRuntimeID := strings.TrimSpace(input.Actor.RuntimeID)
	if claimedRuntimeID != "" && claimedRuntimeID != runtimeID {
		return domain.ProposedAction{}, fmt.Errorf(
			"%w: claimed %q, authenticated %q",
			ErrRuntimeIdentityConflict,
			claimedRuntimeID,
			runtimeID,
		)
	}

	actor, err := domain.NewActor(input.Actor.AgentID, runtimeID, input.Actor.SessionID)
	if err != nil {
		return domain.ProposedAction{}, fmt.Errorf("normalize actor: %w", err)
	}
	delegator, err := normalizePrincipal(input.Delegation.Delegator)
	if err != nil {
		return domain.ProposedAction{}, fmt.Errorf("normalize delegator: %w", err)
	}
	delegation, err := domain.NewDelegation(input.Delegation.ID, delegator)
	if err != nil {
		return domain.ProposedAction{}, fmt.Errorf("normalize delegation: %w", err)
	}
	target, err := domain.NewTarget(input.Target.ResourceType, input.Target.ResourceID)
	if err != nil {
		return domain.ProposedAction{}, fmt.Errorf("normalize target: %w", err)
	}
	parameters, err := normalizeParameters(input.Type, input.Parameters)
	if err != nil {
		return domain.ProposedAction{}, err
	}
	digest, err := domain.ParsePayloadDigest(strings.TrimSpace(input.Payload.Digest))
	if err != nil {
		return domain.ProposedAction{}, fmt.Errorf("normalize payload digest: %w", err)
	}
	payload, err := domain.NewPayloadFacts(digest, input.Payload.Classification, input.Payload.SizeBytes)
	if err != nil {
		return domain.ProposedAction{}, fmt.Errorf("normalize payload: %w", err)
	}
	evidence, err := normalizeEvidence(input.AuthorizationEvidence)
	if err != nil {
		return domain.ProposedAction{}, err
	}

	action, err := domain.NewProposedAction(
		input.ID,
		input.Type,
		input.RequestedAt,
		actor,
		delegation,
		target,
		parameters,
		payload,
		evidence,
	)
	if err != nil {
		return domain.ProposedAction{}, fmt.Errorf("normalize proposed action: %w", err)
	}
	return action, nil
}

func normalizeParameters(
	actionType domain.ActionType,
	input ActionParametersInput,
) (domain.ActionParameters, error) {
	if input == nil {
		return nil, fmt.Errorf("%w: action parameters are required", domain.ErrInvalidArgument)
	}
	if input.actionType() != actionType {
		return nil, fmt.Errorf(
			"%w: parameter type %q does not match action type %q",
			domain.ErrInvalidArgument,
			input.actionType(),
			actionType,
		)
	}

	switch value := input.(type) {
	case ExternalSendInput:
		scope, err := domain.ParseDestinationScope(value.DestinationScope)
		if err != nil {
			return nil, fmt.Errorf("normalize external send: %w", err)
		}
		parameters, err := domain.NewExternalSendParameters(scope, value.Recipients)
		if err != nil {
			return nil, fmt.Errorf("normalize external send: %w", err)
		}
		return parameters, nil
	case UpdateResourceAccessInput:
		currentScope, err := domain.ParseAccessScope(value.CurrentScope)
		if err != nil {
			return nil, fmt.Errorf("normalize resource access: %w", err)
		}
		requestedScope, err := domain.ParseAccessScope(value.RequestedScope)
		if err != nil {
			return nil, fmt.Errorf("normalize resource access: %w", err)
		}
		principals := make([]domain.Principal, 0, len(value.TargetPrincipals))
		for _, item := range value.TargetPrincipals {
			principal, err := normalizePrincipal(item)
			if err != nil {
				return nil, fmt.Errorf("normalize target principal: %w", err)
			}
			principals = append(principals, principal)
		}
		parameters, err := domain.NewUpdateResourceAccessParameters(currentScope, requestedScope, principals)
		if err != nil {
			return nil, fmt.Errorf("normalize resource access: %w", err)
		}
		return parameters, nil
	case DeleteInput:
		mode, err := domain.ParseDeleteMode(value.DeleteMode)
		if err != nil {
			return nil, fmt.Errorf("normalize delete: %w", err)
		}
		parameters, err := domain.NewDeleteParameters(mode, value.Recoverable)
		if err != nil {
			return nil, fmt.Errorf("normalize delete: %w", err)
		}
		return parameters, nil
	default:
		return nil, fmt.Errorf("%w: unsupported action parameters", domain.ErrInvalidArgument)
	}
}

func normalizePrincipal(input PrincipalInput) (domain.Principal, error) {
	return domain.NewPrincipal(input.Type, input.ID)
}

func normalizeEvidence(inputs []AuthorizationEvidenceInput) ([]domain.AuthorizationEvidence, error) {
	result := make([]domain.AuthorizationEvidence, 0, len(inputs))
	for _, input := range inputs {
		typ, err := domain.ParseAuthorizationEvidenceType(input.Type)
		if err != nil {
			return nil, fmt.Errorf("normalize authorization evidence: %w", err)
		}
		issuer, err := normalizePrincipal(input.IssuedBy)
		if err != nil {
			return nil, fmt.Errorf("normalize authorization evidence issuer: %w", err)
		}
		scope, err := normalizeAuthorizationScope(input.Scope)
		if err != nil {
			return nil, fmt.Errorf("normalize authorization evidence scope: %w", err)
		}
		evidence, err := domain.NewAuthorizationEvidence(typ, input.EvidenceID, issuer, scope)
		if err != nil {
			return nil, fmt.Errorf("normalize authorization evidence: %w", err)
		}
		result = append(result, evidence)
	}
	normalized, err := domain.NormalizeAuthorizationEvidence(result)
	if err != nil {
		return nil, fmt.Errorf("normalize authorization evidence: %w", err)
	}
	return normalized, nil
}

func normalizeAuthorizationScope(input AuthorizationScopeInput) (domain.AuthorizationScope, error) {
	var destinationScope domain.DestinationScope
	var requestedScope domain.AccessScope
	var deleteMode domain.DeleteMode
	var err error

	switch input.ActionType {
	case domain.ActionExternalSend:
		destinationScope, err = domain.ParseDestinationScope(input.DestinationScope)
	case domain.ActionUpdateResourceAccess:
		requestedScope, err = domain.ParseAccessScope(input.RequestedScope)
	case domain.ActionDelete:
		deleteMode, err = domain.ParseDeleteMode(input.DeleteMode)
	default:
		err = domain.ErrInvalidActionType
	}
	if err != nil {
		return domain.AuthorizationScope{}, err
	}
	return domain.NewAuthorizationScope(input.ActionType, destinationScope, requestedScope, deleteMode)
}
