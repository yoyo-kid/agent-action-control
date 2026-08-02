package domain

import (
	"fmt"
	"strings"
	"time"
)

// ActionType identifies the side effect proposed by an agent runtime.
type ActionType string

const (
	ActionExternalSend         ActionType = "EXTERNAL_SEND"
	ActionUpdateResourceAccess ActionType = "UPDATE_RESOURCE_ACCESS"
	ActionDelete               ActionType = "DELETE"
)

func ParseActionType(value string) (ActionType, error) {
	typ := ActionType(value)
	if !typ.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidActionType, value)
	}
	return typ, nil
}

func (typ ActionType) Valid() bool {
	switch typ {
	case ActionExternalSend, ActionUpdateResourceAccess, ActionDelete:
		return true
	default:
		return false
	}
}

// ActionDigest binds a decision or approval to one exact normalized action.
type ActionDigest string

func ParseActionDigest(value string) (ActionDigest, error) {
	if len(value) < 8 || len(value) > 128 || !strings.HasPrefix(value, "sha256:") {
		return "", fmt.Errorf("%w: expected sha256 digest", ErrInvalidDigest)
	}
	for _, character := range value[len("sha256:"):] {
		if (character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' {
			return "", fmt.Errorf("%w: unsupported digest character %q", ErrInvalidDigest, character)
		}
	}
	return ActionDigest(value), nil
}

func (digest ActionDigest) Valid() bool {
	_, err := ParseActionDigest(string(digest))
	return err == nil
}

func (digest ActionDigest) String() string { return string(digest) }

// Actor identifies the agent and trusted runtime that proposed an action.
type Actor struct {
	agentID   string
	runtimeID string
	sessionID string
}

func NewActor(agentID, runtimeID, sessionID string) (Actor, error) {
	if strings.TrimSpace(agentID) == "" {
		return Actor{}, fmt.Errorf("%w: agent id is required", ErrInvalidArgument)
	}
	if strings.TrimSpace(runtimeID) == "" {
		return Actor{}, fmt.Errorf("%w: runtime id is required", ErrInvalidArgument)
	}
	return Actor{agentID: agentID, runtimeID: runtimeID, sessionID: sessionID}, nil
}

func (actor Actor) AgentID() string   { return actor.agentID }
func (actor Actor) RuntimeID() string { return actor.runtimeID }
func (actor Actor) SessionID() string { return actor.sessionID }

func (actor Actor) valid() bool {
	return strings.TrimSpace(actor.agentID) != "" && strings.TrimSpace(actor.runtimeID) != ""
}

// ActionParameters is implemented by the normalized, action-specific value
// objects introduced by the action normalizer. The unexported method keeps the
// variant set owned by this package.
type ActionParameters interface {
	ActionType() ActionType
	validate() error
	clone() ActionParameters
}

// ProposedAction is an immutable description of an intended side effect.
type ProposedAction struct {
	id            string
	typ           ActionType
	requestedAt   time.Time
	actor         Actor
	delegation    Delegation
	target        Target
	parameters    ActionParameters
	payloadDigest ActionDigest
}

func NewProposedAction(
	id string,
	typ ActionType,
	requestedAt time.Time,
	actor Actor,
	delegation Delegation,
	target Target,
	parameters ActionParameters,
	payloadDigest ActionDigest,
) (ProposedAction, error) {
	if strings.TrimSpace(id) == "" {
		return ProposedAction{}, fmt.Errorf("%w: proposed action id is required", ErrInvalidArgument)
	}
	if !typ.Valid() {
		return ProposedAction{}, fmt.Errorf("%w: %q", ErrInvalidActionType, typ)
	}
	if requestedAt.IsZero() {
		return ProposedAction{}, fmt.Errorf("%w: requested time is required", ErrInvalidArgument)
	}
	if !actor.valid() {
		return ProposedAction{}, fmt.Errorf("%w: valid actor is required", ErrInvalidArgument)
	}
	if !delegation.valid() {
		return ProposedAction{}, fmt.Errorf("%w: valid delegation is required", ErrInvalidArgument)
	}
	if !target.valid() {
		return ProposedAction{}, fmt.Errorf("%w: valid target is required", ErrInvalidArgument)
	}
	if parameters == nil {
		return ProposedAction{}, fmt.Errorf("%w: action parameters are required", ErrInvalidArgument)
	}
	if parameters.ActionType() != typ {
		return ProposedAction{}, fmt.Errorf("%w: parameter type %q does not match action type %q", ErrInvalidArgument, parameters.ActionType(), typ)
	}
	if err := parameters.validate(); err != nil {
		return ProposedAction{}, err
	}
	if !payloadDigest.Valid() {
		return ProposedAction{}, ErrInvalidDigest
	}
	return ProposedAction{
		id:            id,
		typ:           typ,
		requestedAt:   requestedAt,
		actor:         actor,
		delegation:    delegation,
		target:        target,
		parameters:    parameters.clone(),
		payloadDigest: payloadDigest,
	}, nil
}

func (action ProposedAction) ID() string             { return action.id }
func (action ProposedAction) Type() ActionType       { return action.typ }
func (action ProposedAction) RequestedAt() time.Time { return action.requestedAt }
func (action ProposedAction) Actor() Actor           { return action.actor }
func (action ProposedAction) Delegation() Delegation { return action.delegation }
func (action ProposedAction) Target() Target         { return action.target }
func (action ProposedAction) Parameters() ActionParameters {
	if action.parameters == nil {
		return nil
	}
	return action.parameters.clone()
}
func (action ProposedAction) PayloadDigest() ActionDigest { return action.payloadDigest }
