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
	if err := validateSHA256Digest(value); err != nil {
		return "", err
	}
	return ActionDigest(value), nil
}

func (digest ActionDigest) Valid() bool {
	_, err := ParseActionDigest(string(digest))
	return err == nil
}

func (digest ActionDigest) String() string { return string(digest) }

// PayloadDigest identifies the exact raw payload without retaining its content.
// It is distinct from ActionDigest, which M1-05 computes over the complete
// normalized action.
type PayloadDigest string

func ParsePayloadDigest(value string) (PayloadDigest, error) {
	if err := validateSHA256Digest(value); err != nil {
		return "", err
	}
	return PayloadDigest(value), nil
}

func (digest PayloadDigest) Valid() bool {
	_, err := ParsePayloadDigest(string(digest))
	return err == nil
}

func (digest PayloadDigest) String() string { return string(digest) }

func validateSHA256Digest(value string) error {
	const (
		prefix      = "sha256:"
		hexSize     = 64
		encodedSize = len(prefix) + hexSize
	)
	if len(value) != encodedSize || !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("%w: expected sha256 followed by 64 lowercase hexadecimal characters", ErrInvalidDigest)
	}
	for _, character := range value[len(prefix):] {
		if (character < 'a' || character > 'f') && (character < '0' || character > '9') {
			return fmt.Errorf("%w: unsupported digest character %q", ErrInvalidDigest, character)
		}
	}
	return nil
}

// Actor identifies the agent and trusted runtime that proposed an action.
type Actor struct {
	agentID   string
	runtimeID string
	sessionID string
}

func NewActor(agentID, runtimeID, sessionID string) (Actor, error) {
	agentID, err := normalizeRequiredIdentifier(agentID, "agent id")
	if err != nil {
		return Actor{}, err
	}
	runtimeID, err = normalizeRequiredIdentifier(runtimeID, "runtime id")
	if err != nil {
		return Actor{}, err
	}
	sessionID, err = normalizeOptionalIdentifier(sessionID, "session id")
	if err != nil {
		return Actor{}, err
	}
	return Actor{
		agentID:   agentID,
		runtimeID: runtimeID,
		sessionID: sessionID,
	}, nil
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
	typ         ActionType
	requestedAt time.Time
	actor       Actor
	delegation  Delegation
	target      Target
	parameters  ActionParameters
	payload     PayloadFacts
	evidence    []AuthorizationEvidence
}

func NewProposedAction(
	typ ActionType,
	requestedAt time.Time,
	actor Actor,
	delegation Delegation,
	target Target,
	parameters ActionParameters,
	payload PayloadFacts,
	evidence []AuthorizationEvidence,
) (ProposedAction, error) {
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
	if !payload.valid() {
		return ProposedAction{}, ErrInvalidDigest
	}
	normalizedEvidence, err := NormalizeAuthorizationEvidence(evidence)
	if err != nil {
		return ProposedAction{}, err
	}
	return ProposedAction{
		typ:         typ,
		requestedAt: requestedAt.UTC(),
		actor:       actor,
		delegation:  delegation,
		target:      target,
		parameters:  parameters.clone(),
		payload:     payload.clone(),
		evidence:    normalizedEvidence,
	}, nil
}

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
func (action ProposedAction) Payload() PayloadFacts        { return action.payload.clone() }
func (action ProposedAction) PayloadDigest() PayloadDigest { return action.payload.Digest() }
func (action ProposedAction) AuthorizationEvidence() []AuthorizationEvidence {
	return cloneAuthorizationEvidence(action.evidence)
}
