package domain

import (
	"fmt"
	"strings"
)

// PrincipalType identifies a kind of actor in the delegation graph.
type PrincipalType string

const (
	PrincipalUser    PrincipalType = "USER"
	PrincipalAgent   PrincipalType = "AGENT"
	PrincipalRuntime PrincipalType = "RUNTIME"
	PrincipalService PrincipalType = "SERVICE"
)

func ParsePrincipalType(value string) (PrincipalType, error) {
	typ := PrincipalType(value)
	if !typ.Valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidPrincipalType, value)
	}
	return typ, nil
}

func (typ PrincipalType) Valid() bool {
	switch typ {
	case PrincipalUser, PrincipalAgent, PrincipalRuntime, PrincipalService:
		return true
	default:
		return false
	}
}

// Principal is a stable identity used for delegation and authorization.
type Principal struct {
	typ PrincipalType
	id  string
}

func NewPrincipal(typ PrincipalType, id string) (Principal, error) {
	if !typ.Valid() {
		return Principal{}, fmt.Errorf("%w: %q", ErrInvalidPrincipalType, typ)
	}
	id, err := normalizeRequiredIdentifier(id, "principal id")
	if err != nil {
		return Principal{}, err
	}
	return Principal{typ: typ, id: id}, nil
}

func (principal Principal) Type() PrincipalType { return principal.typ }
func (principal Principal) ID() string          { return principal.id }

func (principal Principal) valid() bool {
	return principal.typ.Valid() && strings.TrimSpace(principal.id) != ""
}

// Delegation binds an action to the principal that delegated authority.
type Delegation struct {
	id        string
	delegator Principal
}

func NewDelegation(id string, delegator Principal) (Delegation, error) {
	id, err := normalizeRequiredIdentifier(id, "delegation id")
	if err != nil {
		return Delegation{}, err
	}
	if !delegator.valid() {
		return Delegation{}, fmt.Errorf("%w: valid delegator is required", ErrInvalidArgument)
	}
	return Delegation{id: id, delegator: delegator}, nil
}

func (delegation Delegation) ID() string           { return delegation.id }
func (delegation Delegation) Delegator() Principal { return delegation.delegator }

func (delegation Delegation) valid() bool {
	return strings.TrimSpace(delegation.id) != "" && delegation.delegator.valid()
}

// Target identifies the resource affected by a proposed action.
type Target struct {
	resourceType string
	resourceID   string
}

func NewTarget(resourceType, resourceID string) (Target, error) {
	resourceType = strings.TrimSpace(resourceType)
	if resourceType == "" {
		return Target{}, fmt.Errorf("%w: target resource type is required", ErrInvalidArgument)
	}
	if len(resourceType) > 128 {
		return Target{}, fmt.Errorf("%w: target resource type exceeds 128 characters", ErrInvalidArgument)
	}
	resourceID, err := normalizeRequiredIdentifier(resourceID, "target resource id")
	if err != nil {
		return Target{}, err
	}
	return Target{
		resourceType: resourceType,
		resourceID:   resourceID,
	}, nil
}

func (target Target) ResourceType() string { return target.resourceType }
func (target Target) ResourceID() string   { return target.resourceID }

func (target Target) valid() bool {
	return strings.TrimSpace(target.resourceType) != "" && strings.TrimSpace(target.resourceID) != ""
}

func normalizeRequiredIdentifier(value, label string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%w: %s is required", ErrInvalidArgument, label)
	}
	if len(value) > 256 {
		return "", fmt.Errorf("%w: %s exceeds 256 characters", ErrInvalidArgument, label)
	}
	return value, nil
}

func normalizeOptionalIdentifier(value, label string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) > 256 {
		return "", fmt.Errorf("%w: %s exceeds 256 characters", ErrInvalidArgument, label)
	}
	return value, nil
}
