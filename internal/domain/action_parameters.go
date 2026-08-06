package domain

import (
	"fmt"
	"sort"
	"strings"
)

// DestinationScope identifies whether a send remains inside a trusted boundary.
type DestinationScope string

const (
	DestinationInternal DestinationScope = "INTERNAL"
	DestinationExternal DestinationScope = "EXTERNAL"
)

func ParseDestinationScope(value string) (DestinationScope, error) {
	scope := DestinationScope(strings.ToUpper(strings.TrimSpace(value)))
	if scope != DestinationInternal && scope != DestinationExternal {
		return "", fmt.Errorf("%w: unsupported destination scope %q", ErrInvalidArgument, value)
	}
	return scope, nil
}

// ExternalSendParameters contains the normalized security facts for a send.
type ExternalSendParameters struct {
	destinationScope DestinationScope
	recipients       []string
}

func NewExternalSendParameters(scope DestinationScope, recipients []string) (ExternalSendParameters, error) {
	normalizedScope, err := ParseDestinationScope(string(scope))
	if err != nil {
		return ExternalSendParameters{}, err
	}
	normalized, err := normalizeStrings(recipients, 100, 320)
	if err != nil || len(normalized) == 0 {
		return ExternalSendParameters{}, fmt.Errorf("%w: at least one valid recipient is required", ErrInvalidArgument)
	}
	return ExternalSendParameters{destinationScope: normalizedScope, recipients: normalized}, nil
}

func (parameters ExternalSendParameters) ActionType() ActionType { return ActionExternalSend }
func (parameters ExternalSendParameters) DestinationScope() DestinationScope {
	return parameters.destinationScope
}
func (parameters ExternalSendParameters) Recipients() []string {
	return append([]string(nil), parameters.recipients...)
}
func (parameters ExternalSendParameters) validate() error {
	_, err := NewExternalSendParameters(parameters.destinationScope, parameters.recipients)
	return err
}
func (parameters ExternalSendParameters) clone() ActionParameters {
	parameters.recipients = append([]string(nil), parameters.recipients...)
	return parameters
}

// AccessScope is a canonical, policy-readable resource visibility token.
type AccessScope string

const (
	AccessPrivate   AccessScope = "PRIVATE"
	AccessShared    AccessScope = "SHARED"
	AccessWorkspace AccessScope = "WORKSPACE"
	AccessPublic    AccessScope = "PUBLIC"
)

func ParseAccessScope(value string) (AccessScope, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" || len(value) > 128 {
		return "", fmt.Errorf("%w: access scope is required", ErrInvalidArgument)
	}
	return AccessScope(value), nil
}

// UpdateResourceAccessParameters contains the normalized access transition.
type UpdateResourceAccessParameters struct {
	currentScope     AccessScope
	requestedScope   AccessScope
	targetPrincipals []Principal
}

func NewUpdateResourceAccessParameters(
	currentScope AccessScope,
	requestedScope AccessScope,
	targetPrincipals []Principal,
) (UpdateResourceAccessParameters, error) {
	normalizedCurrent, err := ParseAccessScope(string(currentScope))
	if err != nil {
		return UpdateResourceAccessParameters{}, err
	}
	normalizedRequested, err := ParseAccessScope(string(requestedScope))
	if err != nil {
		return UpdateResourceAccessParameters{}, err
	}
	if normalizedCurrent == normalizedRequested {
		return UpdateResourceAccessParameters{}, fmt.Errorf("%w: requested scope must change access", ErrInvalidArgument)
	}
	principals, err := normalizePrincipals(targetPrincipals)
	if err != nil {
		return UpdateResourceAccessParameters{}, err
	}
	if normalizedRequested == AccessShared && len(principals) == 0 {
		return UpdateResourceAccessParameters{}, fmt.Errorf("%w: SHARED scope requires target principals", ErrInvalidArgument)
	}
	return UpdateResourceAccessParameters{
		currentScope:     normalizedCurrent,
		requestedScope:   normalizedRequested,
		targetPrincipals: principals,
	}, nil
}

func (parameters UpdateResourceAccessParameters) ActionType() ActionType {
	return ActionUpdateResourceAccess
}
func (parameters UpdateResourceAccessParameters) CurrentScope() AccessScope {
	return parameters.currentScope
}
func (parameters UpdateResourceAccessParameters) RequestedScope() AccessScope {
	return parameters.requestedScope
}
func (parameters UpdateResourceAccessParameters) TargetPrincipals() []Principal {
	return append([]Principal(nil), parameters.targetPrincipals...)
}
func (parameters UpdateResourceAccessParameters) validate() error {
	_, err := NewUpdateResourceAccessParameters(
		parameters.currentScope,
		parameters.requestedScope,
		parameters.targetPrincipals,
	)
	return err
}
func (parameters UpdateResourceAccessParameters) clone() ActionParameters {
	parameters.targetPrincipals = append([]Principal(nil), parameters.targetPrincipals...)
	return parameters
}

// DeleteMode identifies the requested deletion semantics.
type DeleteMode string

const (
	DeleteSoft DeleteMode = "SOFT"
	DeleteHard DeleteMode = "HARD"
)

func ParseDeleteMode(value string) (DeleteMode, error) {
	mode := DeleteMode(strings.ToUpper(strings.TrimSpace(value)))
	if mode != DeleteSoft && mode != DeleteHard {
		return "", fmt.Errorf("%w: unsupported delete mode %q", ErrInvalidArgument, value)
	}
	return mode, nil
}

// DeleteParameters contains normalized deletion semantics.
type DeleteParameters struct {
	mode        DeleteMode
	recoverable bool
}

func NewDeleteParameters(mode DeleteMode, recoverable bool) (DeleteParameters, error) {
	normalizedMode, err := ParseDeleteMode(string(mode))
	if err != nil {
		return DeleteParameters{}, err
	}
	return DeleteParameters{mode: normalizedMode, recoverable: recoverable}, nil
}

func (parameters DeleteParameters) ActionType() ActionType { return ActionDelete }
func (parameters DeleteParameters) Mode() DeleteMode       { return parameters.mode }
func (parameters DeleteParameters) Recoverable() bool      { return parameters.recoverable }
func (parameters DeleteParameters) validate() error {
	_, err := NewDeleteParameters(parameters.mode, parameters.recoverable)
	return err
}
func (parameters DeleteParameters) clone() ActionParameters { return parameters }

func normalizeStrings(values []string, maximumItems, maximumLength int) ([]string, error) {
	if len(values) > maximumItems {
		return nil, fmt.Errorf("%w: too many values", ErrInvalidArgument)
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > maximumLength {
			return nil, fmt.Errorf("%w: invalid value", ErrInvalidArgument)
		}
		unique[value] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizePrincipals(values []Principal) ([]Principal, error) {
	if len(values) > 100 {
		return nil, fmt.Errorf("%w: too many target principals", ErrInvalidArgument)
	}
	unique := make(map[string]Principal, len(values))
	for _, principal := range values {
		if !principal.valid() {
			return nil, fmt.Errorf("%w: invalid target principal", ErrInvalidArgument)
		}
		unique[string(principal.Type())+"\x00"+principal.ID()] = principal
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Principal, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result, nil
}
