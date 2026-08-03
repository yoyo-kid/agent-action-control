package domain

import (
	"fmt"
	"sort"
	"strings"
)

type AuthorizationEvidenceType string

const (
	EvidenceUserInstruction AuthorizationEvidenceType = "USER_INSTRUCTION"
	EvidenceDelegationGrant AuthorizationEvidenceType = "DELEGATION_GRANT"
	EvidenceSystemAssertion AuthorizationEvidenceType = "SYSTEM_ASSERTION"
)

func ParseAuthorizationEvidenceType(value string) (AuthorizationEvidenceType, error) {
	typ := AuthorizationEvidenceType(strings.ToUpper(strings.TrimSpace(value)))
	switch typ {
	case EvidenceUserInstruction, EvidenceDelegationGrant, EvidenceSystemAssertion:
		return typ, nil
	default:
		return "", fmt.Errorf("%w: unsupported authorization evidence type %q", ErrInvalidArgument, value)
	}
}

// AuthorizationScope binds evidence to one action and its sensitive dimension.
type AuthorizationScope struct {
	actionType       ActionType
	destinationScope DestinationScope
	requestedScope   AccessScope
	deleteMode       DeleteMode
}

func NewAuthorizationScope(
	actionType ActionType,
	destinationScope DestinationScope,
	requestedScope AccessScope,
	deleteMode DeleteMode,
) (AuthorizationScope, error) {
	if !actionType.Valid() {
		return AuthorizationScope{}, ErrInvalidActionType
	}
	scope := AuthorizationScope{actionType: actionType}
	switch actionType {
	case ActionExternalSend:
		normalized, err := ParseDestinationScope(string(destinationScope))
		if err != nil {
			return AuthorizationScope{}, fmt.Errorf("%w: destination scope is required", ErrInvalidArgument)
		}
		scope.destinationScope = normalized
	case ActionUpdateResourceAccess:
		normalized, err := ParseAccessScope(string(requestedScope))
		if err != nil {
			return AuthorizationScope{}, fmt.Errorf("%w: requested scope is required", ErrInvalidArgument)
		}
		scope.requestedScope = normalized
	case ActionDelete:
		normalized, err := ParseDeleteMode(string(deleteMode))
		if err != nil {
			return AuthorizationScope{}, fmt.Errorf("%w: delete mode is required", ErrInvalidArgument)
		}
		scope.deleteMode = normalized
	}
	return scope, nil
}

func (scope AuthorizationScope) ActionType() ActionType             { return scope.actionType }
func (scope AuthorizationScope) DestinationScope() DestinationScope { return scope.destinationScope }
func (scope AuthorizationScope) RequestedScope() AccessScope        { return scope.requestedScope }
func (scope AuthorizationScope) DeleteMode() DeleteMode             { return scope.deleteMode }
func (scope AuthorizationScope) valid() bool {
	_, err := NewAuthorizationScope(scope.actionType, scope.destinationScope, scope.requestedScope, scope.deleteMode)
	return err == nil
}

// AuthorizationEvidence is a verifiable, scoped authorization reference.
type AuthorizationEvidence struct {
	typ      AuthorizationEvidenceType
	id       string
	issuedBy Principal
	scope    AuthorizationScope
}

func NewAuthorizationEvidence(
	typ AuthorizationEvidenceType,
	id string,
	issuedBy Principal,
	scope AuthorizationScope,
) (AuthorizationEvidence, error) {
	normalizedType, err := ParseAuthorizationEvidenceType(string(typ))
	if err != nil {
		return AuthorizationEvidence{}, err
	}
	id, err = normalizeRequiredIdentifier(id, "evidence id")
	if err != nil {
		return AuthorizationEvidence{}, err
	}
	if !issuedBy.valid() || !scope.valid() {
		return AuthorizationEvidence{}, fmt.Errorf("%w: invalid evidence issuer or scope", ErrInvalidArgument)
	}
	return AuthorizationEvidence{typ: normalizedType, id: id, issuedBy: issuedBy, scope: scope}, nil
}

func (evidence AuthorizationEvidence) Type() AuthorizationEvidenceType { return evidence.typ }
func (evidence AuthorizationEvidence) ID() string                      { return evidence.id }
func (evidence AuthorizationEvidence) IssuedBy() Principal             { return evidence.issuedBy }
func (evidence AuthorizationEvidence) Scope() AuthorizationScope       { return evidence.scope }
func (evidence AuthorizationEvidence) valid() bool {
	_, err := NewAuthorizationEvidence(evidence.typ, evidence.id, evidence.issuedBy, evidence.scope)
	return err == nil
}

func cloneAuthorizationEvidence(values []AuthorizationEvidence) []AuthorizationEvidence {
	return append([]AuthorizationEvidence(nil), values...)
}

func NormalizeAuthorizationEvidence(values []AuthorizationEvidence) ([]AuthorizationEvidence, error) {
	if len(values) > 100 {
		return nil, fmt.Errorf("%w: too much authorization evidence", ErrInvalidArgument)
	}
	unique := make(map[string]AuthorizationEvidence, len(values))
	for _, evidence := range values {
		if !evidence.valid() {
			return nil, fmt.Errorf("%w: invalid authorization evidence", ErrInvalidArgument)
		}
		key := string(evidence.Type()) + "\x00" + evidence.ID()
		if existing, ok := unique[key]; ok && existing != evidence {
			return nil, fmt.Errorf("%w: evidence id reused with conflicting facts", ErrInvalidArgument)
		}
		unique[key] = evidence
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]AuthorizationEvidence, 0, len(keys))
	for _, key := range keys {
		result = append(result, unique[key])
	}
	return result, nil
}
