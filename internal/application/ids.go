package application

import "fmt"

// IDKind identifies an application-owned record whose identifier is generated
// during decision composition or commit preparation.
type IDKind string

const (
	IDDecision     IDKind = "DECISION"
	IDPolicyEffect IDKind = "POLICY_EFFECT"
)

func (kind IDKind) Valid() bool {
	switch kind {
	case IDDecision, IDPolicyEffect:
		return true
	default:
		return false
	}
}

func ParseIDKind(value string) (IDKind, error) {
	kind := IDKind(value)
	if !kind.Valid() {
		return "", fmt.Errorf("%w: unsupported id kind %q", ErrInvalidInput, value)
	}
	return kind, nil
}

// IDGenerator produces opaque identifiers. The application selects the kind;
// adapters own randomness, persistence-independent formatting, and entropy.
type IDGenerator interface {
	NewID(kind IDKind) (string, error)
}
