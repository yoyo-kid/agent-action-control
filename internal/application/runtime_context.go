package application

import (
	"fmt"
	"strings"
)

// AuthenticatedRuntime is trusted context supplied by the authentication
// adapter. Caller-provided JSON cannot construct or override this identity.
type AuthenticatedRuntime struct {
	runtimeID string
}

func NewAuthenticatedRuntime(runtimeID string) (AuthenticatedRuntime, error) {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" {
		return AuthenticatedRuntime{}, fmt.Errorf("%w: runtime id is required", ErrInvalidInput)
	}
	if len(runtimeID) > 256 {
		return AuthenticatedRuntime{}, fmt.Errorf("%w: runtime id exceeds 256 characters", ErrInvalidInput)
	}
	return AuthenticatedRuntime{runtimeID: runtimeID}, nil
}

func (runtime AuthenticatedRuntime) RuntimeID() string { return runtime.runtimeID }
