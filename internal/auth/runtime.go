package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/yoyo-kid/agent-action-control/internal/application"
)

var (
	ErrCredentialMissing = errors.New("runtime credential is missing")
	ErrCredentialInvalid = errors.New("runtime credential is invalid")
)

// RuntimeAuthenticator exchanges an opaque credential for trusted runtime
// context. HTTP parsing stays in transport; credential verification remains a
// replaceable adapter outside the domain.
type RuntimeAuthenticator interface {
	Authenticate(context.Context, string) (application.AuthenticatedRuntime, error)
}

// StaticRuntimeAuthenticator is the M1 development credential adapter.
// Production deployments can replace it without changing the decision use case.
type StaticRuntimeAuthenticator struct {
	runtimesByToken map[string]string
}

func NewStaticRuntimeAuthenticator(
	runtimesByToken map[string]string,
) (*StaticRuntimeAuthenticator, error) {
	if len(runtimesByToken) == 0 {
		return nil, fmt.Errorf("%w: at least one runtime credential is required", application.ErrInvalidInput)
	}
	values := make(map[string]string, len(runtimesByToken))
	for token, runtimeID := range runtimesByToken {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("%w: runtime credential cannot be empty", application.ErrInvalidInput)
		}
		runtime, err := application.NewAuthenticatedRuntime(runtimeID)
		if err != nil {
			return nil, err
		}
		values[token] = runtime.RuntimeID()
	}
	return &StaticRuntimeAuthenticator{runtimesByToken: values}, nil
}

func (authenticator *StaticRuntimeAuthenticator) Authenticate(
	_ context.Context,
	credential string,
) (application.AuthenticatedRuntime, error) {
	credential = strings.TrimSpace(credential)
	if credential == "" {
		return application.AuthenticatedRuntime{}, ErrCredentialMissing
	}
	if authenticator == nil {
		return application.AuthenticatedRuntime{}, ErrCredentialInvalid
	}
	runtimeID, ok := authenticator.runtimesByToken[credential]
	if !ok {
		return application.AuthenticatedRuntime{}, ErrCredentialInvalid
	}
	return application.NewAuthenticatedRuntime(runtimeID)
}
