package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/yoyo-kid/agent-action-control/internal/application"
)

func TestStaticRuntimeAuthenticator(t *testing.T) {
	authenticator, err := NewStaticRuntimeAuthenticator(map[string]string{" token-1 ": " runtime-1 "})
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}
	runtime, err := authenticator.Authenticate(context.Background(), " token-1 ")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if runtime.RuntimeID() != "runtime-1" {
		t.Fatalf("runtime ID = %q", runtime.RuntimeID())
	}
	for _, credential := range []string{"", "wrong"} {
		_, err := authenticator.Authenticate(context.Background(), credential)
		if !errors.Is(err, ErrCredentialMissing) && !errors.Is(err, ErrCredentialInvalid) {
			t.Fatalf("credential %q returned %v", credential, err)
		}
	}
}

func TestStaticRuntimeAuthenticatorRejectsInvalidConfiguration(t *testing.T) {
	tests := []map[string]string{
		nil,
		{"": "runtime-1"},
		{"token-1": ""},
	}
	for _, values := range tests {
		if _, err := NewStaticRuntimeAuthenticator(values); !errors.Is(err, application.ErrInvalidInput) {
			t.Fatalf("configuration %#v returned %v", values, err)
		}
	}
}
