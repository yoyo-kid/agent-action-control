package main

import (
	"testing"

	"github.com/yoyo-kid/agent-action-control/internal/policy/embedded"
	ospreypolicy "github.com/yoyo-kid/agent-action-control/internal/policy/osprey"
)

func TestConfigurePolicyEvaluatorDefaultsToEmbedded(t *testing.T) {
	t.Setenv("ACTION_CONTROL_POLICY_EVALUATOR", "")
	evaluator, closeEvaluator, err := configurePolicyEvaluator()
	if err != nil {
		t.Fatalf("configure evaluator: %v", err)
	}
	if _, ok := evaluator.(embedded.Evaluator); !ok {
		t.Fatalf("evaluator = %T", evaluator)
	}
	if err := closeEvaluator(); err != nil {
		t.Fatalf("close evaluator: %v", err)
	}
}

func TestConfigurePolicyEvaluatorBuildsOspreyAdapter(t *testing.T) {
	t.Setenv("ACTION_CONTROL_POLICY_EVALUATOR", "osprey")
	t.Setenv("ACTION_CONTROL_OSPREY_ADDRESS", "localhost:19951")
	t.Setenv("ACTION_CONTROL_OSPREY_POLICY_VERSION", "bundle-v1")
	t.Setenv("ACTION_CONTROL_OSPREY_TIMEOUT", "750ms")
	evaluator, closeEvaluator, err := configurePolicyEvaluator()
	if err != nil {
		t.Fatalf("configure evaluator: %v", err)
	}
	if _, ok := evaluator.(*ospreypolicy.Evaluator); !ok {
		t.Fatalf("evaluator = %T", evaluator)
	}
	if err := closeEvaluator(); err != nil {
		t.Fatalf("close evaluator: %v", err)
	}
}

func TestConfigurePolicyEvaluatorRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		address string
		version string
		timeout string
	}{
		{name: "unknown evaluator", mode: "other"},
		{name: "missing address", mode: "osprey", version: "bundle-v1"},
		{name: "missing version", mode: "osprey", address: "localhost:19951"},
		{name: "invalid timeout", mode: "osprey", address: "localhost:19951", version: "bundle-v1", timeout: "soon"},
		{name: "nonpositive timeout", mode: "osprey", address: "localhost:19951", version: "bundle-v1", timeout: "0s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("ACTION_CONTROL_POLICY_EVALUATOR", test.mode)
			t.Setenv("ACTION_CONTROL_OSPREY_ADDRESS", test.address)
			t.Setenv("ACTION_CONTROL_OSPREY_POLICY_VERSION", test.version)
			t.Setenv("ACTION_CONTROL_OSPREY_TIMEOUT", test.timeout)
			if _, _, err := configurePolicyEvaluator(); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
