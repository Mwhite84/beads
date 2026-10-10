package main

import (
	"encoding/json"
	"errors"
	"testing"
)

// Exercise the existing front-door renderer on the real command tree. A
// managed-local proxy must refuse too: permission to spawn a provider does
// not supply a guarded storage role.
func TestGuardProxyFrontDoorRefusesEveryTopology(t *testing.T) {
	t.Setenv("BD_JSON_ENVELOPE", "")
	oldJSON := jsonOutput
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = oldJSON })

	topologies := []ProxyTopology{
		ProxyTopologyAny, ProxyTopologyManagedLocal, ProxyTopologyExternalTCP,
		ProxyTopologyExternalUnix, ProxyTopologyTeamServer, ProxyTopologyUnknown,
	}
	if got := len(guardCmd.Commands()); got != 4 {
		t.Fatalf("guard command count = %d, want capture/apply/lookup/initialize", got)
	}
	for _, command := range guardCmd.Commands() {
		for _, topology := range topologies {
			t.Run(command.Name()+"/"+string(topology), func(t *testing.T) {
				var refusal error
				out := captureStdout(t, func() error {
					refusal = validateProxyRegistryBeforeProvider(command, topology)
					return nil
				})
				var exit *exitError
				if !errors.As(refusal, &exit) || exit.Code != 1 {
					t.Fatalf("front-door result = %v, want exit 1", refusal)
				}
				var wire struct {
					Code    string             `json:"code"`
					Reason  ProxyRefusalReason `json:"reason"`
					Mutates *bool              `json:"mutates"`
				}
				if err := json.Unmarshal([]byte(out), &wire); err != nil {
					t.Fatalf("invalid refusal JSON %q: %v", out, err)
				}
				if wire.Code != "proxy.guard.unsupported" || wire.Reason != ProxyReasonUnimplemented || wire.Mutates == nil || *wire.Mutates {
					t.Fatalf("unexpected refusal contract: %s", out)
				}
			})
		}
	}
}

func TestGuardInitializationUsesExclusiveWorkspaceGate(t *testing.T) {
	for _, command := range guardCmd.Commands() {
		wantExclusive := command.Name() == "initialize"
		if got := commandNeedsExclusiveGate(command); got != wantExclusive {
			t.Errorf("%s exclusive = %v, want %v", command.CommandPath(), got, wantExclusive)
		}
	}
}
