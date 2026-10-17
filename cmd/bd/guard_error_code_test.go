package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/steveyegge/beads/guardops"
)

// Exercise real RunE framing without root initialization, storage or a server.
// A valid request supplies identity; malformed input cannot fabricate one.
func TestGuardErrorCodeUnavailableCommandIsBoundAndDoesNotWrite(t *testing.T) {
	oldStore := store
	store = nil
	t.Cleanup(func() { store = oldStore })
	r := guardops.Request{Protocol: guardops.Protocol, OperationID: "local-diagnostic", Actor: "local-test", ContextJSON: "{}",
		Expected: guardops.Snapshot{Protocol: guardops.Protocol, IssueID: "test-1", Database: "test", Branch: "main", Head: "head", Root: "root", Generation: "generation", Token: "token", StateJSON: "opaque"}, Effect: guardops.Effect{Kind: "release"}}
	for _, name := range []string{"apply", "lookup", "lookup-explanation"} {
		t.Run(name, func(t *testing.T) {
			command, _, err := guardCmd.Find([]string{name})
			if err != nil {
				t.Fatal(err)
			}
			var wire any = r
			protocol, id, digest := guardops.Protocol, r.OperationID, guardops.Digest(r)
			outcome := "refused"
			if name != "apply" {
				outcome = "unknown"
				if name == "lookup-explanation" {
					protocol = guardops.ExplanationProtocol
					id = guardops.ExplanationOperationID(r.OperationID)
				}
				wire = map[string]string{"protocol": protocol, "operationId": id, "requestDigest": digest}
			}
			raw, _ := json.Marshal(wire)
			oldFlag, _ := command.Flags().GetString("request-json")
			if err := command.Flags().Set("request-json", "-"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = command.Flags().Set("request-json", oldFlag); command.SetIn(nil) })
			command.SetIn(strings.NewReader(string(raw)))
			before := commandDidWrite.Load()
			out := captureStdout(t, func() error { return command.RunE(command, nil) })
			var result map[string]any
			if err := json.Unmarshal([]byte(out), &result); err != nil {
				t.Fatal(err)
			}
			if len(result) != 5 || result["protocol"] != protocol || result["operationId"] != id || result["requestDigest"] != digest || result["outcome"] != outcome || result["errorCode"] != string(guardops.CodeCapabilityUnavailable) {
				t.Fatalf("unbound refusal: %s", out)
			}
			if commandDidWrite.Load() != before {
				t.Fatal("capability refusal asserted a write")
			}
			command.SetIn(strings.NewReader(`{"operationId":"PRIVATE_UNVALIDATED"}`))
			var malformedErr error
			out = captureStdout(t, func() error { malformedErr = command.RunE(command, nil); return nil })
			if malformedErr == nil || out != "" {
				t.Fatalf("malformed framing acquired identity: %q %v", out, malformedErr)
			}
		})
	}
}
