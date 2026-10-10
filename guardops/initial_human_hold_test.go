package guardops

import (
	"encoding/json"
	"strings"
	"testing"
)

func initialHoldWire(t *testing.T) []byte {
	t.Helper()
	r := wireRequest()
	ns, bns := strings.Repeat("a", 64), RecordValueDigest("beads.guard.birth.v1\x00"+r.Expected.IssueID)
	birth := map[string]any{"recordKey": "krewe.audit.v1." + bns + "." + strings.Repeat("b", 64), "recordValueDigest": strings.Repeat("b", 64), "incarnation": strings.Repeat("c", 64), "createdEventId": "b98d4dca-2549-56b8-b0a0-92b797ed3379"}
	value := map[string]any{"kind": "initial-unworkable-hold", "operationId": r.OperationID, "guardGeneration": r.Expected.Generation, "originalToken": r.Expected.Token, "actor": r.Actor, "heldAt": "2026-10-10T12:34:56Z", "materialVersion": "first-material", "clearanceNamespace": ns, "clearanceContentDigest": RecordValueDigest("[]"), "baseline": "native-create-birth", "scope": "native-incarnation-since-create", "historyComplete": false, "clearance": nil, "birth": birth}
	raw := string(jsonWire(t, map[string]any{"version": 1, "namespace": strings.Repeat("d", 64), "value": value}))
	effect := map[string]any{"kind": "add-initial-human-hold", "materialVersion": "first-material", "clearanceNamespace": ns, "clearanceContentDigest": RecordValueDigest("[]"), "holdRecordKey": clearanceRecordKey(strings.Repeat("d", 64), raw), "holdRecordValue": raw, "birthRecordKey": birth["recordKey"], "birthRecordValueDigest": birth["recordValueDigest"]}
	var object map[string]any
	if err := json.Unmarshal(jsonWire(t, r), &object); err != nil {
		t.Fatal(err)
	}
	object["effect"] = effect
	return jsonWire(t, object)
}
func TestInitialHumanHoldAdditiveStrictWire(t *testing.T) {
	raw := initialHoldWire(t)
	r, err := DecodeRequest(raw)
	if err != nil {
		t.Fatalf("genuine prospective first-hold request refused: %v", err)
	}
	if r.Effect.Kind != "add-initial-human-hold" || Digest(r) == Digest(wireRequest()) || Digest(wireRequest()) != requestVector {
		t.Fatal("new effect aliases or changes old release digest")
	}
	for _, field := range []string{"materialVersion", "clearanceNamespace", "clearanceContentDigest", "holdRecordKey", "holdRecordValue", "birthRecordKey", "birthRecordValueDigest"} {
		t.Run("digest/"+field, func(t *testing.T) {
			var obj map[string]any
			_ = json.Unmarshal(raw, &obj)
			effect := obj["effect"].(map[string]any)
			effect[field] = effect[field].(string) + " "
			var changed Request
			_ = json.Unmarshal(jsonWire(t, obj), &changed)
			if Digest(changed) == Digest(r) {
				t.Fatal("exact field missing from digest")
			}
		})
	}
}
func TestInitialHumanHoldRejectsUnknownUnusedAndContradictoryEvidence(t *testing.T) {
	raw := initialHoldWire(t)
	for _, tc := range []struct{ name, old, next string }{
		{"history complete", `\"historyComplete\":false`, `\"historyComplete\":true`},
		{"legacy baseline", `native-create-birth`, `unknown-legacy`},
		{"wrong scope", `native-incarnation-since-create`, `complete-history`},
		{"non-null clearance", `\"clearance\":null`, `\"clearance\":{}`},
		{"blank actor", `\"actor\":\"sol-d\"`, `\"actor\":\" \"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := strings.ReplaceAll(string(raw), tc.old, tc.next)
			if changed == string(raw) {
				t.Fatal("test did not modify wire")
			}
			_, err := DecodeRequest([]byte(changed))
			requireInvalid(t, err)
		})
	}
	for _, key := range []string{"comment", "receiptRecordsJson", "historyValue"} {
		t.Run("unused/"+key, func(t *testing.T) {
			_, err := DecodeRequest(jsonReplace(t, raw, `"kind":"add-initial-human-hold"`, `"kind":"add-initial-human-hold","`+key+`":"unused"`))
			requireInvalid(t, err)
		})
	}
}
