package guardops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func clearanceRecordKey(namespace, raw string) string {
	hash := sha256.Sum256([]byte(raw))
	return "krewe.audit.v1." + namespace + "." + hex.EncodeToString(hash[:])
}

func clearHoldWire(t *testing.T, edit func(map[string]any, map[string]any, map[string]any)) []byte {
	t.Helper()
	r := wireRequest()
	clearance := map[string]any{"clearedBy": r.Actor, "clearedAt": "2026-10-10T12:34:56.123456789Z", "materialVersion": " exact-material λ "}
	history := map[string]any{"kind": "identified-clearance", "operationId": r.OperationID, "guardGeneration": r.Expected.Generation, "originalToken": r.Expected.Token, "baseline": "unknown-legacy", "historyComplete": false, "clearance": clearance}
	effect := map[string]any{"kind": "clear-human-hold"}
	if edit != nil {
		edit(clearance, history, effect)
	}
	clearNamespace, historyNamespace := strings.Repeat("a", 64), strings.Repeat("b", 64)
	clearRaw := string(jsonWire(t, map[string]any{"version": 1, "namespace": clearNamespace, "value": clearance}))
	historyRaw := string(jsonWire(t, map[string]any{"version": 1, "namespace": historyNamespace, "value": history}))
	for key, value := range map[string]string{"clearanceKey": clearanceRecordKey(clearNamespace, clearRaw), "clearanceValue": clearRaw, "historyKey": clearanceRecordKey(historyNamespace, historyRaw), "historyValue": historyRaw} {
		if _, set := effect[key]; !set {
			effect[key] = value
		}
	}
	var request map[string]any
	if err := json.Unmarshal(jsonWire(t, r), &request); err != nil {
		t.Fatal(err)
	}
	request["effect"] = effect
	return jsonWire(t, request)
}

func TestClearHumanHoldWireAcceptsExactProspectiveEvidence(t *testing.T) {
	raw := clearHoldWire(t, nil)
	r, err := DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	if err := json.Unmarshal(raw, &before); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(jsonWire(t, r), &after); err != nil {
		t.Fatal(err)
	}
	if string(before["effect"]) != string(after["effect"]) {
		// Object member order is immaterial, but every opaque string is exact.
		var want, got map[string]any
		_ = json.Unmarshal(before["effect"], &want)
		_ = json.Unmarshal(after["effect"], &got)
		for key, value := range want {
			if got[key] != value {
				t.Fatalf("effect field %s changed: %#v != %#v", key, got[key], value)
			}
		}
	}
	// Independent Python hashlib / big-endian uint64 UTF8 lengths.
	if Digest(r) != "dca2ac87c86680d7dc9ec66d8f6fd50c22ba035853ee1cf17003c78ae96f6857" {
		t.Fatalf("clearance tuple digest changed: %s", Digest(r))
	}
	if Digest(wireRequest()) != requestVector || Digest(r) == requestVector {
		t.Fatal("legacy or new effect identity lost")
	}
	changed, err := DecodeRequest(clearHoldWire(t, func(clearance, history, effect map[string]any) { clearance["materialVersion"] = "exact-material λ" }))
	if err != nil || Digest(changed) == Digest(r) {
		t.Fatalf("exact record bytes lost from digest: %v", err)
	}
}

func TestClearHumanHoldWireRefusesUnidentifiedOrCompleteHistory(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any, map[string]any, map[string]any)
	}{
		{"actor mismatch", func(c, h, e map[string]any) { c["clearedBy"] = "other" }},
		{"missing actor", func(c, h, e map[string]any) { delete(c, "clearedBy") }},
		{"noncanonical timezone", func(c, h, e map[string]any) { c["clearedAt"] = "2026-10-10T12:34:56+00:00" }},
		{"noncanonical fraction", func(c, h, e map[string]any) { c["clearedAt"] = "2026-10-10T12:34:56.100Z" }},
		{"invalid date", func(c, h, e map[string]any) { c["clearedAt"] = "2026-02-30T12:34:56Z" }},
		{"blank material", func(c, h, e map[string]any) { c["materialVersion"] = " \n" }},
		{"material byte cap", func(c, h, e map[string]any) { c["materialVersion"] = strings.Repeat("λ", 129) }},
		{"unknown clearance field", func(c, h, e map[string]any) { c["wholeHistory"] = true }},
		{"operation mismatch", func(c, h, e map[string]any) { h["operationId"] = "other" }},
		{"generation mismatch", func(c, h, e map[string]any) { h["guardGeneration"] = "other" }},
		{"token mismatch", func(c, h, e map[string]any) { h["originalToken"] = "other" }},
		{"history kind", func(c, h, e map[string]any) { h["kind"] = "no-prior-clearance" }},
		{"legacy known", func(c, h, e map[string]any) { h["baseline"] = "known" }},
		{"complete history", func(c, h, e map[string]any) { h["historyComplete"] = true }},
		{"null completeness", func(c, h, e map[string]any) { h["historyComplete"] = nil }},
		{"missing completeness", func(c, h, e map[string]any) { delete(h, "historyComplete") }},
		{"different linked clearance", func(c, h, e map[string]any) { h["clearance"] = map[string]any{"clearedBy": "other"} }},
		{"unknown history field", func(c, h, e map[string]any) { h["enrolled"] = true }},
		{"caller kv prefix", func(c, h, e map[string]any) { e["clearanceKey"] = "kv.krewe.audit.v1.bad" }},
		{"wrong key hash", func(c, h, e map[string]any) {
			e["historyKey"] = "krewe.audit.v1." + strings.Repeat("b", 64) + "." + strings.Repeat("c", 64)
		}},
		{"null opaque record", func(c, h, e map[string]any) { e["historyValue"] = nil }},
		{"unknown effect", func(c, h, e map[string]any) { e["force"] = true }},
	} {
		t.Run(tc.name, func(t *testing.T) { _, err := DecodeRequest(clearHoldWire(t, tc.edit)); requireInvalid(t, err) })
	}
}

func TestClearHumanHoldWireRefusesAmbiguousRecords(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"duplicate", `{"version":1,"version":1,"namespace":"` + strings.Repeat("a", 64) + `","value":{}}`},
		{"unpaired escape", `{"version":1,"namespace":"` + strings.Repeat("a", 64) + `","value":{"clearedBy":"\ud800"}}`},
		{"oversized", strings.Repeat("x", (64<<10)+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRequest(clearHoldWire(t, func(c, h, e map[string]any) {
				e["clearanceValue"] = tc.raw
				e["clearanceKey"] = clearanceRecordKey(strings.Repeat("a", 64), tc.raw)
			}))
			requireInvalid(t, err)
		})
	}
}

func TestClearHumanHoldWireRequiresDistinctHashedNamespacesAndExactShape(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"missing key", func(e map[string]any) { delete(e, "clearanceKey") }},
		{"wrong record type", func(e map[string]any) { e["historyValue"] = 1 }},
		{"same namespace", func(e map[string]any) {
			raw := strings.ReplaceAll(e["historyValue"].(string), strings.Repeat("b", 64), strings.Repeat("a", 64))
			e["historyValue"] = raw
			e["historyKey"] = clearanceRecordKey(strings.Repeat("a", 64), raw)
		}},
		{"uppercase namespace", func(e map[string]any) {
			raw := strings.ReplaceAll(e["clearanceValue"].(string), strings.Repeat("a", 64), strings.Repeat("A", 64))
			e["clearanceValue"] = raw
			e["clearanceKey"] = clearanceRecordKey(strings.Repeat("A", 64), raw)
		}},
		{"wrong version", func(e map[string]any) {
			raw := strings.Replace(e["clearanceValue"].(string), `"version":1`, `"version":2`, 1)
			e["clearanceValue"] = raw
			e["clearanceKey"] = clearanceRecordKey(strings.Repeat("a", 64), raw)
		}},
		{"envelope extra field", func(e map[string]any) {
			raw := strings.Replace(e["clearanceValue"].(string), `"version":1`, `"version":1,"force":true`, 1)
			e["clearanceValue"] = raw
			e["clearanceKey"] = clearanceRecordKey(strings.Repeat("a", 64), raw)
		}},
		{"comment forbidden", func(e map[string]any) { e["comment"] = "unrelated release" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var request map[string]any
			_ = json.Unmarshal(clearHoldWire(t, nil), &request)
			tc.edit(request["effect"].(map[string]any))
			_, err := DecodeRequest(jsonWire(t, request))
			requireInvalid(t, err)
		})
	}
}

func TestClearHumanHoldTypedValidationBoundsActorAndPreservesOpaqueStrings(t *testing.T) {
	r, err := DecodeRequest(clearHoldWire(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []struct {
		name, actor string
		valid       bool
	}{
		{"exact byte boundary", strings.Repeat("λ", 127) + "x", true},
		{"beyond byte boundary", strings.Repeat("λ", 128), false},
	} {
		t.Run(actor.name, func(t *testing.T) {
			copy := r
			copy.Actor = actor.actor
			copy.Effect.ClearanceValue = strings.ReplaceAll(copy.Effect.ClearanceValue, r.Actor, actor.actor)
			copy.Effect.HistoryValue = strings.ReplaceAll(copy.Effect.HistoryValue, r.Actor, actor.actor)
			copy.Effect.ClearanceKey = clearanceRecordKey(strings.Repeat("a", 64), copy.Effect.ClearanceValue)
			copy.Effect.HistoryKey = clearanceRecordKey(strings.Repeat("b", 64), copy.Effect.HistoryValue)
			err := ValidateRequest(copy)
			if actor.valid && err != nil {
				t.Fatal(err)
			} else if !actor.valid {
				requireInvalid(t, err)
			}
		})
	}
	invalid := r
	invalid.Effect.ClearanceValue += string([]byte{0xff})
	requireInvalid(t, ValidateRequest(invalid))
	for _, kind := range []string{"release", "release-with-comment"} {
		invalid := r
		invalid.Effect.Kind = kind
		invalid.Effect.Comment = "body"
		requireInvalid(t, ValidateRequest(invalid))
	}
	// Opaque record whitespace changes the payload hash and effect digest but
	// does not change the identified clearance or grant complete history.
	spaced := r
	spaced.Effect.ClearanceValue = " \n" + r.Effect.ClearanceValue + "\t "
	spaced.Effect.ClearanceKey = clearanceRecordKey(strings.Repeat("a", 64), spaced.Effect.ClearanceValue)
	if err := ValidateRequest(spaced); err != nil || Digest(spaced) == Digest(r) {
		t.Fatalf("opaque bytes normalized: %v", err)
	}
}
