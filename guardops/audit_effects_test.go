package guardops

import (
	"encoding/json"
	"strings"
	"testing"
)

const auditFailureComment = "bead-audit-result\n\n```json\n{\"outcome\":\"failed\",\"materialVersion\":\"original-material\",\"planVersion\":null,\"repository\":\"origin/repo\",\"reviewedSha\":\"pinned-sha\",\"scope\":\"bead\",\"findings\":[\"Reviewer failed λ `command  --exact`\\n\"]}\n```\n\nExplanatory result, no successful validation."

func auditFailureWire(t *testing.T, body string) []byte {
	t.Helper()
	return jsonReplace(t, jsonWire(t, wireRequest()), `"kind":"release"`, `"kind":"audit-comment","comment":`+string(jsonWire(t, body)))
}

func TestAuditFailureCommentExactOpaqueWireAndDistinctDigest(t *testing.T) {
	for _, outcome := range []string{"failed", "partial"} {
		t.Run(outcome, func(t *testing.T) {
			body := strings.Replace(auditFailureComment, `"outcome":"failed"`, `"outcome":"`+outcome+`"`, 1)
			r, err := DecodeRequest(auditFailureWire(t, body))
			if err != nil || r.Effect.Comment != body {
				t.Fatalf("exact explanatory comment refused/changed: %v", err)
			}
			changed := r
			changed.Effect.Comment += " "
			if Digest(r) == Digest(changed) || Digest(r) == Digest(wireRequest()) || Digest(wireRequest()) != requestVector {
				t.Fatal("failure-comment exact bytes/kind identity or old digest lost")
			}
			changed.Effect.Kind = "release-with-comment"
			if Digest(r) == Digest(changed) {
				t.Fatal("audit comment digest aliases lifecycle comment")
			}
		})
	}
}

func TestAuditFailureCommentRejectsSuccessAndAmbiguousEnvelope(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"success", strings.Replace(auditFailureComment, `"outcome":"failed"`, `"outcome":"success"`, 1)},
		{"skipped", strings.Replace(auditFailureComment, `"outcome":"failed"`, `"outcome":"skipped"`, 1)},
		{"ordinary", "human note"},
		{"wrong marker", strings.Replace(auditFailureComment, "bead-audit-result", "bead-audit-failure", 1)},
		{"second fence", auditFailureComment + "\n```json\n{}\n```"},
		{"extra field", strings.Replace(auditFailureComment, `"outcome":"failed"`, `"outcome":"failed","receipt":true`, 1)},
		{"duplicate", strings.Replace(auditFailureComment, `"outcome":"failed"`, `"outcome":"failed","outcome":"failed"`, 1)},
		{"alias", strings.Replace(auditFailureComment, `"outcome":"failed"`, `"Outcome":"failed"`, 1)},
		{"bad findings", strings.Replace(auditFailureComment, `"findings":[`, `"findings":[1,`, 1)},
		{"null finding", strings.Replace(auditFailureComment, `"findings":[`, `"findings":[null,`, 1)},
		{"blank identity", strings.Replace(auditFailureComment, "pinned-sha", " ", 1)},
		{"oversized text", auditFailureComment + strings.Repeat("λ", 32768)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRequest(auditFailureWire(t, tc.body))
			requireInvalid(t, err)
		})
	}
	for _, field := range []string{"receiptRecordsJson", "acceptedDescription", "outcome"} {
		t.Run("extra wire/"+field, func(t *testing.T) {
			raw := auditFailureWire(t, auditFailureComment)
			_, err := DecodeRequest(jsonReplace(t, raw, `"kind":"audit-comment"`, `"kind":"audit-comment","`+field+`":"success"`))
			requireInvalid(t, err)
		})
	}
}

func auditEffectWire(t *testing.T, kind string, edit func(map[string]any)) []byte {
	t.Helper()
	r := wireRequest()
	receipt := map[string]any{"repository": "origin/repo", "reviewedSha": "reviewed-original-sha", "materialVersion": "accepted-material", "planVersion": nil, "scope": "bead", "outcome": "success", "recordedAt": "2026-10-10T12:34:56.000Z"}
	ns := strings.Repeat("a", 64)
	raw := string(jsonWire(t, map[string]any{"version": 1, "namespace": ns, "value": receipt}))
	records := string(jsonWire(t, []any{map[string]any{"key": clearanceRecordKey(ns, raw), "value": raw}}))
	e := map[string]any{"kind": kind, "receiptRecordsJson": records}
	if kind == "archive-replace" {
		e["archiveComment"] = "bead-audit-archive\n2026-10-10T12:34:56.000Z\n\n exact original λ\n "
		e["acceptedDescription"] = " accepted exact `cmd  --flag` λ\n "
	}
	if kind == "add-human-hold" {
		delete(e, "receiptRecordsJson")
		e["materialVersion"], e["clearanceNamespace"], e["clearanceContentDigest"] = "new-material", ns, strings.Repeat("b", 64)
		c := map[string]any{"clearedBy": "identified human", "clearedAt": "2026-10-10T12:00:00Z", "materialVersion": "old-material"}
		v := map[string]any{"kind": "bounded-unworkable-hold", "operationId": r.OperationID, "guardGeneration": r.Expected.Generation, "originalToken": r.Expected.Token, "actor": r.Actor, "heldAt": "2026-10-10T12:34:56Z", "materialVersion": e["materialVersion"], "clearanceNamespace": ns, "clearanceContentDigest": e["clearanceContentDigest"], "baseline": "unknown-legacy", "historyComplete": false, "clearance": c}
		hns := strings.Repeat("c", 64)
		hraw := string(jsonWire(t, map[string]any{"version": 1, "namespace": hns, "value": v}))
		e["holdRecordKey"], e["holdRecordValue"] = clearanceRecordKey(hns, hraw), hraw
	}
	if edit != nil {
		edit(e)
	}
	var object map[string]any
	_ = json.Unmarshal(jsonWire(t, r), &object)
	object["effect"] = e
	return jsonWire(t, object)
}

func TestAuditEffectsAcceptExactWireAndDistinctDigest(t *testing.T) {
	for _, kind := range []string{"archive-replace", "validate", "add-human-hold"} {
		t.Run(kind, func(t *testing.T) {
			raw := auditEffectWire(t, kind, nil)
			r, err := DecodeRequest(raw)
			if err != nil {
				t.Fatal(err)
			}
			var before, after map[string]any
			_ = json.Unmarshal(raw, &before)
			_ = json.Unmarshal(jsonWire(t, r), &after)
			if string(jsonWire(t, before["effect"])) != string(jsonWire(t, after["effect"])) {
				t.Fatal("opaque audit bytes changed")
			}
			if Digest(r) == requestVector || Digest(wireRequest()) != requestVector {
				t.Fatal("legacy/new digest identity lost")
			}
			changed := jsonReplace(t, raw, `"contextJson":"`, `"contextJson":" `)
			other, err := DecodeRequest(changed)
			if err != nil || Digest(r) == Digest(other) {
				t.Fatalf("context omitted from digest: %v", err)
			}
		})
	}
}

func TestAuditEffectsRefuseWrongShapeAndUnboundedText(t *testing.T) {
	for _, kind := range []string{"archive-replace", "validate", "add-human-hold"} {
		for _, change := range []string{"extra", "missing", "legacy-field"} {
			t.Run(kind+"/"+change, func(t *testing.T) {
				_, err := DecodeRequest(auditEffectWire(t, kind, func(e map[string]any) {
					if change == "extra" {
						e["force"] = true
					}
					if change == "legacy-field" {
						e["comment"] = "unrelated"
					}
					if change == "missing" {
						if kind == "add-human-hold" {
							delete(e, "holdRecordValue")
						} else {
							delete(e, "receiptRecordsJson")
						}
					}
				}))
				requireInvalid(t, err)
			})
		}
	}
	for _, body := range []string{"", " \n", strings.Repeat("λ", 32768), "not-an-archive"} {
		_, err := DecodeRequest(auditEffectWire(t, "archive-replace", func(e map[string]any) { e["archiveComment"] = body }))
		requireInvalid(t, err)
	}
}

func TestAuditReceiptRecordsRequireImmutableSuccessfulExactRecords(t *testing.T) {
	for _, change := range []string{"none", "bad-key", "failed", "extra", "duplicate", "null-plan", "malformed", "oversize"} {
		t.Run(change, func(t *testing.T) {
			_, err := DecodeRequest(auditEffectWire(t, "validate", func(e map[string]any) {
				var records []map[string]string
				_ = json.Unmarshal([]byte(e["receiptRecordsJson"].(string)), &records)
				var envelope map[string]any
				_ = json.Unmarshal([]byte(records[0]["value"]), &envelope)
				value := envelope["value"].(map[string]any)
				switch change {
				case "none":
					records = nil
				case "bad-key":
					records[0]["key"] += "0"
				case "failed":
					value["outcome"] = "failed"
				case "extra":
					value["authorRationale"] = "hidden"
				case "duplicate":
					records = append(records, records[0])
				case "null-plan":
					value["scope"] = "plan"
				case "malformed":
					value["recordedAt"] = "2026-02-30T12:00:00Z"
				case "oversize":
					value["repository"] = strings.Repeat("x", 65536)
				}
				if len(records) > 0 && change != "bad-key" {
					raw := string(jsonWire(t, envelope))
					records[0]["value"] = raw
					records[0]["key"] = clearanceRecordKey(envelope["namespace"].(string), raw)
				}
				e["receiptRecordsJson"] = string(jsonWire(t, records))
			}))
			requireInvalid(t, err)
		})
	}
}

func TestAuditHoldEvidenceRejectsSameMaterialAndFabricatedCompleteHistory(t *testing.T) {
	for _, change := range []string{"same-material", "complete", "actor", "token", "operation", "namespace", "digest", "unidentified"} {
		t.Run(change, func(t *testing.T) {
			_, err := DecodeRequest(auditEffectWire(t, "add-human-hold", func(e map[string]any) {
				var envelope map[string]any
				_ = json.Unmarshal([]byte(e["holdRecordValue"].(string)), &envelope)
				v := envelope["value"].(map[string]any)
				switch change {
				case "same-material":
					v["clearance"].(map[string]any)["materialVersion"] = v["materialVersion"]
				case "complete":
					v["historyComplete"] = true
				case "actor":
					v["actor"] = "another"
				case "token":
					v["originalToken"] = "replacement capture"
				case "operation":
					v["operationId"] = "other operation"
				case "namespace":
					v["clearanceNamespace"] = strings.Repeat("d", 64)
				case "digest":
					v["clearanceContentDigest"] = strings.Repeat("d", 64)
				case "unidentified":
					v["clearance"].(map[string]any)["clearedBy"] = ""
				}
				raw := string(jsonWire(t, envelope))
				e["holdRecordValue"] = raw
				e["holdRecordKey"] = clearanceRecordKey(envelope["namespace"].(string), raw)
			}))
			requireInvalid(t, err)
		})
	}
}
