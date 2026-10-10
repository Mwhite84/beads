package guardops

import (
	"encoding/json"
	"strings"
	"testing"
)

func explanationWireRequest(t *testing.T) ExplanationRequest {
	t.Helper()
	original, err := DecodeRequest(auditEffectWire(t, "validate", nil))
	if err != nil {
		t.Fatal(err)
	}
	original.ContextJSON = `{"repository":"origin/repo","reviewedSha":"reviewed-original-sha","scope":"bead","materialVersion":"accepted-material"}`
	body := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(auditFailureComment, `"outcome":"failed"`, `"outcome":"success"`), "original-material", "accepted-material"), "pinned-sha", "reviewed-original-sha")
	return ExplanationRequest{Protocol: ExplanationProtocol, OperationID: ExplanationOperationID(original.OperationID), OriginalRequest: original, Expected: original.Expected, Comment: body}
}
func TestExplanationStableDeliveryIdentityPreservesOriginalRequest(t *testing.T) {
	r := explanationWireRequest(t)
	decoded, err := DecodeExplanation(jsonWire(t, r))
	if err != nil || decoded != r {
		t.Fatalf("exact new request refused/changed: %v", err)
	}
	changed := r
	changed.Expected.Token += "fresh-permission"
	changed.Expected.StateJSON += " "
	if ExplanationDigest(changed) != ExplanationDigest(r) {
		t.Fatal("fresh permission became delivery identity")
	}
	changed = r
	changed.Comment += " "
	if ExplanationDigest(changed) == ExplanationDigest(r) {
		t.Fatal("exact comment bytes not bound")
	}
	changed = r
	changed.OriginalRequest.ContextJSON += " "
	if ExplanationDigest(changed) == ExplanationDigest(r) {
		t.Fatal("original opaque request bytes not bound")
	}
	if Digest(wireRequest()) != requestVector {
		t.Fatal("old digest changed")
	}
}
func TestExplanationStrictShapeAndBindings(t *testing.T) {
	r := explanationWireRequest(t)
	for _, tc := range []struct {
		name string
		edit func(*ExplanationRequest)
	}{
		{"wrong protocol", func(r *ExplanationRequest) { r.Protocol = Protocol }},
		{"arbitrary delivery id", func(r *ExplanationRequest) { r.OperationID = "body-dependent" }},
		{"cross issue", func(r *ExplanationRequest) { r.Expected.IssueID += "other" }},
		{"cross generation", func(r *ExplanationRequest) { r.Expected.Generation += "other" }},
		{"release original", func(r *ExplanationRequest) {
			r.OriginalRequest = wireRequest()
			r.OperationID = ExplanationOperationID(r.OriginalRequest.OperationID)
		}},
		{"failed success envelope", func(r *ExplanationRequest) {
			r.Comment = strings.Replace(r.Comment, `"outcome":"success"`, `"outcome":"failed"`, 1)
		}},
		{"wrong repository", func(r *ExplanationRequest) { r.Comment = strings.ReplaceAll(r.Comment, "origin/repo", "another/repo") }},
		{"wrong material", func(r *ExplanationRequest) {
			r.Comment = strings.ReplaceAll(r.Comment, "accepted-material", "other-material")
		}},
		{"oversize TEXT", func(r *ExplanationRequest) { r.Comment += strings.Repeat("λ", 32768) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := r
			tc.edit(&changed)
			_, err := DecodeExplanation(jsonWire(t, changed))
			requireInvalid(t, err)
		})
	}
	for _, key := range []string{"actor", "result", "outcome", "receiptRecordsJson"} {
		t.Run("unknown/"+key, func(t *testing.T) {
			var obj map[string]any
			_ = json.Unmarshal(jsonWire(t, r), &obj)
			obj[key] = "injected"
			_, err := DecodeExplanation(jsonWire(t, obj))
			requireInvalid(t, err)
		})
	}
	for _, wire := range []string{strings.Replace(string(jsonWire(t, r)), `"comment":`, `"comment":"duplicate","comment":`, 1), strings.Replace(string(jsonWire(t, r)), `"originalRequest":`, `"OriginalRequest":`, 1), string(jsonWire(t, r)) + ` {}`} {
		_, err := DecodeExplanation([]byte(wire))
		requireInvalid(t, err)
	}
}
func TestExplanationLookupKeepsProtocolAndExactDigestSeparate(t *testing.T) {
	r := explanationWireRequest(t)
	lookup := ExplanationLookupRequest{Protocol: ExplanationProtocol, OperationID: r.OperationID, RequestDigest: ExplanationDigest(r)}
	decoded, err := DecodeExplanationLookup(jsonWire(t, lookup))
	if err != nil || decoded != lookup {
		t.Fatal("new exact lookup refused", err)
	}
	lookup.Protocol = Protocol
	_, err = DecodeExplanationLookup(jsonWire(t, lookup))
	requireInvalid(t, err)
}
