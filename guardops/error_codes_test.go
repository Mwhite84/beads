package guardops

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGuardErrorCodeWireCompatibility(t *testing.T) {
	// Frozen downstream vocabulary: adding a code requires a coordinated decoder change.
	codes := []ErrorCode{CodeInvalidRequest, CodeHistoryPublicationRequired, CodeCapabilityUnavailable,
		CodeContextUnavailable, CodeUnsupportedState, CodeExpectationConflict, CodeSerializationConflict,
		CodeRequestMismatch, CodePermissionDenied, CodeSchemaUnavailable, CodeDeadlineExceeded,
		CodeCancelled, CodeStorageFailure, CodePublicationUnconfirmed, CodeLookupUnconfirmed}
	const vocabulary = `invalid-request,history-publication-required,capability-unavailable,context-unavailable,unsupported-state,expectation-conflict,serialization-conflict,request-mismatch,permission-denied,schema-unavailable,deadline-exceeded,cancelled,storage-failure,publication-unconfirmed,lookup-unconfirmed`
	var values []string
	for _, code := range codes {
		values = append(values, string(code))
		for _, value := range []any{Result{Outcome: "refused", ErrorCode: code}, ExplanationResult{Outcome: "refused", ErrorCode: code}} {
			raw, err := json.Marshal(value)
			if err != nil || !strings.Contains(string(raw), `"errorCode":"`+string(code)+`"`) || strings.Contains(string(raw), `"reason"`) {
				t.Fatalf("unexpected structured failure wire: %s, %v", raw, err)
			}
		}
	}
	if strings.Join(values, ",") != vocabulary {
		t.Fatal("downstream vocabulary drift")
	}
	for _, value := range []any{Result{Outcome: "applied"}, ExplanationResult{Outcome: "applied"}} {
		raw, err := json.Marshal(value)
		if err != nil || strings.Contains(string(raw), `"errorCode"`) {
			t.Fatalf("legacy success shape changed: %s %v", raw, err)
		}
	}
	var legacy Result
	if err := json.Unmarshal([]byte(`{"protocol":"beads.guard.v1","operationId":"old","requestDigest":"digest","outcome":"applied","resultJson":"{}"}`), &legacy); err != nil || legacy.ErrorCode != "" {
		t.Fatalf("legacy durable result no longer readable: %+v %v", legacy, err)
	}
}
