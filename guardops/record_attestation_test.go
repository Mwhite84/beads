package guardops

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRecordAttestationExactReadWireAndIndependentLookup(t *testing.T) {
	value := `{"version":1,"namespace":"` + strings.Repeat("a", 64) + `","value":{"legacy":true}}`
	r := RecordAttestationRequest{Protocol: Protocol, Expected: wireRequest().Expected, RecordKey: "krewe.audit.v1." + strings.Repeat("a", 64) + "." + RecordValueDigest(value), RecordValue: value}
	raw, _ := json.Marshal(r)
	decoded, err := DecodeRecordAttestation(raw)
	if err != nil || decoded != r {
		t.Fatalf("exact read envelope rejected: %v", err)
	}
	// Content-hash admission alone does not identify this unknown payload.
	for _, cause := range []string{"wrong key", "altered value", "unknown field", "duplicate key", "missing expected", "null value", "lookup fields"} {
		t.Run(cause, func(t *testing.T) {
			var object map[string]any
			_ = json.Unmarshal(raw, &object)
			switch cause {
			case "wrong key":
				object["recordKey"] = "kv." + r.RecordKey
			case "altered value":
				object["recordValue"] = value + " "
			case "unknown field":
				object["complete"] = true
			case "missing expected":
				delete(object, "expected")
			case "null value":
				object["recordValue"] = nil
			case "lookup fields":
				object["operationId"] = "caller-picked"
				object["requestDigest"] = strings.Repeat("a", 64)
			}
			invalid, _ := json.Marshal(object)
			if cause == "duplicate key" {
				invalid = []byte(strings.Replace(string(invalid), `"recordKey":`, `"recordKey":"other","recordKey":`, 1))
			}
			_, err := DecodeRecordAttestation(invalid)
			requireInvalid(t, err)
		})
	}
	if ValidateLookup(LookupRequest{Protocol: Protocol, OperationID: "missing digest"}) == nil {
		t.Fatal("record attestation widened digest-required lookup")
	}
}
func TestRetirePointerMetadataPreservesExactUnrelatedNumbersAndRejectsAmbiguity(t *testing.T) {
	raw := json.RawMessage(`{"krewe_claim_run":"original","other":{"n":9007199254740993,"text":"λ"}}`)
	kept, err := RetirePointerMetadata(raw, "original")
	if err != nil || string(kept["other"]) != `{"n":9007199254740993,"text":"λ"}` || len(kept) != 1 {
		t.Fatalf("metadata corrupted: %s %v", kept, err)
	}
	for _, value := range []string{`null`, `[]`, `{}`, `{"krewe_claim_run":null}`, `{"krewe_claim_run":"newer"}`, `{"krewe_claim_run":"original","krewe_claim_run":"original"}`, `{"krewe_claim_run":"original","other":"\ud800"}`} {
		if _, err := RetirePointerMetadata([]byte(value), "original"); err == nil {
			t.Fatalf("ambiguous metadata accepted %s", value)
		}
	}
}
