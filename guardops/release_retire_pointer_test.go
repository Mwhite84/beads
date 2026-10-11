package guardops

import (
	"encoding/json"
	"strings"
	"testing"
)

const retiredPointer = "workflow#original-run"

func retirePointerWire(t *testing.T, edit func(map[string]any)) []byte {
	t.Helper()
	comment := string(jsonWire(t, map[string]any{"schema": "omg.bead-claim-release.v1", "code": "KRW_SOURCE_STALE_CLAIM_RECLAIMED", "reason": "Original run terminal λ `exact  --command`\n", "retiredClaimPointer": retiredPointer}))
	effect := map[string]any{"kind": "release-retire-pointer", "claimPointer": retiredPointer, "comment": comment}
	if edit != nil {
		edit(effect)
	}
	var envelope map[string]any
	_ = json.Unmarshal(jsonWire(t, wireRequest()), &envelope)
	envelope["effect"] = effect
	return jsonWire(t, envelope)
}

func TestRetirePointerExactWireDigestAndLegacyCompatibility(t *testing.T) {
	raw := retirePointerWire(t, nil)
	r, err := DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]any
	_ = json.Unmarshal(raw, &before)
	_ = json.Unmarshal(jsonWire(t, r), &after)
	if string(jsonWire(t, before["effect"])) != string(jsonWire(t, after["effect"])) || Digest(wireRequest()) != requestVector {
		t.Fatal("new provenance bytes or old release digest changed")
	}
	changed, err := DecodeRequest(retirePointerWire(t, func(e map[string]any) {
		e["claimPointer"] = retiredPointer + " "
		var comment map[string]any
		_ = json.Unmarshal([]byte(e["comment"].(string)), &comment)
		comment["retiredClaimPointer"] = e["claimPointer"]
		e["comment"] = string(jsonWire(t, comment))
	}))
	if err != nil || Digest(r) == Digest(changed) {
		t.Fatalf("exact pointer omitted from identity: %v", err)
	}
}

func TestRetirePointerRejectsMissingAmbiguousOrUnrelatedFields(t *testing.T) {
	for _, cause := range []string{"blank pointer", "missing pointer", "null pointer", "wrong provenance", "missing provenance", "blank reason", "receipt", "oversized comment", "bad schema", "duplicate provenance"} {
		t.Run(cause, func(t *testing.T) {
			_, err := DecodeRequest(retirePointerWire(t, func(e map[string]any) {
				switch cause {
				case "blank pointer":
					e["claimPointer"] = " "
				case "missing pointer":
					delete(e, "claimPointer")
				case "null pointer":
					e["claimPointer"] = nil
				case "receipt":
					e["receiptRecordsJson"] = "[]"
				case "oversized comment":
					e["comment"] = strings.Repeat("λ", 32768)
				default:
					var c map[string]any
					_ = json.Unmarshal([]byte(e["comment"].(string)), &c)
					if cause == "wrong provenance" {
						c["retiredClaimPointer"] = "newer-run"
					}
					if cause == "missing provenance" {
						delete(c, "retiredClaimPointer")
					}
					if cause == "blank reason" {
						c["reason"] = " "
					}
					if cause == "bad schema" {
						c["schema"] = "other"
					}
					body := string(jsonWire(t, c))
					if cause == "duplicate provenance" {
						body = strings.Replace(body, `"retiredClaimPointer":`, `"retiredClaimPointer":"other","retiredClaimPointer":`, 1)
					}
					e["comment"] = body
				}
			}))
			requireInvalid(t, err)
		})
	}
}
