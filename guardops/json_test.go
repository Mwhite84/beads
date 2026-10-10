package guardops

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func jsonWire(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func jsonReplace(t *testing.T, raw []byte, before, after string) []byte {
	t.Helper()
	if bytes.Count(raw, []byte(before)) != 1 {
		t.Fatalf("fixture replacement must identify one field: %q", before)
	}
	return bytes.Replace(raw, []byte(before), []byte(after), 1)
}

func TestDecodeRequestPreservesFrozenOpaqueBytesAndDigests(t *testing.T) {
	original := wireRequest()
	raw := append([]byte(" \n\t"), jsonWire(t, original)...)
	raw = append(raw, []byte("\r\n ")...)
	before := bytes.Clone(raw)
	decoded, err := DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != original || decoded.Expected.StateJSON != frozenState || decoded.ContextJSON != original.ContextJSON {
		t.Fatal("strict decode normalized opaque state/context or another wire field")
	}
	if SnapshotDigest(decoded.Expected) != snapshotVector || Digest(decoded) != requestVector {
		t.Fatal("strict decode changed frozen TypeScript digest identity")
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("decoder mutated caller bytes")
	}
}

func TestDecodeRequestRejectsDuplicateAndUnknownFieldsAtEveryObject(t *testing.T) {
	base := jsonWire(t, wireRequest())
	for _, tc := range []struct{ name, before, after string }{
		{"top duplicate", `"actor":"sol-d"`, `"actor":"sol-d","actor":"other"`},
		{"top identical duplicate", `"actor":"sol-d"`, `"actor":"sol-d","actor":"sol-d"`},
		{"escaped duplicate name", `"actor":"sol-d"`, `"actor":"sol-d","\u0061ctor":"other"`},
		{"snapshot duplicate", `"token":"token-1"`, `"token":"token-1","token":"other"`},
		{"effect duplicate", `"kind":"release"`, `"kind":"release","kind":"release"`},
		{"top unknown", `"actor":"sol-d"`, `"actor":"sol-d","unrecognized":true`},
		{"snapshot unknown", `"token":"token-1"`, `"token":"token-1","unrecognized":true`},
		{"effect unknown", `"kind":"release"`, `"kind":"release","unrecognized":true`},
		{"top case alias", `"actor":"sol-d"`, `"actor":"sol-d","Actor":"other"`},
		{"snapshot case alias", `"token":"token-1"`, `"token":"token-1","Token":"other"`},
		{"effect case alias", `"kind":"release"`, `"kind":"release","Kind":"release"`},
		{"noncanonical name", `"actor":"sol-d"`, `"Actor":"sol-d"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRequest(jsonReplace(t, base, tc.before, tc.after))
			requireInvalid(t, err)
		})
	}
}

func TestDecodeRequestRejectsMissingAndWrongFieldShapes(t *testing.T) {
	base := jsonWire(t, wireRequest())
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(base, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"protocol", "operationId", "actor", "expected", "effect", "contextJson"} {
		t.Run("missing "+name, func(t *testing.T) {
			copy := make(map[string]json.RawMessage, len(fields))
			for key, value := range fields {
				if key != name {
					copy[key] = value
				}
			}
			_, err := DecodeRequest(jsonWire(t, copy))
			requireInvalid(t, err)
		})
	}
	for _, tc := range []struct{ name, before, after string }{
		{"numeric actor", `"actor":"sol-d"`, `"actor":1`},
		{"null actor", `"actor":"sol-d"`, `"actor":null`},
		{"object context", string(jsonWire(t, wireRequest().ContextJSON)), `{}`},
		{"wrong protocol", `"protocol":"beads.guard.v1","operationId"`, `"protocol":"wrong","operationId"`},
		{"null snapshot token", `"token":"token-1"`, `"token":null`},
		{"numeric snapshot token", `"token":"token-1"`, `"token":1`},
		{"wrong effect", `"kind":"release"`, `"kind":"hold"`},
		{"null effect kind", `"kind":"release"`, `"kind":null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRequest(jsonReplace(t, base, tc.before, tc.after))
			requireInvalid(t, err)
		})
	}
	for _, raw := range []string{"", "null", "[]", `"string"`, "42", "{}"} {
		t.Run("root "+raw, func(t *testing.T) {
			_, err := DecodeRequest([]byte(raw))
			requireInvalid(t, err)
		})
	}
	for _, container := range []string{"expected", "effect"} {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(fields[container], &nested); err != nil {
			t.Fatal(err)
		}
		for field := range nested {
			t.Run("missing "+container+"."+field, func(t *testing.T) {
				copy := make(map[string]json.RawMessage, len(fields))
				for key, value := range fields {
					copy[key] = value
				}
				inner := make(map[string]json.RawMessage, len(nested))
				for key, value := range nested {
					if key != field {
						inner[key] = value
					}
				}
				copy[container] = jsonWire(t, inner)
				_, err := DecodeRequest(jsonWire(t, copy))
				requireInvalid(t, err)
			})
		}
	}
}

func TestDecodeRejectsTrailingValuesAndMalformedEncoding(t *testing.T) {
	request, lookup := jsonWire(t, wireRequest()), jsonWire(t, LookupRequest{Protocol: Protocol, OperationID: "operation-1", RequestDigest: requestVector})
	for _, suffix := range []string{"{}", " null", " []", " true", " garbage", "\x00"} {
		t.Run("trailing "+suffix, func(t *testing.T) {
			_, err := DecodeRequest(append(bytes.Clone(request), suffix...))
			requireInvalid(t, err)
			_, err = DecodeLookup(append(bytes.Clone(lookup), suffix...))
			requireInvalid(t, err)
		})
	}
	for _, raw := range [][]byte{
		jsonReplace(t, request, `"actor":"sol-d"`, "\"actor\":\"\xff\""),
		jsonReplace(t, request, `"actor":"sol-d"`, `"actor":"\x41"`),
		request[:len(request)-1],
	} {
		_, err := DecodeRequest(raw)
		requireInvalid(t, err)
	}
	_, err := DecodeLookup(jsonReplace(t, lookup, `"operationId":"operation-1"`, "\"operationId\":\"\xed\xa0\x80\""))
	requireInvalid(t, err)
}

func TestDecodeUnicodePairsAndEscapedLiteralSurrogates(t *testing.T) {
	base := jsonWire(t, wireRequest())
	for _, tc := range []struct{ name, encoded, want string }{
		{"paired emoji", `"\uD83D\uDE42"`, "🙂"},
		{"BMP accents", `"\u00e9\u5b57"`, "é字"},
		{"literal high surrogate escape", `"\\ud800"`, `\ud800`},
		{"literal low surrogate escape", `"\\udfff"`, `\udfff`},
		{"escaped quote before pair", `"\"\uD83D\uDE42"`, "\"🙂"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := DecodeRequest(jsonReplace(t, base, `"actor":"sol-d"`, `"actor":`+tc.encoded))
			if err != nil || decoded.Actor != tc.want {
				t.Fatalf("valid Unicode changed/refused: actor=%q err=%v", decoded.Actor, err)
			}
		})
	}
	for _, encoded := range []string{`"\ud800"`, `"\udfff"`, `"\ud800x"`, `"\ud800\u0041"`, `"\ud800\ud800"`, `"\udfff\ud800"`, `"\ud800\\udfff"`} {
		t.Run("unpaired "+encoded, func(t *testing.T) {
			_, err := DecodeRequest(jsonReplace(t, base, `"actor":"sol-d"`, `"actor":`+encoded))
			requireInvalid(t, err)
		})
	}
	original := wireRequest()
	original.Expected.StateJSON = " \n{\"literal\":\"\\ud800\",\"int64\":9007199254740993,\"escaped\":\"\\\\uDFFF\"}\t "
	decoded, err := DecodeRequest(jsonWire(t, original))
	if err != nil || decoded != original || Digest(decoded) != Digest(original) {
		t.Fatalf("opaque literal escape/state whitespace was interpreted: %v", err)
	}
}

func TestDecodeLookupRejectsAmbiguousOrInvalidWire(t *testing.T) {
	original := LookupRequest{Protocol: Protocol, OperationID: "operation-1", RequestDigest: requestVector}
	base := jsonWire(t, original)
	decoded, err := DecodeLookup(base)
	if err != nil || decoded != original {
		t.Fatalf("valid lookup changed/refused: %+v %v", decoded, err)
	}
	for _, tc := range []struct{ name, before, after string }{
		{"duplicate", `"operationId":"operation-1"`, `"operationId":"operation-1","operationId":"other"`},
		{"escaped duplicate", `"operationId":"operation-1"`, `"operationId":"operation-1","\u006fperationId":"other"`},
		{"case alias", `"operationId":"operation-1"`, `"operationId":"operation-1","OperationId":"other"`},
		{"unknown", `"operationId":"operation-1"`, `"operationId":"operation-1","unknown":true`},
		{"missing operation", `"operationId":"operation-1",`, ""},
		{"wrong operation type", `"operationId":"operation-1"`, `"operationId":[]`},
		{"unpaired escape", `"operationId":"operation-1"`, `"operationId":"\ud800"`},
		{"wrong protocol", `"protocol":"beads.guard.v1"`, `"protocol":"wrong"`},
		{"wrong digest", requestVector, strings.Repeat("g", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeLookup(jsonReplace(t, base, tc.before, tc.after))
			requireInvalid(t, err)
		})
	}
}

func TestDecodeWireByteCapIsInclusiveAndRefusesOversize(t *testing.T) {
	lookup := LookupRequest{Protocol: Protocol, OperationID: "operation-1", RequestDigest: requestVector}
	raw := jsonWire(t, lookup)
	// Padding counts toward the full input cap, independent of decoded fields.
	raw = append(raw, bytes.Repeat([]byte{' '}, MaxWireBytes-len(raw))...)
	decoded, err := DecodeLookup(raw)
	if err != nil || decoded != lookup {
		t.Fatalf("exact-cap wire refused or changed: %v", err)
	}
	raw = append(raw, ' ')
	_, err = DecodeLookup(raw)
	requireInvalid(t, err)
	_, err = DecodeRequest(raw)
	requireInvalid(t, err)
}
