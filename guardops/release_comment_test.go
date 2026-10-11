package guardops

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const releaseCommentBody = " \nClear after λ `cmd`\t\n "

// Independently calculated with Python hashlib and >Q UTF8 byte lengths.
const releaseCommentVector = "17fa7c23b40bc7381df0117455b9e3bbd0eecbf57cd36cb8d29320d4f0b39a15"

func releaseCommentWire(t *testing.T, comment string) []byte {
	t.Helper()
	return jsonReplace(t, jsonWire(t, wireRequest()), `"kind":"release"`, `"kind":"release-with-comment","comment":`+string(jsonWire(t, comment)))
}

func TestReleaseCommentWirePreservesExactBodyAndLegacyDigest(t *testing.T) {
	raw := releaseCommentWire(t, releaseCommentBody)
	before := bytes.Clone(raw)
	r, err := DecodeRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Effect struct{ Kind, Comment string }
	}
	if err := json.Unmarshal(jsonWire(t, r), &envelope); err != nil || envelope.Effect.Kind != "release-with-comment" || envelope.Effect.Comment != releaseCommentBody || !bytes.Equal(raw, before) {
		t.Fatalf("release comment lost its exact body/input: %+v err=%v", envelope, err)
	}
	if Digest(wireRequest()) != requestVector {
		t.Fatal("legacy release digest changed")
	}
	if Digest(r) == Digest(wireRequest()) {
		t.Fatal("new effect lost its distinct digest identity")
	}
	if Digest(r) != releaseCommentVector {
		t.Fatalf("new effect framing changed: got %s want %s", Digest(r), releaseCommentVector)
	}
	trimmed, err := DecodeRequest(releaseCommentWire(t, strings.TrimSpace(releaseCommentBody)))
	if err != nil || Digest(r) == Digest(trimmed) {
		t.Fatalf("comment whitespace was normalized in digest: err=%v", err)
	}
}

func TestReleaseCommentWireRequiresBoundedNonblankUTF8Body(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"empty", "", false}, {"blank", " \r\n\t", false},
		{"one byte", "x", true}, {"UTF8 exact byte cap", strings.Repeat("é", (1<<20)/2), true},
		{"UTF8 exceeds byte cap", strings.Repeat("é", (1<<20)/2) + "x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRequest(releaseCommentWire(t, tc.body))
			if tc.valid {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireInvalid(t, err)
			}
		})
	}
}

func TestReleaseCommentWireRejectsAmbiguousAndWrongShapes(t *testing.T) {
	base := releaseCommentWire(t, "body")
	for _, tc := range []struct{ name, before, after string }{
		{"missing", `,"comment":"body"`, ``},
		{"null", `"comment":"body"`, `"comment":null`},
		{"number", `"comment":"body"`, `"comment":1`},
		{"object", `"comment":"body"`, `"comment":{"text":"body"}`},
		{"alias", `"comment":"body"`, `"Comment":"body"`},
		{"duplicate", `"comment":"body"`, `"comment":"body","comment":"other"`},
		{"unknown", `"comment":"body"`, `"comment":"body","force":true`},
		{"unpaired escape", `"comment":"body"`, `"comment":"\ud800"`},
		{"legacy with body", `"kind":"release-with-comment"`, `"kind":"release"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeRequest(jsonReplace(t, base, tc.before, tc.after))
			requireInvalid(t, err)
		})
	}
}

func TestReleaseCommentTypedValidationRejectsInvalidUTF8AndLegacyBody(t *testing.T) {
	r := wireRequest()
	r.Effect = Effect{Kind: "release-with-comment", Comment: string([]byte{0xff})}
	requireInvalid(t, ValidateRequest(r))
	r.Effect.Comment = " valid exact UTF8 λ\n "
	if err := ValidateRequest(r); err != nil {
		t.Fatal(err)
	}
	r.Effect.Kind = "release"
	requireInvalid(t, ValidateRequest(r))
	r.Effect.Comment = ""
	if err := ValidateRequest(r); err != nil || Digest(r) != requestVector {
		t.Fatalf("typed extension changed legacy contract: err=%v", err)
	}
}
