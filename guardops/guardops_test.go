package guardops

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Independently frozen TypeScript wire vectors from guarded-bead-command.test.ts.
// The \x60 escapes preserve its literal backticks.
const frozenState = " {\n \"issues\": [{\"id\":\"guard.1\",\"description\":\"λ \\n \x60cmd\x60\", \"assignee\":null}], \"dependencies\":[], \"config\":{\"kv.opaque\":\"é\"}\n } "
const snapshotVector = "6c0e3b9ab9ead6fb79218bfa911d710794b7226b171eac2715bc8c4587fa0f2a"
const requestVector = "f6554d2ff6d435acb0aaf6dcea87096727fec39d49b7f891447e278bf9b715a3"

func wireSnapshot() Snapshot {
	return Snapshot{
		Protocol: Protocol, IssueID: "guard.1", Database: "guard_db", Branch: "main",
		Head: strings.Repeat("h", 40), Root: strings.Repeat("r", 40),
		Generation: "generation-1", Token: "token-1", StateJSON: frozenState,
	}
}

func wireRequest() Request {
	return Request{
		Protocol: Protocol, OperationID: "operation-1", Actor: "sol-d", Expected: wireSnapshot(),
		Effect: Effect{Kind: "release"}, ContextJSON: " {\"proof\":\"é\", \"sha\":\"" + strings.Repeat("a", 40) + "\"} ",
	}
}

func requireInvalid(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected typed wire validation refusal, got %v", err)
	}
}

func TestWireDigestsMatchFrozenTypeScriptUTF8Vectors(t *testing.T) {
	s, r := wireSnapshot(), wireRequest()
	if err := ValidateSnapshot(s); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRequest(r); err != nil {
		t.Fatal(err)
	}
	if got := SnapshotDigest(s); got != snapshotVector {
		t.Fatalf("snapshot byte-framing drift: got %s want %s", got, snapshotVector)
	}
	if got := Digest(r); got != requestVector {
		t.Fatalf("request byte-framing drift: got %s want %s", got, requestVector)
	}
	if s != wireSnapshot() || r != wireRequest() {
		t.Fatal("digest or validation mutated its input")
	}
}

func TestWireLengthFramingSeparatesConcatenationCollisions(t *testing.T) {
	a, b := wireRequest(), wireRequest()
	a.OperationID, a.Actor = "ab", "c"
	b.OperationID, b.Actor = "a", "bc"
	if Digest(a) == Digest(b) {
		t.Fatal("component boundaries disappeared from digest")
	}
	a.OperationID, a.Actor = "é", "字🙂"
	b.OperationID, b.Actor = "é字", "🙂"
	if Digest(a) == Digest(b) {
		t.Fatal("UTF8 component boundaries disappeared from digest")
	}
}

func TestWireRequestDigestBindsEveryDeclaredField(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Request)
	}{
		{"protocol", func(r *Request) { r.Protocol += "-different" }},
		{"operationId", func(r *Request) { r.OperationID += "-different" }},
		{"actor", func(r *Request) { r.Actor += "-different" }},
		{"expected.protocol", func(r *Request) { r.Expected.Protocol += "-different" }},
		{"expected.issueId", func(r *Request) { r.Expected.IssueID += "-different" }},
		{"expected.database", func(r *Request) { r.Expected.Database += "-different" }},
		{"expected.branch", func(r *Request) { r.Expected.Branch += "-different" }},
		{"expected.head", func(r *Request) { r.Expected.Head += "-different" }},
		{"expected.root", func(r *Request) { r.Expected.Root += "-different" }},
		{"expected.generation", func(r *Request) { r.Expected.Generation += "-different" }},
		{"expected.token", func(r *Request) { r.Expected.Token += "-different" }},
		{"expected.stateJson", func(r *Request) { r.Expected.StateJSON += "-different" }},
		{"effect.kind", func(r *Request) { r.Effect.Kind += "-different" }},
		{"contextJson", func(r *Request) { r.ContextJSON += "-different" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := wireRequest()
			tc.change(&changed)
			if Digest(changed) == requestVector {
				t.Fatal("different request reused original identity")
			}
		})
	}
}

func TestWireOpaqueStateAndContextBytesArePreserved(t *testing.T) {
	for _, state := range []string{
		frozenState, " opaque future state\n ",
		" \t{\"row_lock\":9007199254740993,\"raw\":\"字🙂é\",\"differentOrder\":true}\n ",
	} {
		t.Run(state, func(t *testing.T) {
			r := wireRequest()
			r.Expected.StateJSON = state
			before := r
			if err := ValidateRequest(r); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Request
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded != before || decoded.Expected.StateJSON != state || Digest(decoded) != Digest(before) {
				t.Fatal("wire serialization changed opaque bytes or int64 text")
			}
			changed := r
			changed.Expected.StateJSON = strings.TrimSpace(state)
			if Digest(changed) == Digest(r) {
				t.Fatal("opaque state whitespace was normalized")
			}
			changed = r
			changed.ContextJSON = strings.TrimSpace(r.ContextJSON)
			if Digest(changed) == Digest(r) {
				t.Fatal("opaque context whitespace was normalized")
			}
		})
	}
}

func TestWireSnapshotRejectsIncompleteProtocolAndShape(t *testing.T) {
	requireInvalid(t, ValidateSnapshot(Snapshot{}))
	for _, tc := range []struct {
		name   string
		change func(*Snapshot)
	}{
		{"wrong protocol", func(s *Snapshot) { s.Protocol = "beads.guard.v0" }},
		{"issueId", func(s *Snapshot) { s.IssueID = " " }},
		{"database", func(s *Snapshot) { s.Database = "" }},
		{"branch", func(s *Snapshot) { s.Branch = "\t" }},
		{"head", func(s *Snapshot) { s.Head = "" }},
		{"root", func(s *Snapshot) { s.Root = "" }},
		{"generation", func(s *Snapshot) { s.Generation = "" }},
		{"token", func(s *Snapshot) { s.Token = "\n" }},
		{"stateJson", func(s *Snapshot) { s.StateJSON = " " }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := wireSnapshot()
			tc.change(&s)
			requireInvalid(t, ValidateSnapshot(s))
		})
	}
}

func TestWireRequestRejectsUnsupportedOrIncompleteShape(t *testing.T) {
	requireInvalid(t, ValidateRequest(Request{}))
	for _, tc := range []struct {
		name   string
		change func(*Request)
	}{
		{"wrong protocol", func(r *Request) { r.Protocol = "beads.guard.v0" }},
		{"unsupported effect", func(r *Request) { r.Effect.Kind = "hold" }},
		{"missing effect", func(r *Request) { r.Effect = Effect{} }},
		{"missing operation", func(r *Request) { r.OperationID = "" }},
		{"blank actor", func(r *Request) { r.Actor = "\t" }},
		{"empty context", func(r *Request) { r.ContextJSON = "" }},
		{"blank context", func(r *Request) { r.ContextJSON = " \n " }},
		{"missing expected", func(r *Request) { r.Expected = Snapshot{} }},
		{"missing expected token", func(r *Request) { r.Expected.Token = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := wireRequest()
			tc.change(&r)
			requireInvalid(t, ValidateRequest(r))
		})
	}
}

func TestWireValidationUsesExactUTF8ByteCaps(t *testing.T) {
	t.Run("state", func(t *testing.T) {
		s := wireSnapshot()
		s.StateJSON = strings.Repeat("é", MaxStateBytes/2)
		if len(s.StateJSON) != MaxStateBytes {
			t.Fatal("fixture byte count drift")
		}
		if err := ValidateSnapshot(s); err != nil {
			t.Fatalf("exact-cap state refused: %v", err)
		}
		s.StateJSON += "x"
		requireInvalid(t, ValidateSnapshot(s))
	})
	t.Run("context", func(t *testing.T) {
		r := wireRequest()
		r.ContextJSON = strings.Repeat("é", MaxContextBytes/2)
		if err := ValidateRequest(r); err != nil {
			t.Fatalf("exact-cap context refused: %v", err)
		}
		r.ContextJSON += "x"
		requireInvalid(t, ValidateRequest(r))
	})
	t.Run("operation and actor", func(t *testing.T) {
		r := wireRequest()
		r.OperationID, r.Actor = strings.Repeat("é", 64), strings.Repeat("é", 128)
		if err := ValidateRequest(r); err != nil {
			t.Fatalf("exact byte-cap identity refused: %v", err)
		}
		lookup := LookupRequest{Protocol: Protocol, OperationID: r.OperationID, RequestDigest: requestVector}
		if err := ValidateLookup(lookup); err != nil {
			t.Fatal(err)
		}
		r.OperationID += "x"
		lookup.OperationID = r.OperationID
		requireInvalid(t, ValidateRequest(r))
		requireInvalid(t, ValidateLookup(lookup))
		r = wireRequest()
		r.Actor = strings.Repeat("é", 128) + "x"
		requireInvalid(t, ValidateRequest(r))
	})
}

func TestWireInvalidUTF8CannotBeSilentlyReplaced(t *testing.T) {
	bad := string([]byte{0xed, 0xa0, 0x80}) // UTF8 encoding of an invalid surrogate.
	for _, tc := range []struct {
		name   string
		change func(*Request)
	}{
		{"actor", func(r *Request) { r.Actor += bad }},
		{"operationId", func(r *Request) { r.OperationID += bad }},
		{"stateJson", func(r *Request) { r.Expected.StateJSON += bad }},
		{"contextJson", func(r *Request) { r.ContextJSON += bad }},
		{"root", func(r *Request) { r.Expected.Root += bad }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := wireRequest()
			tc.change(&r)
			requireInvalid(t, ValidateRequest(r))
		})
	}
	requireInvalid(t, ValidateLookup(LookupRequest{
		Protocol: Protocol, OperationID: "operation-" + bad, RequestDigest: requestVector,
	}))
}

func TestWireLookupRequiresProtocolIdentityAndLowercaseSHA256(t *testing.T) {
	original := LookupRequest{Protocol: Protocol, OperationID: "operation-1", RequestDigest: requestVector}
	if err := ValidateLookup(original); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*LookupRequest)
	}{
		{"wrong protocol", func(r *LookupRequest) { r.Protocol = "beads.guard.v0" }},
		{"blank operation", func(r *LookupRequest) { r.OperationID = " " }},
		{"missing digest", func(r *LookupRequest) { r.RequestDigest = "" }},
		{"uppercase digest", func(r *LookupRequest) { r.RequestDigest = strings.ToUpper(requestVector) }},
		{"nonhex digest", func(r *LookupRequest) { r.RequestDigest = strings.Repeat("g", 64) }},
		{"short digest", func(r *LookupRequest) { r.RequestDigest = requestVector[:62] }},
		{"long digest", func(r *LookupRequest) { r.RequestDigest += "00" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := original
			tc.change(&r)
			requireInvalid(t, ValidateLookup(r))
		})
	}
	if original.RequestDigest != requestVector {
		t.Fatal("validation changed lookup identity")
	}
}
