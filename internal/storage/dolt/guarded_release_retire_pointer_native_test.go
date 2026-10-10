package dolt

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/steveyegge/beads/guardops"
)

const guardedRetiredPointer = "workflow#original-run"
const guardedUnrelatedMetadata = `{"array":[1,2],"integer":9007199254740993,"text":"λ"}`

func guardedRetirePointerRequest(t *testing.T, ctx context.Context, s *DoltStore) (guardops.Mutator, guardops.Request) {
	t.Helper()
	m, r := guardedNativeSeed(t, ctx, s)
	for key, raw := range map[string]string{"krewe_claim_run": `"` + guardedRetiredPointer + `"`, "unrelated": guardedUnrelatedMetadata} {
		if err := s.MergeMetadata(ctx, r.Expected.IssueID, key, json.RawMessage(raw), r.Actor); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	r.Expected, err = m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	var metadata map[string]json.RawMessage
	issue, err := s.GetIssue(ctx, r.Expected.IssueID)
	if err != nil || json.Unmarshal(issue.Metadata, &metadata) != nil {
		t.Fatal("ordinary metadata setup unreadable", err)
	}
	t.Logf("ordinary native metadata before guarded capture: requested=%s actual=%s", guardedUnrelatedMetadata, string(metadata["unrelated"]))
	if string(metadata["unrelated"]) != guardedCapturedUnrelatedMetadata(t, r) {
		t.Fatal("native row and original captured metadata differ")
	}
	r.OperationID = "native-retire-original-pointer"
	comment, _ := json.Marshal(map[string]string{"schema": "omg.bead-claim-release.v1", "code": "KRW_SOURCE_STALE_CLAIM_RECLAIMED", "reason": "Original run terminal λ `command  --exact`", "retiredClaimPointer": guardedRetiredPointer})
	// Decode the ruled new wire shape through the actual typed request. On the
	// pre-change source the unsupported effect is refused, not stubbed.
	raw, _ := json.Marshal(r)
	var wire map[string]any
	_ = json.Unmarshal(raw, &wire)
	wire["effect"] = map[string]string{"kind": "release-retire-pointer", "claimPointer": guardedRetiredPointer, "comment": string(comment)}
	raw, _ = json.Marshal(wire)
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return m, r
}

func guardedRequireRetiredPointer(t *testing.T, ctx context.Context, s *DoltStore, r guardops.Request, result guardops.Result) {
	t.Helper()
	issue, err := s.GetIssue(ctx, r.Expected.IssueID)
	if err != nil || issue.Assignee != "" || issue.Status != "open" {
		t.Fatalf("claim not actually released: %+v %v", issue, err)
	}
	var metadata map[string]json.RawMessage
	if json.Unmarshal(issue.Metadata, &metadata) != nil || metadata["krewe_claim_run"] != nil || string(metadata["unrelated"]) != guardedCapturedUnrelatedMetadata(t, r) {
		t.Fatalf("orphan pointer remained or unrelated metadata lost: %s", issue.Metadata)
	}
	var native struct {
		RetiredClaimPointer string `json:"retiredClaimPointer"`
		CommentID           string `json:"commentId"`
	}
	if json.Unmarshal([]byte(result.ResultJSON), &native) != nil || native.RetiredClaimPointer != guardedRetiredPointer || native.CommentID == "" {
		t.Fatalf("durable release result lacks exact pointer provenance: %s", result.ResultJSON)
	}
	comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
	if err != nil || len(comments) != 1 || comments[0].Text != r.Effect.Comment || comments[0].ID != native.CommentID {
		t.Fatalf("exact release provenance comment not published once: %+v %v", comments, err)
	}
	var provenance map[string]any
	if json.Unmarshal([]byte(comments[0].Text), &provenance) != nil || provenance["retiredClaimPointer"] != guardedRetiredPointer {
		t.Fatal("release comment lacks exact original pointer")
	}
	var published string
	if err := s.db.QueryRowContext(ctx, "SELECT metadata FROM issues AS OF 'HEAD' WHERE id=?", r.Expected.IssueID).Scan(&published); err != nil || json.Unmarshal([]byte(published), &metadata) != nil || metadata["krewe_claim_run"] != nil {
		t.Fatalf("native HEAD did not retire pointer: %s %v", published, err)
	}
}

func TestGuardedNativeRetirePointerReleaseReplayPreservesUnrelatedMetadata(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedRetirePointerRequest(t, ctx, s)
	before := guardedNativeObserve(t, ctx, s)
	result, err := m.Apply(ctx, r)
	if err != nil || result.Outcome != "applied" {
		t.Fatalf("new pointer retirement refused: %+v %v", result, err)
	}
	guardedRequireRetiredPointer(t, ctx, s, r, result)
	after := guardedNativeObserve(t, ctx, s)
	if after.LeaseJSON != "[]" || after.Unclaimed != before.Unclaimed+1 || after.Operations != 1 || after.Commits != before.Commits+1 || after.Token == before.Token || after.Head == before.Head {
		t.Fatal("pointer/release/comment/lease/event/ledger/history not atomic")
	}
	replay, err := m.Apply(ctx, r)
	if err != nil || !replay.Replayed || replay.ResultJSON != result.ResultJSON || guardedNativeObserve(t, ctx, s) != after {
		t.Fatal("original release replay retired/mutated another pointer or repeated effects")
	}
}

func TestGuardedNativeRetirePointerRefusesNewerPointerStatusAndMaterial(t *testing.T) {
	for _, cause := range []string{"pointer", "status", "material"} {
		t.Run(cause, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			m, r := guardedRetirePointerRequest(t, ctx, s)
			if cause == "pointer" {
				if err := s.MergeMetadata(ctx, r.Expected.IssueID, "krewe_claim_run", json.RawMessage(`"workflow#newer-run"`), r.Actor); err != nil {
					t.Fatal(err)
				}
			} else {
				updates := map[string]interface{}{"description": "newer material"}
				if cause == "status" {
					updates = map[string]interface{}{"status": "blocked"}
				}
				if err := s.UpdateIssue(ctx, r.Expected.IssueID, updates, r.Actor); err != nil {
					t.Fatal(err)
				}
			}
			before := guardedNativeObserve(t, ctx, s)
			result, err := m.Apply(ctx, r)
			if err == nil || result.Outcome != "conflict" || guardedNativeObserve(t, ctx, s) != before {
				t.Fatalf("stale release retired new work: %+v %v", result, err)
			}
			comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
			if err != nil || len(comments) != 0 {
				t.Fatal("stale retirement left comment")
			}
		})
	}
}

func TestGuardedNativeRetirePointerCommentEventFailureRollsBackReleaseAndMetadata(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedRetirePointerRequest(t, ctx, s)
	before := guardedNativeObserve(t, ctx, s)
	fault := &guardedReleaseCommentFault{phase: "comment event"}
	original := s.db
	s.db = sql.OpenDB(guardedReleaseCommentFaultConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if !errors.Is(err, errGuardedReleaseCommentFault) || result.Outcome != "refused" || fault.failures.Load() != 1 || !fault.tentativeReleased || fault.tentativeComments != "1" || fault.commits.Load() != 0 || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("tentative release/comment not fully rolled back: %+v %v %+v", result, err, fault)
	}
	issue, err := s.GetIssue(ctx, r.Expected.IssueID)
	var metadata map[string]json.RawMessage
	if err != nil || json.Unmarshal(issue.Metadata, &metadata) != nil || string(metadata["krewe_claim_run"]) != `"`+guardedRetiredPointer+`"` || string(metadata["unrelated"]) != guardedCapturedUnrelatedMetadata(t, r) {
		t.Fatal("failed retirement lost original pointer/unrelated metadata")
	}
	comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
	if err != nil || len(comments) != 0 {
		t.Fatal("failed retirement left comment")
	}
}

func TestGuardedNativeRetirePointerAckLossRecoveredByOriginalLookup(t *testing.T) {
	ctx, s, cfg := guardedNativeStore(t)
	m, r := guardedRetirePointerRequest(t, ctx, s)
	fault := &guardedNativeCommitAckFault{}
	original := s.db
	s.db = sql.OpenDB(guardedNativeCommitAckConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	unknown, err := m.Apply(ctx, r)
	if !errors.Is(err, io.ErrUnexpectedEOF) || unknown.Outcome != "unknown" || fault.commitCalls.Load() != 1 {
		t.Fatalf("retirement ack loss asserted completion/replayed: %+v %v", unknown, err)
	}
	freshCfg := *cfg
	freshCfg.CreateIfMissing = false
	fresh, err := New(ctx, &freshCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	recovery, err := fresh.GuardedMutator()
	if err != nil {
		t.Fatal(err)
	}
	found, err := recovery.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: guardops.Digest(r)})
	if err != nil || found.Outcome != "applied" {
		t.Fatalf("original retirement lookup failed: %+v %v", found, err)
	}
	guardedRequireRetiredPointer(t, ctx, fresh, r, found)
	after := guardedNativeObserve(t, ctx, fresh)
	replay, err := recovery.Apply(ctx, r)
	if err != nil || !replay.Replayed || replay.ResultJSON != found.ResultJSON || guardedNativeObserve(t, ctx, fresh) != after || fault.commitCalls.Load() != 1 {
		t.Fatal("retirement recovery manufactured new history/effects")
	}
}

// The native JSON column may canonicalize numbers at ordinary fixture creation.
// Guarded retirement must preserve the exact OBSERVED original database values;
// it cannot reconstruct precision already absent before the original capture.
func guardedCapturedUnrelatedMetadata(t *testing.T, r guardops.Request) string {
	t.Helper()
	var state struct {
		Issues []map[string]*string `json:"issues"`
	}
	if json.Unmarshal([]byte(r.Expected.StateJSON), &state) != nil {
		t.Fatal("original capture malformed")
	}
	for _, row := range state.Issues {
		if row["id"] != nil && *row["id"] == r.Expected.IssueID && row["metadata"] != nil {
			var values map[string]json.RawMessage
			if json.Unmarshal([]byte(*row["metadata"]), &values) != nil || values["unrelated"] == nil {
				t.Fatal("captured unrelated metadata missing")
			}
			return string(values["unrelated"])
		}
	}
	t.Fatal("captured original issue metadata missing")
	return ""
}
