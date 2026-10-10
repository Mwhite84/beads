package dolt

import (
	"encoding/json"
	"testing"
)

// Ordinary lifecycle release deliberately leaves Krewe metadata untouched.
// A guarded exact-pointer retirement must still finish that outstanding effect
// without forging a second lifecycle release or deleting somebody else's work.
func TestGuardedNativeRetirePointerAlreadyOrdinaryReleasedPublishesOnce(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedRetirePointerRequest(t, ctx, s)
	if err := s.UnclaimIssue(ctx, r.Expected.IssueID, r.Actor, false); err != nil {
		t.Fatal(err)
	}
	original, err := s.GetIssue(ctx, r.Expected.IssueID)
	var metadata map[string]json.RawMessage
	if err != nil || original.Status != "open" || original.Assignee != "" || json.Unmarshal(original.Metadata, &metadata) != nil || string(metadata["krewe_claim_run"]) != `"`+guardedRetiredPointer+`"` {
		t.Fatalf("ordinary release did not leave exact orphan pointer: %+v %v", original, err)
	}
	// This is the ORIGINAL independent request capture after fixture setup;
	// failed/unknown requests are never recaptured or replaced.
	r.Expected, err = m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	r.OperationID = "native-retire-already-ordinary-released"
	before := guardedNativeObserve(t, ctx, s)
	result, err := m.Apply(ctx, r)
	if err != nil || result.Outcome != "applied" {
		t.Fatalf("already open/unassigned retirement refused: %+v %v", result, err)
	}
	var native struct {
		Changed             *bool  `json:"changed"`
		RetiredClaimPointer string `json:"retiredClaimPointer"`
		CommentID           string `json:"commentId"`
	}
	if json.Unmarshal([]byte(result.ResultJSON), &native) != nil || native.Changed == nil || *native.Changed || native.RetiredClaimPointer != guardedRetiredPointer || native.CommentID == "" {
		t.Fatalf("retirement forged lifecycle change or lost provenance: %s", result.ResultJSON)
	}
	guardedRequireRetiredPointer(t, ctx, s, r, result)
	after := guardedNativeObserve(t, ctx, s)
	if after.Status != before.Status || after.Assignee != before.Assignee || after.Started != before.Started || after.LeaseJSON != before.LeaseJSON || after.Unclaimed != before.Unclaimed || after.Operations != before.Operations+1 || after.Commits != before.Commits+1 || after.Head == before.Head || after.Token == before.Token {
		t.Fatalf("retirement repeated lifecycle or failed atomic publication: before=%+v after=%+v", before, after)
	}
	issue, err := s.GetIssue(ctx, r.Expected.IssueID)
	if err != nil || issue.Description != original.Description || issue.AcceptanceCriteria != original.AcceptanceCriteria || issue.Title != original.Title || issue.Priority != original.Priority || issue.IssueType != original.IssueType || issue.ExternalRef != original.ExternalRef {
		t.Fatal("pointer retirement changed unrelated issue material", err)
	}
	replay, err := m.Apply(ctx, r)
	if err != nil || !replay.Replayed || replay.ResultJSON != result.ResultJSON || guardedNativeObserve(t, ctx, s) != after {
		t.Fatalf("already released retirement replay repeated effect: %+v %v", replay, err)
	}
}
