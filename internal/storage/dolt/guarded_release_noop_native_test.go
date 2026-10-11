package dolt

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	"github.com/steveyegge/beads/issueops"
)

func TestGuardedNativeAlreadyReleasedPublishesOnlyRequestedEvidence(t *testing.T) {
	for _, kind := range []string{"release", "release-with-comment"} {
		t.Run(kind, func(t *testing.T) {
			ctx, store, _ := guardedNativeStore(t)
			mutator, request := guardedNativeSeed(t, ctx, store)
			request.OperationID = "native-already-released-1"
			request.Effect.Kind = kind
			if kind == "release-with-comment" {
				request.Effect.Comment = guardedReleaseCommentBody
			}
			if err := store.UnclaimIssue(ctx, request.Expected.IssueID, request.Actor, false); err != nil {
				t.Fatal(err)
			}
			before := guardedNativeObserve(t, ctx, store)
			if before.Assignee != "" || before.Status != "open" || before.Started.Valid || before.LeaseJSON != "[]" {
				t.Fatalf("ordinary native release did not establish no-op fixture: %+v", before)
			}
			stale, err := mutator.Apply(ctx, request)
			if !errors.Is(err, guardtx.ErrConflict) || stale.Outcome != "conflict" || stale.ResultJSON != "" || guardedNativeObserve(t, ctx, store) != before {
				t.Fatalf("already-released state bypassed ORIGINAL full snapshot: %+v err=%v", stale, err)
			}
			// A new explicit caller capture authorizes this distinct operation;
			// Apply itself may not replace the failed original expectation.
			request.Expected, err = mutator.Capture(ctx, request.Expected.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			result, err := mutator.Apply(ctx, request)
			if err != nil || result.Outcome != "applied" || result.Replayed || result.RequestDigest != guardops.Digest(request) {
				t.Fatalf("open/unassigned guarded completion refused: %+v err=%v", result, err)
			}
			var native guardedReleaseCommentResult
			if err := json.Unmarshal([]byte(result.ResultJSON), &native); err != nil || native.Changed || native.Issue == nil || native.Issue.ID != request.Expected.IssueID || native.Issue.Assignee != "" || native.Issue.Status != "open" {
				t.Fatalf("no-op fabricated a release or changed result identity: %+v err=%v", native, err)
			}
			after := guardedNativeObserve(t, ctx, store)
			if after.Assignee != before.Assignee || after.Status != before.Status || after.RowVersion != before.RowVersion || after.Started != before.Started || after.LeaseJSON != before.LeaseJSON || after.Unclaimed != before.Unclaimed || after.Operations != 1 || after.Token == before.Token || after.Head == before.Head || after.Commits != before.Commits+1 {
				t.Fatalf("no-op changed lifecycle or omitted protected ledger/history: before=%+v after=%+v", before, after)
			}
			if kind == "release-with-comment" {
				guardedReleaseCommentRequireOneComment(t, ctx, store, request, result)
			} else {
				comments, err := store.GetIssueComments(ctx, request.Expected.IssueID)
				if err != nil || len(comments) != 0 || native.CommentID != "" {
					t.Fatalf("plain no-op invented comment: %+v err=%v", comments, err)
				}
				var decoded map[string]json.RawMessage
				if err := json.Unmarshal([]byte(result.ResultJSON), &decoded); err != nil || len(decoded) != 2 || decoded["Issue"] == nil || decoded["Changed"] == nil {
					t.Fatalf("legacy result shape changed: %s err=%v", result.ResultJSON, err)
				}
			}
			var rowVersion int64
			var saved, token string
			if err := store.db.QueryRowContext(ctx, "SELECT row_lock FROM issues AS OF 'HEAD' WHERE id=?", request.Expected.IssueID).Scan(&rowVersion); err != nil || rowVersion != before.RowVersion {
				t.Fatalf("native HEAD invented row revision: %d err=%v", rowVersion, err)
			}
			if err := store.db.QueryRowContext(ctx, "SELECT result_json FROM bd_guard_operations AS OF 'HEAD' WHERE operation_id=?", request.OperationID).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			var ledger guardops.Result
			if err := json.Unmarshal([]byte(saved), &ledger); err != nil || ledger != result {
				t.Fatalf("same native HEAD omitted exact no-op completion: %+v err=%v", ledger, err)
			}
			if err := store.db.QueryRowContext(ctx, "SELECT token FROM bd_guard_state AS OF 'HEAD' WHERE id=1").Scan(&token); err != nil || token != after.Token {
				t.Fatalf("same native HEAD omitted no-op operation token: %q err=%v", token, err)
			}
			replay, err := mutator.Apply(ctx, request)
			if err != nil || !replay.Replayed {
				t.Fatalf("no-op original request replay failed: %+v err=%v", replay, err)
			}
			replay.Replayed = false
			if replay != result || guardedNativeObserve(t, ctx, store) != after {
				t.Fatal("no-op replay repeated history/lifecycle or changed original result")
			}
			if kind == "release-with-comment" {
				guardedReleaseCommentRequireOneComment(t, ctx, store, request, result)
			}
		})
	}
}

func TestGuardedNativeAlreadyReleasedDoesNotRelaxOrdinaryReleaseRole(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	_, request := guardedNativeSeed(t, ctx, store)
	if err := store.UnclaimIssue(ctx, request.Expected.IssueID, request.Actor, false); err != nil {
		t.Fatal(err)
	}
	before := guardedNativeObserve(t, ctx, store)
	role, err := store.Releaser()
	if err != nil {
		t.Fatal(err)
	}
	_, err = role.Release(ctx, issueops.ReleaseRequest{Actor: request.Actor, IssueID: request.Expected.IssueID})
	if !errors.Is(err, issueops.ErrNotClaimed) || guardedNativeObserve(t, ctx, store) != before {
		t.Fatalf("ordinary native release semantics were relaxed: err=%v", err)
	}
}

func TestGuardedNativeAlreadyReleasedDoesNotCompleteOtherUnassignedStatuses(t *testing.T) {
	for _, status := range []string{"in_progress", "closed"} {
		t.Run(status, func(t *testing.T) {
			ctx, store, _ := guardedNativeStore(t)
			mutator, request := guardedNativeSeed(t, ctx, store)
			if err := store.UnclaimIssue(ctx, request.Expected.IssueID, request.Actor, false); err != nil {
				t.Fatal(err)
			}
			if err := store.UpdateIssue(ctx, request.Expected.IssueID, map[string]interface{}{"status": status}, request.Actor); err != nil {
				t.Fatal(err)
			}
			var err error
			request.Expected, err = mutator.Capture(ctx, request.Expected.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			request.Effect = guardops.Effect{Kind: "release-with-comment", Comment: guardedReleaseCommentBody}
			before := guardedNativeObserve(t, ctx, store)
			result, err := mutator.Apply(ctx, request)
			if err == nil || result.Outcome != "refused" || result.ResultJSON != "" || result.Replayed || guardedNativeObserve(t, ctx, store) != before {
				t.Fatalf("other unassigned status fabricated release completion: %+v err=%v", result, err)
			}
			comments, err := store.GetIssueComments(ctx, request.Expected.IssueID)
			if err != nil || len(comments) != 0 {
				t.Fatalf("refused status persisted comment: %+v err=%v", comments, err)
			}
		})
	}
}
