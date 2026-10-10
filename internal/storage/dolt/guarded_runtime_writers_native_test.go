package dolt

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	storeops "github.com/steveyegge/beads/internal/storage/issueops"
	"github.com/steveyegge/beads/internal/storage/versioncontrolops"
	"github.com/steveyegge/beads/internal/types"
	"github.com/steveyegge/beads/issueops"
)

// These are ordinary native writers, not guarded Apply substitutes. The shared
// private-port fixture never starts a server or falls back to Docker.
func TestGuardedRuntimeNativeMetadataAndLifecycle(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	_, _ = guardedRuntimeSeed(t, ctx, store)
	before := guardedNativeObserve(t, ctx, store)
	if err := store.MergeMetadata(ctx, "guard-target", "runtime-control", json.RawMessage(`{"execution":"ordinary"}`), "guard-owner"); err != nil {
		t.Fatal(err)
	}
	metadata := guardedNativeObserve(t, ctx, store)
	guardedRuntimeRequireMaterialRevision(t, before, metadata)
	guardedRuntimeRequireEvent(t, ctx, store, types.EventUpdated, "guard-owner")
	guardedRuntimeRequirePublication(t, ctx, store, before, metadata)
	issue, err := store.GetIssue(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]struct{ Execution string }
	if err := json.Unmarshal(issue.Metadata, &fields); err != nil || fields["runtime-control"].Execution != "ordinary" {
		t.Fatalf("ordinary metadata did not retain nested JSON: %s err=%v", issue.Metadata, err)
	}
	releaser, err := store.Releaser()
	if err != nil {
		t.Fatal(err)
	}
	released, err := releaser.Release(ctx, issueops.ReleaseRequest{IssueID: "guard-target", Actor: "guard-owner"})
	if err != nil || !released.Changed || released.Issue == nil || released.Issue.Assignee != "" || released.Issue.Status != "open" {
		t.Fatalf("ordinary native release: %+v err=%v", released, err)
	}
	unclaimed := guardedNativeObserve(t, ctx, store)
	guardedRuntimeRequirePublication(t, ctx, store, metadata, unclaimed)
	if unclaimed.Assignee != "" || unclaimed.Status != "open" || unclaimed.Started.Valid || unclaimed.LeaseJSON != "[]" || unclaimed.RowVersion == metadata.RowVersion || unclaimed.Unclaimed != metadata.Unclaimed+1 {
		t.Fatalf("ordinary release row/lease/event disagree: before=%+v after=%+v", metadata, unclaimed)
	}
	if err := store.ClaimIssue(ctx, "guard-target", "second-owner"); err != nil {
		t.Fatal(err)
	}
	claimed := guardedNativeObserve(t, ctx, store)
	guardedRuntimeRequirePublication(t, ctx, store, unclaimed, claimed)
	if claimed.Assignee != "second-owner" || claimed.Status != "in_progress" || !claimed.Started.Valid || claimed.LeaseJSON == "[]" || claimed.RowVersion == unclaimed.RowVersion {
		t.Fatalf("ordinary claim row/lease disagree: %+v", claimed)
	}
	guardedRuntimeRequireEvent(t, ctx, store, types.EventClaimed, "second-owner")
	if err := store.CloseIssue(ctx, "guard-target", "ordinary work complete", "second-owner", "runtime-control"); err != nil {
		t.Fatal(err)
	}
	closed := guardedNativeObserve(t, ctx, store)
	guardedRuntimeRequirePublication(t, ctx, store, claimed, closed)
	if closed.Status != "closed" || closed.LeaseJSON != "[]" || closed.RowVersion == claimed.RowVersion {
		t.Fatalf("ordinary close row/lease disagree: %+v", closed)
	}
	guardedRuntimeRequireEvent(t, ctx, store, types.EventClosed, "second-owner")
	var headStatus string
	if err := store.db.QueryRowContext(ctx, "SELECT status FROM issues AS OF 'HEAD' WHERE id='guard-target'").Scan(&headStatus); err != nil || headStatus != "closed" {
		t.Fatalf("ordinary close absent from native HEAD: %q err=%v", headStatus, err)
	}
}

func TestGuardedRuntimeNativeIgnoredWritesStampWithoutHistory(t *testing.T) {
	for _, name := range []string{"heartbeat", "comment event", "local metadata", "repo cache", "wisp material", "wisp label", "wisp event", "wisp comment"} {
		t.Run(name, func(t *testing.T) {
			ctx, store, _ := guardedNativeStore(t)
			mutator, request := guardedRuntimeSeed(t, ctx, store)
			wispID := "guard-wisp"
			if name == "wisp material" || name == "wisp label" || name == "wisp event" || name == "wisp comment" {
				beforeCreate := guardedNativeObserve(t, ctx, store)
				if err := store.CreateIssue(ctx, &types.Issue{ID: wispID, Title: "original wisp", Status: types.StatusOpen, Priority: 2, IssueType: types.TypeTask, Ephemeral: true}, "wisp-owner"); err != nil {
					t.Fatal(err)
				}
				created := guardedNativeObserve(t, ctx, store)
				guardedRuntimeRequireIgnoredStamp(t, beforeCreate, created)
				guardedNativeRequireOriginalClaim(t, beforeCreate, created)
				var err error
				request.Expected, err = mutator.Capture(ctx, "guard-target")
				if err != nil {
					t.Fatal(err)
				}
			}
			table := map[string]string{"heartbeat": "leases", "comment event": "events", "local metadata": "local_metadata", "repo cache": "repo_mtimes", "wisp material": "wisps", "wisp label": "wisp_labels", "wisp event": "wisp_events", "wisp comment": "wisp_comments"}[name]
			before := guardedNativeObserve(t, ctx, store)
			rowsBefore := guardedRuntimeTableJSON(t, ctx, store, table)
			var err error
			switch name {
			case "heartbeat":
				// A different TTL guarantees a real lease change without sleeps.
				err = store.HeartbeatIssue(storeops.WithLeaseTTL(ctx, 2*time.Hour), "guard-target", "guard-owner")
			case "comment event":
				err = store.AddComment(ctx, "guard-target", "comment-owner", "ignored ordinary event")
			case "local metadata":
				err = store.SetLocalMetadata(ctx, "runtime-control", "new clone-local value")
			case "repo cache":
				err = store.SetRepoMtime(ctx, "/private/representative-repo", "/private/representative-repo/issues.jsonl", 123456789)
			case "wisp material":
				err = store.UpdateIssue(ctx, wispID, map[string]interface{}{"title": "changed wisp material"}, "wisp-owner")
			case "wisp label":
				err = store.AddLabel(ctx, wispID, "runtime-control", "wisp-owner")
			case "wisp event":
				err = store.AddComment(ctx, wispID, "wisp-owner", "ignored wisp event")
			case "wisp comment":
				_, err = store.AddIssueComment(ctx, wispID, "wisp-owner", "ignored structured wisp comment")
			}
			if err != nil {
				t.Fatalf("ordinary %s failed: %v", name, err)
			}
			after := guardedNativeObserve(t, ctx, store)
			rowsAfter := guardedRuntimeTableJSON(t, ctx, store, table)
			if rowsBefore == rowsAfter {
				t.Fatalf("%s returned success without a physical %s change", name, table)
			}
			guardedRuntimeRequireIgnoredStamp(t, before, after)
			if name == "heartbeat" {
				if after.LeaseJSON == before.LeaseJSON {
					t.Fatal("heartbeat did not extend the physical lease")
				}
				withOldLease := after
				withOldLease.LeaseJSON = before.LeaseJSON
				guardedNativeRequireOriginalClaim(t, before, withOldLease)
			} else {
				guardedNativeRequireOriginalClaim(t, before, after)
			}
			result, err := mutator.Apply(ctx, request)
			if !errors.Is(err, guardtx.ErrConflict) || result.Outcome != "conflict" {
				t.Fatalf("stale durable capture survived ordinary %s: %+v err=%v", name, result, err)
			}
			if guardedNativeObserve(t, ctx, store) != after || guardedRuntimeTableJSON(t, ctx, store, table) != rowsAfter {
				t.Fatal("stale refusal altered ordinary writer effects/token/history")
			}
			// An ignored-only token is pending coordination, not native work.
			if err := store.CommitWithConfig(ctx, "must not publish ignored-only work"); err != nil {
				t.Fatal(err)
			}
			if flushed := guardedNativeObserve(t, ctx, store); flushed != after {
				t.Fatalf("ignored-only coordination created native history or another token: before=%+v after=%+v", after, flushed)
			}
		})
	}
}

func TestGuardedRuntimeNativeSharedRegularIgnoredTransaction(t *testing.T) {
	for _, journal := range []bool{false, true} {
		name := "journal disabled"
		if journal {
			name = "journal enabled"
		}
		t.Run(name, func(t *testing.T) {
			ctx, store, _ := guardedNativeStore(t)
			_, _ = guardedRuntimeSeed(t, ctx, store)
			store.SetEventsJournalEnabled(journal)
			before := guardedNativeObserve(t, ctx, store)
			if err := store.RunInTransaction(ctx, "ordinary shared runtime write", func(tx storage.Transaction) error {
				if err := tx.UpdateIssue(ctx, "guard-target", map[string]interface{}{"description": "shared runtime material"}, "guard-owner"); err != nil {
					return err
				}
				return tx.CreateIssue(ctx, &types.Issue{ID: "guard-wisp", Title: "shared runtime wisp", Status: types.StatusOpen, Priority: 2, IssueType: types.TypeTask, Ephemeral: true}, "wisp-owner")
			}); err != nil {
				t.Fatal(err)
			}
			after := guardedNativeObserve(t, ctx, store)
			guardedRuntimeRequireMaterialRevision(t, before, after)
			guardedRuntimeRequireEvent(t, ctx, store, types.EventUpdated, "guard-owner")
			guardedRuntimeRequirePublication(t, ctx, store, before, after)
			wisp, err := store.GetIssue(ctx, "guard-wisp")
			if err != nil || wisp == nil || !wisp.Ephemeral || wisp.Title != "shared runtime wisp" {
				t.Fatalf("shared ignored plane did not commit: %+v err=%v", wisp, err)
			}
			var description string
			if err := store.db.QueryRowContext(ctx, "SELECT description FROM issues AS OF 'HEAD' WHERE id='guard-target'").Scan(&description); err != nil || description != "shared runtime material" {
				t.Fatalf("shared versioned plane did not publish: %q err=%v", description, err)
			}
			rows, err := store.ReadEventsJournal(ctx, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !journal {
				if len(rows) != 0 {
					t.Fatalf("guard binding silently enabled journal: %+v", rows)
				}
				return
			}
			if len(rows) != 2 || rows[0].IssueID != "guard-target" || rows[1].IssueID != "guard-wisp" || rows[1].Seq != rows[0].Seq+1 {
				t.Fatalf("shared runtime journal missing consecutive actual writes: %+v", rows)
			}
			// Pruning only the ignored journal is another ordinary SQL writer;
			// it must stamp without changing native versioned history.
			beforePrune := guardedNativeObserve(t, ctx, store)
			n, err := store.PruneEventsJournal(ctx, rows[1].Seq+1, 0, 0)
			if err != nil || n != 2 {
				t.Fatalf("ordinary journal prune: count=%d err=%v", n, err)
			}
			afterPrune := guardedNativeObserve(t, ctx, store)
			guardedRuntimeRequireIgnoredStamp(t, beforePrune, afterPrune)
			guardedNativeRequireOriginalClaim(t, beforePrune, afterPrune)
			remaining, err := store.ReadEventsJournal(ctx, rows[1].Seq, 0)
			if err != nil || len(remaining) != 0 {
				t.Fatalf("pruned journal still has actual rows: %+v err=%v", remaining, err)
			}
		})
	}
}

func TestGuardedRuntimeNativeSameValueConfigIsActualNoOp(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	mutator, request := guardedRuntimeSeed(t, ctx, store)
	const key, value = "kv.runtime-noop", `{"accepted":true}`
	if err := store.SetConfig(ctx, key, value); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitWithConfig(ctx, "establish actual same-value baseline"); err != nil {
		t.Fatal(err)
	}
	var err error
	request.Expected, err = mutator.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	before := guardedNativeObserve(t, ctx, store)
	configBefore := guardedRuntimeTableJSON(t, ctx, store, "config")
	if err := store.SetConfig(ctx, key, value); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitWithConfig(ctx, "same value must not create history"); err != nil {
		t.Fatal(err)
	}
	if actual, err := store.GetConfig(ctx, key); err != nil || actual != value {
		t.Fatalf("same-value write lost exact config: %q err=%v", actual, err)
	}
	if guardedNativeObserve(t, ctx, store) != before || guardedRuntimeTableJSON(t, ctx, store, "config") != configBefore {
		t.Fatal("actual REPLACE of same value changed token, rows, native HEAD or history")
	}
	// The original valid expectation remains usable; a no-op cannot stale it.
	result, err := mutator.Apply(ctx, request)
	if err != nil || result.Outcome != "applied" {
		t.Fatalf("same-value no-op invalidated original expectation: %+v err=%v", result, err)
	}
}

func TestGuardedRuntimeNativeProxiedBlockedRepairParticipates(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	mutator, request := guardedRuntimeSeed(t, ctx, store)
	// Deliberately inconsistent derived state is fixture setup, not a new
	// runtime writer. Commit it before testing the existing public repair seam.
	if _, err := store.db.ExecContext(ctx, "UPDATE issues SET is_blocked=1 WHERE id='guard-target'"); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitWithConfig(ctx, "private inconsistent blocked-flag fixture"); err != nil {
		t.Fatal(err)
	}
	var err error
	request.Expected, err = mutator.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	before := guardedNativeObserve(t, ctx, store)
	conn, err := store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed, repairErr := versioncontrolops.RecomputeAllBlockedOnConn(ctx, conn, "private guarded control <guard-test@example.invalid>")
	closeErr := conn.Close()
	if repairErr != nil || closeErr != nil || changed != 1 {
		t.Fatalf("actual pinned proxied repair: changed=%d err=%v close=%v", changed, repairErr, closeErr)
	}
	after := guardedNativeObserve(t, ctx, store)
	guardedRuntimeRequirePublication(t, ctx, store, before, after)
	guardedNativeRequireOriginalClaim(t, before, after)
	var blocked bool
	if err := store.db.QueryRowContext(ctx, "SELECT is_blocked FROM issues AS OF 'HEAD' WHERE id='guard-target'").Scan(&blocked); err != nil || blocked {
		t.Fatalf("corrected derived flag absent from native HEAD: blocked=%v err=%v", blocked, err)
	}
	result, err := mutator.Apply(ctx, request)
	if !errors.Is(err, guardtx.ErrConflict) || result.Outcome != "conflict" || guardedNativeObserve(t, ctx, store) != after {
		t.Fatalf("original capture survived actual proxied repair: %+v err=%v", result, err)
	}
	// Its idempotent invocation must not create a token or history entry.
	conn, err = store.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changed, repairErr = versioncontrolops.RecomputeAllBlockedOnConn(ctx, conn, "")
	closeErr = conn.Close()
	if repairErr != nil || closeErr != nil || changed != 0 || guardedNativeObserve(t, ctx, store) != after {
		t.Fatalf("consistent derived-state repair changed native state: changed=%d err=%v close=%v", changed, repairErr, closeErr)
	}
}

func guardedRuntimeRequirePublication(t *testing.T, ctx context.Context, store *DoltStore, before, after guardedNativeObservation) {
	t.Helper()
	if after.Token == before.Token || after.Head == before.Head || after.Commits != before.Commits+1 || after.Operations != 0 {
		t.Fatalf("ordinary effect/token/native publication disagree: before=%+v after=%+v", before, after)
	}
	// Observe the same published token, rather than accepting a dirty token that
	// accidentally missed the native staging set.
	var token string
	if err := store.db.QueryRowContext(ctx, "SELECT token FROM bd_guard_state AS OF 'HEAD' WHERE id=1").Scan(&token); err != nil || token != after.Token {
		t.Fatalf("ordinary native HEAD lacks acknowledged token: token=%q err=%v", token, err)
	}
}

func guardedRuntimeSeed(t *testing.T, ctx context.Context, store *DoltStore) (guardops.Mutator, guardops.Request) {
	t.Helper()
	mutator, request := guardedNativeSeed(t, ctx, store)
	// The frozen seed sets issue_prefix, while its create/claim/init commits
	// selectively stage other tables. Publish that fixture config first so the
	// ignored-only flush control cannot commit unrelated setup work.
	if err := store.CommitWithConfig(ctx, "publish representative fixture config baseline"); err != nil {
		t.Fatal(err)
	}
	pending, err := storeops.HasPendingChanges(ctx, store.db)
	if err != nil || pending {
		t.Fatalf("representative fixture has unrelated native work: pending=%v err=%v", pending, err)
	}
	request.Expected, err = mutator.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	return mutator, request
}

func guardedRuntimeRequireMaterialRevision(t *testing.T, before, after guardedNativeObservation) {
	t.Helper()
	// Native UpdateIssue changes row_lock for all material updates, including
	// metadata. Witness that revision while preserving ownership and liveness.
	if after.RowVersion == before.RowVersion || after.Assignee != before.Assignee || after.Status != before.Status || after.Started != before.Started || after.LeaseJSON != before.LeaseJSON || after.Unclaimed != before.Unclaimed || after.Operations != 0 {
		t.Fatalf("material revision altered lifecycle/lease or lost its revision: before=%+v after=%+v", before, after)
	}
}

func guardedRuntimeRequireIgnoredStamp(t *testing.T, before, after guardedNativeObservation) {
	t.Helper()
	if after.Token == before.Token || after.Head != before.Head || after.Commits != before.Commits || after.Operations != 0 {
		t.Fatalf("ignored-only native effect did not stamp without history: before=%+v after=%+v", before, after)
	}
}

func guardedRuntimeRequireEvent(t *testing.T, ctx context.Context, store *DoltStore, kind types.EventType, actor string) {
	t.Helper()
	events, err := store.GetEvents(ctx, "guard-target", 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.EventType == kind && event.Actor == actor {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("ordinary %s event for %s: got %d, want exactly one", kind, actor, count)
	}
}

func guardedRuntimeTableJSON(t *testing.T, ctx context.Context, store *DoltStore, table string) string {
	t.Helper()
	// Only read a table selected by this file's fixed literal test cases.
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := guardRows(ctx, tx, table)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
