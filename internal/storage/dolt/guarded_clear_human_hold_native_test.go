package dolt

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/steveyegge/beads/guardops"
)

func guardedClearanceRequest(t *testing.T, ctx context.Context, store *DoltStore) (guardops.Mutator, guardops.Request) {
	t.Helper()
	mutator, request := guardedNativeSeed(t, ctx, store)
	for _, label := range []string{"human-required", "standing"} {
		if err := store.AddLabel(ctx, request.Expected.IssueID, label, request.Actor); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := mutator.Capture(ctx, request.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	request.Expected = snapshot
	request.OperationID = "native-human-clearance-1"
	clearance := map[string]any{"clearedBy": request.Actor, "clearedAt": "2026-10-10T12:34:56.123456789Z", "materialVersion": "original-material-fingerprint"}
	history := map[string]any{"kind": "identified-clearance", "operationId": request.OperationID, "guardGeneration": snapshot.Generation, "originalToken": snapshot.Token, "baseline": "unknown-legacy", "historyComplete": false, "clearance": clearance}
	encode := func(namespace string, value any) (string, string) {
		raw, err := json.Marshal(map[string]any{"version": 1, "namespace": namespace, "value": value})
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		return "krewe.audit.v1." + namespace + "." + hex.EncodeToString(hash[:]), string(raw)
	}
	clearKey, clearValue := encode(strings.Repeat("a", 64), clearance)
	historyKey, historyValue := encode(strings.Repeat("b", 64), history)
	request.Effect = guardops.Effect{Kind: "clear-human-hold", ClearanceKey: clearKey, ClearanceValue: clearValue, HistoryKey: historyKey, HistoryValue: historyValue}
	if err := guardops.ValidateRequest(request); err != nil {
		t.Fatal(err)
	}
	return mutator, request
}

func TestGuardedNativeClearHumanHoldPublishesImmutableEvidenceAndReplay(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	mutator, request := guardedClearanceRequest(t, ctx, store)
	before := guardedNativeObserve(t, ctx, store)
	result, err := mutator.Apply(ctx, request)
	if err != nil || result.Outcome != "applied" || result.Replayed {
		t.Fatalf("identified clearance failed: %+v err=%v", result, err)
	}
	after := guardedClearanceRequireApplied(t, ctx, store, request, result, before)
	replay, err := mutator.Apply(ctx, request)
	if err != nil || !replay.Replayed {
		t.Fatalf("cleared label prevented ledger-first replay: %+v err=%v", replay, err)
	}
	replay.Replayed = false
	if replay != result || guardedNativeObserve(t, ctx, store) != after {
		t.Fatal("replay repeated label/event/history or changed original evidence")
	}
	guardedClearanceRequireApplied(t, ctx, store, request, replay, before)
}

func TestGuardedNativeClearHumanHoldOriginalSnapshotRefusesOrdinaryChanges(t *testing.T) {
	for _, change := range []string{"material", "human KV"} {
		t.Run(change, func(t *testing.T) {
			ctx, store, _ := guardedNativeStore(t)
			mutator, request := guardedClearanceRequest(t, ctx, store)
			if change == "material" {
				if err := store.UpdateIssue(ctx, request.Expected.IssueID, map[string]interface{}{"description": "changed after captured review"}, request.Actor); err != nil {
					t.Fatal(err)
				}
			} else if err := store.SetConfig(ctx, "kv.krewe.audit.v1.concurrent-human-record", "unknown concurrent human evidence"); err != nil {
				t.Fatal(err)
			}
			before := guardedNativeObserve(t, ctx, store)
			result, err := mutator.Apply(ctx, request)
			if err == nil || result.Outcome != "conflict" || result.ResultJSON != "" || result.Replayed {
				t.Fatalf("stale review cleared hold: %+v err=%v", result, err)
			}
			guardedClearanceRequireRefused(t, ctx, store, mutator, request, before, true)
		})
	}
}

func TestGuardedNativeClearHumanHoldRefusesMissingHoldAndImmutableKeyReuse(t *testing.T) {
	for _, cause := range []string{"absent hold", "existing clearance"} {
		t.Run(cause, func(t *testing.T) {
			ctx, store, _ := guardedNativeStore(t)
			mutator, request := guardedClearanceRequest(t, ctx, store)
			if cause == "absent hold" {
				if err := store.RemoveLabel(ctx, request.Expected.IssueID, "human-required", request.Actor); err != nil {
					t.Fatal(err)
				}
			} else {
				key := request.Effect.ClearanceKey
				if err := store.SetConfig(ctx, "kv."+key, "preserve existing malformed human record"); err != nil {
					t.Fatal(err)
				}
			}
			// Refresh ONLY the deliberate precondition fixture before this call;
			// never refresh a failed request or claim historical completeness.
			snapshot, err := mutator.Capture(ctx, request.Expected.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			request.Expected = snapshot
			var history map[string]any
			_ = json.Unmarshal([]byte(request.Effect.HistoryValue), &history)
			history["value"].(map[string]any)["originalToken"] = snapshot.Token
			raw, _ := json.Marshal(history)
			request.Effect.HistoryValue = string(raw)
			hash := sha256.Sum256(raw)
			newKey := "krewe.audit.v1." + strings.Repeat("b", 64) + "." + hex.EncodeToString(hash[:])
			request.Effect.HistoryKey = newKey
			before := guardedNativeObserve(t, ctx, store)
			result, err := mutator.Apply(ctx, request)
			if err == nil || result.Outcome != "refused" || result.ResultJSON != "" || result.Replayed {
				t.Fatalf("invalid current hold/immutable append completed: %+v err=%v", result, err)
			}
			guardedClearanceRequireRefused(t, ctx, store, mutator, request, before, cause != "absent hold")
		})
	}
}

func TestGuardedNativeClearHumanHoldSecondRecordFailureRollsBackRemovalAndFirstRecord(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	mutator, request := guardedClearanceRequest(t, ctx, store)
	before := guardedNativeObserve(t, ctx, store)
	fault := &guardedClearanceInsertFault{key: "kv." + request.Effect.HistoryKey}
	connector := guardedReleaseCommentConnector(t, store)
	original := store.db
	store.db = sql.OpenDB(guardedClearanceFaultConnector{Connector: connector, fault: fault})
	store.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := mutator.Apply(ctx, request)
	if !errors.Is(err, errGuardedClearanceInsertFault) || result.Outcome != "refused" || result.ResultJSON != "" || result.Replayed || fault.calls.Load() != 1 || !fault.tentativeRemovalAndRecord || fault.base.commits.Load() != 0 {
		t.Fatalf("actual second record fault did not roll back once: %+v err=%v calls=%d tentative=%v commits=%d", result, err, fault.calls.Load(), fault.tentativeRemovalAndRecord, fault.base.commits.Load())
	}
	guardedClearanceRequireRefused(t, ctx, store, mutator, request, before, true)
	for _, key := range []string{request.Effect.ClearanceKey, request.Effect.HistoryKey} {
		var count int
		if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key`=?", "kv."+key).Scan(&count); err != nil || count != 0 {
			t.Fatalf("rolled-back record survived: %s count=%d err=%v", key, count, err)
		}
	}
}

func TestGuardedNativeClearHumanHoldAckLossIsRecoveredByOriginalOperation(t *testing.T) {
	ctx, writer, cfg := guardedNativeStore(t)
	mutator, request := guardedClearanceRequest(t, ctx, writer)
	before := guardedNativeObserve(t, ctx, writer)
	fault := &guardedNativeCommitAckFault{}
	original := writer.db
	writer.db = sql.OpenDB(guardedNativeCommitAckConnector{Connector: guardedReleaseCommentConnector(t, writer), fault: fault})
	writer.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := mutator.Apply(ctx, request)
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrCommitIndeterminate) || result.Outcome != "unknown" || result.ResultJSON != "" || result.Replayed || fault.commitCalls.Load() != 1 || fault.successfulCommits.Load() != 1 {
		t.Fatalf("real SQL acknowledgement loss was not unknown: %+v err=%v", result, err)
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
	resolved, err := recovery.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: request.OperationID, RequestDigest: guardops.Digest(request)})
	if err != nil || resolved.Outcome != "applied" {
		t.Fatalf("fresh lookup failed: %+v err=%v", resolved, err)
	}
	after := guardedClearanceRequireApplied(t, ctx, fresh, request, resolved, before)
	replay, err := recovery.Apply(ctx, request)
	if err != nil || !replay.Replayed || replay.ResultJSON != resolved.ResultJSON || guardedNativeObserve(t, ctx, fresh) != after || fault.commitCalls.Load() != 1 {
		t.Fatalf("unknown recovery repeated effect: %+v err=%v", replay, err)
	}
}

func guardedClearanceRequireApplied(t *testing.T, ctx context.Context, store *DoltStore, r guardops.Request, result guardops.Result, before guardedNativeObservation) guardedNativeObservation {
	t.Helper()
	after := guardedNativeObserve(t, ctx, store)
	if after.Assignee != before.Assignee || after.Status != before.Status || after.Started != before.Started || after.RowVersion != before.RowVersion || after.LeaseJSON != before.LeaseJSON || after.Unclaimed != before.Unclaimed || after.Operations != 1 || after.Token == before.Token || after.Head == before.Head || after.Commits != before.Commits+1 {
		t.Fatalf("clearance changed claim or failed single publication: before=%+v after=%+v", before, after)
	}
	labels, err := store.GetLabels(ctx, r.Expected.IssueID)
	if err != nil || len(labels) != 1 || labels[0] != "standing" {
		t.Fatalf("clearance removed other labels or retained hold: %v err=%v", labels, err)
	}
	var removed int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='label_removed' AND actor=? AND comment='Removed label: human-required'", r.Expected.IssueID, r.Actor).Scan(&removed); err != nil || removed != 1 {
		t.Fatalf("native removal event missing/repeated: count=%d err=%v", removed, err)
	}
	for _, record := range []struct{ key, value string }{{r.Effect.ClearanceKey, r.Effect.ClearanceValue}, {r.Effect.HistoryKey, r.Effect.HistoryValue}} {
		var raw, headRaw string
		if err := store.db.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+record.key).Scan(&raw); err != nil || raw != record.value {
			t.Fatalf("exact prospective record missing: %s err=%v", record.key, err)
		}
		if err := store.db.QueryRowContext(ctx, "SELECT value FROM config AS OF 'HEAD' WHERE `key`=?", "kv."+record.key).Scan(&headRaw); err != nil || headRaw != record.value {
			t.Fatalf("same native HEAD missing record: %s err=%v", record.key, err)
		}
	}
	var held int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels AS OF 'HEAD' WHERE issue_id=? AND label='human-required'", r.Expected.IssueID).Scan(&held); err != nil || held != 0 {
		t.Fatalf("native HEAD did not clear hold: count=%d err=%v", held, err)
	}
	var outcome struct {
		IssueID         string `json:"issueId"`
		Cleared         bool   `json:"cleared"`
		MaterialVersion string `json:"materialVersion"`
		HistoryComplete *bool  `json:"historyComplete"`
	}
	if err := json.Unmarshal([]byte(result.ResultJSON), &outcome); err != nil || outcome.IssueID != r.Expected.IssueID || !outcome.Cleared || outcome.MaterialVersion != "original-material-fingerprint" || outcome.HistoryComplete == nil || *outcome.HistoryComplete {
		t.Fatalf("clearance invented complete history or lost identity: %+v err=%v", outcome, err)
	}
	var saved, token string
	if err := store.db.QueryRowContext(ctx, "SELECT result_json FROM bd_guard_operations AS OF 'HEAD' WHERE operation_id=?", r.OperationID).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	var ledger guardops.Result
	if err := json.Unmarshal([]byte(saved), &ledger); err != nil || ledger.ResultJSON != result.ResultJSON || ledger.RequestDigest != guardops.Digest(r) || ledger.Outcome != "applied" {
		t.Fatalf("same HEAD lacks original ledger: %+v err=%v", ledger, err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT token FROM bd_guard_state AS OF 'HEAD' WHERE id=1").Scan(&token); err != nil || token != after.Token {
		t.Fatalf("same HEAD lacks token: %q err=%v", token, err)
	}
	return after
}

func guardedClearanceRequireRefused(t *testing.T, ctx context.Context, store *DoltStore, mutator guardops.Mutator, r guardops.Request, before guardedNativeObservation, held bool) {
	t.Helper()
	if after := guardedNativeObserve(t, ctx, store); after != before {
		t.Fatalf("refusal changed native effects/ledger/token/history: before=%+v after=%+v", before, after)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id=? AND label='human-required'", r.Expected.IssueID).Scan(&count); err != nil || (count == 1) != held {
		t.Fatalf("refusal changed hold: count=%d err=%v", count, err)
	}
	wantRemoved := 0
	if !held {
		wantRemoved = 1 // deliberate ordinary RemoveLabel fixture before capture
	}
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='label_removed'", r.Expected.IssueID).Scan(&count); err != nil || count != wantRemoved {
		t.Fatalf("refusal leaked removal event: count=%d want=%d err=%v", count, wantRemoved, err)
	}
	lookup, err := mutator.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: guardops.Digest(r)})
	if err != nil || lookup.Outcome != "absent" {
		t.Fatalf("refusal left ledger: %+v err=%v", lookup, err)
	}
}

var errGuardedClearanceInsertFault = errors.New("private native second-clearance-record fault")

type guardedClearanceInsertFault struct {
	key                       string
	calls                     atomic.Int32
	tentativeRemovalAndRecord bool
	base                      guardedReleaseCommentFault
}
type guardedClearanceFaultConnector struct {
	driver.Connector
	fault *guardedClearanceInsertFault
}

func (c guardedClearanceFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &guardedClearanceFaultConn{guardedReleaseCommentFaultConn: &guardedReleaseCommentFaultConn{Conn: conn, fault: &c.fault.base}, fault: c.fault}, nil
}

type guardedClearanceFaultConn struct {
	*guardedReleaseCommentFaultConn
	fault *guardedClearanceInsertFault
}

func (c *guardedClearanceFaultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if query == "REPLACE INTO config (`key`, value) VALUES (?, ?)" && len(args) == 2 && args[0].Value == c.fault.key {
		c.fault.calls.Add(1)
		rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, "SELECT (SELECT COUNT(*) FROM labels WHERE issue_id='guard-target' AND label='human-required'),(SELECT COUNT(*) FROM config WHERE `key` LIKE 'kv.krewe.audit.v1.%')", nil)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		values := make([]driver.Value, 2)
		if err := rows.Next(values); err != nil {
			return nil, err
		}
		text := func(v driver.Value) string {
			if b, ok := v.([]byte); ok {
				return string(b)
			}
			return fmt.Sprint(v)
		}
		c.fault.tentativeRemovalAndRecord = text(values[0]) == "0" && text(values[1]) == "1"
		return nil, errGuardedClearanceInsertFault
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}
