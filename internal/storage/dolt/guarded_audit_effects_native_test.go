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
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steveyegge/beads/guardops"
)

const guardedNativeFailureComment = "bead-audit-result\n\n```json\n{\"outcome\":\"failed\",\"materialVersion\":\"original-material\",\"planVersion\":null,\"repository\":\"origin/repo\",\"reviewedSha\":\"pinned-sha\",\"scope\":\"bead\",\"findings\":[\"Review failed λ `command  --exact`\\n\"]}\n```\n\nFailure evidence only, no validation receipt."

func guardedAuditFailureRequest(t *testing.T, ctx context.Context, s *DoltStore) (guardops.Mutator, guardops.Request) {
	t.Helper()
	m, r := guardedAuditRequest(t, ctx, s, "validate")
	r.OperationID = "native-audit-failure-comment"
	r.Effect = guardops.Effect{Kind: "audit-comment", Comment: guardedNativeFailureComment}
	return m, r
}

func TestGuardedNativeAuditFailureCommentPublishesOnceWithoutReceiptOrLifecycle(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedAuditFailureRequest(t, ctx, s)
	before := guardedNativeObserve(t, ctx, s)
	issue, err := s.GetIssue(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if err != nil || result.Outcome != "applied" {
		t.Fatalf("failure comment did not publish: %+v %v", result, err)
	}
	after := guardedNativeObserve(t, ctx, s)
	guardedAuditRequireLifecycle(t, before, after, false)
	if after.Operations != 1 || after.Commits != before.Commits+1 || after.Head == before.Head || after.Token == before.Token {
		t.Fatal("explanation/comment/ledger/token/history not atomic")
	}
	current, err := s.GetIssue(ctx, r.Expected.IssueID)
	if err != nil || !reflect.DeepEqual(current, issue) {
		t.Fatalf("failure comment changed native issue row/recency/material: before=%+v after=%+v %v", issue, current, err)
	}
	var native struct {
		IssueID   string `json:"issueId"`
		Commented bool   `json:"commented"`
		CommentID string `json:"commentId"`
	}
	if err := json.Unmarshal([]byte(result.ResultJSON), &native); err != nil || native.IssueID != r.Expected.IssueID || !native.Commented || native.CommentID == "" {
		t.Fatalf("failure comment result missing actual comment identity: %+v %v", native, err)
	}
	comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
	if err != nil || len(comments) != 1 || comments[0].ID != native.CommentID || comments[0].Text != r.Effect.Comment || comments[0].Author != r.Actor {
		t.Fatalf("exact failure comment lost: %+v %v", comments, err)
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key` LIKE 'kv.krewe.audit.v1.%'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failure explanation minted an audit record: %d %v", count, err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='commented' AND CAST(comment AS BINARY)=CAST(? AS BINARY)", r.Expected.IssueID, r.Effect.Comment).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failure comment event text lost: %d %v", count, err)
	}
	var published string
	if err := s.db.QueryRowContext(ctx, "SELECT text FROM comments AS OF 'HEAD' WHERE id=?", native.CommentID).Scan(&published); err != nil || published != r.Effect.Comment {
		t.Fatalf("failure comment not in native publication: %q %v", published, err)
	}
	replay, err := m.Apply(ctx, r)
	if err != nil || !replay.Replayed || replay.ResultJSON != result.ResultJSON || guardedNativeObserve(t, ctx, s) != after {
		t.Fatal("failure comment replay repeated native effects/history")
	}
}

func TestGuardedNativeAuditFailureCommentEventFailureRollsBack(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedAuditFailureRequest(t, ctx, s)
	before := guardedNativeObserve(t, ctx, s)
	fault := &guardedReleaseCommentFault{phase: "comment event"}
	original := s.db
	s.db = sql.OpenDB(guardedReleaseCommentFaultConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if !errors.Is(err, errGuardedReleaseCommentFault) || result.Outcome != "refused" || fault.failures.Load() != 1 || fault.tentativeComments != "1" || fault.commits.Load() != 0 || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("tentative structured failure comment not rolled back: %+v %v %+v", result, err, fault)
	}
	comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
	if err != nil || len(comments) != 0 {
		t.Fatal("failure comment survived failed event insert")
	}
}

func TestGuardedNativeAuditFailureCommentAckLossLookupWithoutReplay(t *testing.T) {
	ctx, s, cfg := guardedNativeStore(t)
	m, r := guardedAuditFailureRequest(t, ctx, s)
	fault := &guardedNativeCommitAckFault{}
	original := s.db
	s.db = sql.OpenDB(guardedNativeCommitAckConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	unknown, err := m.Apply(ctx, r)
	if !errors.Is(err, io.ErrUnexpectedEOF) || unknown.Outcome != "unknown" || fault.commitCalls.Load() != 1 {
		t.Fatalf("failure comment ack loss lost uncertainty/commit-once: %+v %v", unknown, err)
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
		t.Fatalf("failure comment original lookup unresolved: %+v %v", found, err)
	}
	after := guardedNativeObserve(t, ctx, fresh)
	comments, err := fresh.GetIssueComments(ctx, r.Expected.IssueID)
	if err != nil || len(comments) != 1 || comments[0].Text != r.Effect.Comment {
		t.Fatal("unknown failure comment not actually published once")
	}
	replay, err := recovery.Apply(ctx, r)
	if err != nil || !replay.Replayed || replay.ResultJSON != found.ResultJSON || guardedNativeObserve(t, ctx, fresh) != after || fault.commitCalls.Load() != 1 {
		t.Fatal("failure comment lookup/replay repeated native effects")
	}
}

func TestGuardedNativeAuditFailureCommentRefusesClaimAndStaleMaterial(t *testing.T) {
	for _, cause := range []string{"claim", "stale material"} {
		t.Run(cause, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			m, r := guardedAuditFailureRequest(t, ctx, s)
			want := "conflict"
			if cause == "claim" {
				if err := s.ClaimIssue(ctx, r.Expected.IssueID, "competing owner"); err != nil {
					t.Fatal(err)
				}
				var err error
				r.Expected, err = m.Capture(ctx, r.Expected.IssueID)
				if err != nil {
					t.Fatal(err)
				}
				want = "refused"
			} else if err := s.UpdateIssue(ctx, r.Expected.IssueID, map[string]interface{}{"description": "ordinary changed material"}, r.Actor); err != nil {
				t.Fatal(err)
			}
			before := guardedNativeObserve(t, ctx, s)
			result, err := m.Apply(ctx, r)
			if err == nil || result.Outcome != want || guardedNativeObserve(t, ctx, s) != before {
				t.Fatalf("unsafe failure comment wrote evidence: %+v %v", result, err)
			}
			comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
			if err != nil || len(comments) != 0 {
				t.Fatal("refused failure explanation left comment")
			}
		})
	}
}

func guardedAuditRecord(t *testing.T, ns string, value any) guardops.AuditRecord {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"version": 1, "namespace": ns, "value": value})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	return guardops.AuditRecord{Key: "krewe.audit.v1." + ns + "." + hex.EncodeToString(hash[:]), Value: string(raw)}
}
func guardedAuditRequest(t *testing.T, ctx context.Context, s *DoltStore, kind string) (guardops.Mutator, guardops.Request) {
	t.Helper()
	m, r := guardedNativeSeed(t, ctx, s)
	if err := s.UnclaimIssue(ctx, r.Expected.IssueID, r.Actor, false); err != nil {
		t.Fatal(err)
	}
	var err error
	r.Expected, err = m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	r.OperationID = "native-audit-" + kind
	record := guardedAuditRecord(t, strings.Repeat("a", 64), map[string]any{"repository": "origin/repo", "reviewedSha": "pinned-reviewed-sha", "materialVersion": "accepted-material", "planVersion": nil, "scope": "bead", "outcome": "success", "recordedAt": "2026-10-10T12:34:56.000Z"})
	raw, _ := json.Marshal([]guardops.AuditRecord{record})
	r.Effect = guardops.Effect{Kind: kind, ReceiptRecordsJSON: string(raw)}
	if kind == "archive-replace" {
		r.Effect.ArchiveComment = "bead-audit-archive\n2026-10-10T12:34:56.000Z\n\noriginal material"
		r.Effect.AcceptedDescription = "accepted λ `exact  --command`\n"
	}
	return m, r
}
func guardedAuditRequireRecords(t *testing.T, ctx context.Context, s *DoltStore, r guardops.Request) {
	t.Helper()
	records, err := guardops.DecodeAuditReceiptRecords(r.Effect.ReceiptRecordsJSON)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		for _, suffix := range []string{"", " AS OF 'HEAD'"} {
			var value string
			if err := s.db.QueryRowContext(ctx, "SELECT value FROM config"+suffix+" WHERE `key`=?", "kv."+record.Key).Scan(&value); err != nil || value != record.Value {
				t.Fatalf("receipt not exact/published: %q err=%v", value, err)
			}
		}
	}
}
func guardedAuditRequireLifecycle(t *testing.T, before, after guardedNativeObservation, allowMaterial bool) {
	t.Helper()
	if after.Assignee != before.Assignee || after.Status != before.Status || after.Started != before.Started || after.LeaseJSON != before.LeaseJSON || after.Unclaimed != before.Unclaimed || (!allowMaterial && after.RowVersion != before.RowVersion) {
		t.Fatalf("audit mutated lifecycle/lease: before=%+v after=%+v", before, after)
	}
}
func TestGuardedNativeAuditArchiveReplaceAndValidatePublishOnce(t *testing.T) {
	for _, kind := range []string{"archive-replace", "validate"} {
		t.Run(kind, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			m, r := guardedAuditRequest(t, ctx, s, kind)
			before := guardedNativeObserve(t, ctx, s)
			original, err := s.GetIssue(ctx, r.Expected.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			result, err := m.Apply(ctx, r)
			if err != nil || result.Outcome != "applied" {
				t.Fatalf("audit effect: %+v err=%v", result, err)
			}
			after := guardedNativeObserve(t, ctx, s)
			guardedAuditRequireLifecycle(t, before, after, kind == "archive-replace")
			if after.Head == before.Head || after.Token == before.Token || after.Commits != before.Commits+1 || after.Operations != 1 {
				t.Fatalf("audit lacks one atomic history/ledger/token: %+v %+v", before, after)
			}
			issue, err := s.GetIssue(ctx, r.Expected.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			want := original.Description
			if kind == "archive-replace" {
				want = r.Effect.AcceptedDescription
			}
			if issue.Description != want || issue.AcceptanceCriteria != original.AcceptanceCriteria || issue.ExternalRef != original.ExternalRef {
				t.Fatalf("description/material result wrong: %+v", issue)
			}
			if kind == "validate" && !issue.UpdatedAt.Equal(original.UpdatedAt) {
				t.Fatal("no-op validation advanced native recency")
			}
			comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "archive-replace" {
				if len(comments) != 1 || comments[0].Text != r.Effect.ArchiveComment || comments[0].Author != r.Actor {
					t.Fatalf("exact original archive missing: %+v", comments)
				}
			} else if len(comments) != 0 {
				t.Fatal("no-op manufactured archive")
			}
			guardedAuditRequireRecords(t, ctx, s, r)
			replay, err := m.Apply(ctx, r)
			if err != nil || !replay.Replayed || replay.ResultJSON != result.ResultJSON || guardedNativeObserve(t, ctx, s) != after {
				t.Fatalf("audit replay changed effects: %+v %v", replay, err)
			}
		})
	}
}
func TestGuardedNativeAuditRefusesStaleOrdinaryWritersAndWrongArchive(t *testing.T) {
	for _, cause := range []string{"material", "routing", "clearance KV", "wrong original archive", "existing receipt"} {
		t.Run(cause, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			m, r := guardedAuditRequest(t, ctx, s, "archive-replace")
			switch cause {
			case "material":
				if err := s.UpdateIssue(ctx, r.Expected.IssueID, map[string]interface{}{"acceptance_criteria": "concurrent acceptance"}, r.Actor); err != nil {
					t.Fatal(err)
				}
			case "routing":
				if err := s.AddLabel(ctx, r.Expected.IssueID, "agent=changed", r.Actor); err != nil {
					t.Fatal(err)
				}
			case "clearance KV":
				if err := s.SetConfig(ctx, "kv.krewe.audit.v1.concurrent-clearance", "unknown"); err != nil {
					t.Fatal(err)
				}
			case "wrong original archive":
				r.Effect.ArchiveComment += " altered"
			case "existing receipt":
				records, _ := guardops.DecodeAuditReceiptRecords(r.Effect.ReceiptRecordsJSON)
				if err := s.SetConfig(ctx, "kv."+records[0].Key, records[0].Value); err != nil {
					t.Fatal(err)
				}
				r.Expected, _ = m.Capture(ctx, r.Expected.IssueID)
			}
			before := guardedNativeObserve(t, ctx, s)
			result, err := m.Apply(ctx, r)
			want := "conflict"
			if cause == "wrong original archive" || cause == "existing receipt" {
				want = "refused"
			}
			if err == nil || result.Outcome != want || guardedNativeObserve(t, ctx, s) != before {
				t.Fatalf("unsafe audit accepted or changed state: %+v %v", result, err)
			}
			comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
			if err != nil || len(comments) != 0 {
				t.Fatalf("refusal left archive: %+v %v", comments, err)
			}
		})
	}
}

var errGuardedAuditFault = errors.New("private audit receipt insertion fault")

type guardedAuditFault struct {
	key        string
	expectHold bool
	calls      atomic.Int32
	tentative  bool
	base       guardedReleaseCommentFault
}
type guardedAuditFaultConnector struct {
	driver.Connector
	fault *guardedAuditFault
}

func (c guardedAuditFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &guardedAuditFaultConn{guardedReleaseCommentFaultConn: &guardedReleaseCommentFaultConn{Conn: conn, fault: &c.fault.base}, fault: c.fault}, nil
}

type guardedAuditFaultConn struct {
	*guardedReleaseCommentFaultConn
	fault *guardedAuditFault
}

func (c *guardedAuditFaultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "REPLACE INTO config (`key`, value) VALUES (?, ?)" && len(args) == 2 && args[0].Value == c.fault.key {
		c.fault.calls.Add(1)
		rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, "SELECT description,(SELECT COUNT(*) FROM comments WHERE issue_id='guard-target'),(SELECT COUNT(*) FROM labels WHERE issue_id='guard-target' AND label='human-required') FROM issues WHERE id='guard-target'", nil)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		values := make([]driver.Value, 3)
		if err := rows.Next(values); err != nil {
			return nil, err
		}
		text := func(v driver.Value) string {
			if b, ok := v.([]byte); ok {
				return string(b)
			}
			return fmt.Sprint(v)
		}
		c.fault.tentative = text(values[0]) == "accepted λ `exact  --command`\n" && text(values[1]) == "1"
		if c.fault.expectHold {
			c.fault.tentative = text(values[2]) == "1"
		}
		return nil, errGuardedAuditFault
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func guardedAuditHoldRequest(t *testing.T, ctx context.Context, s *DoltStore, cause string) (guardops.Mutator, guardops.Request) {
	t.Helper()
	m, clear := guardedClearanceRequest(t, ctx, s)
	result, err := m.Apply(ctx, clear)
	if err != nil || result.Outcome != "applied" {
		t.Fatalf("positive identified native clearance setup: %+v %v", result, err)
	}
	if err := s.UnclaimIssue(ctx, clear.Expected.IssueID, clear.Actor, false); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateIssue(ctx, clear.Expected.IssueID, map[string]interface{}{"description": "material changed after identified clearance"}, clear.Actor); err != nil {
		t.Fatal(err)
	}
	if cause == "manual clear" {
		if err := s.AddLabel(ctx, clear.Expected.IssueID, "human-required", "ordinary human"); err != nil {
			t.Fatal(err)
		}
		if err := s.RemoveLabel(ctx, clear.Expected.IssueID, "human-required", "ordinary human"); err != nil {
			t.Fatal(err)
		}
	}
	if cause == "unknown clearance" {
		if err := s.SetConfig(ctx, "kv.krewe.audit.v1."+strings.Repeat("a", 64)+"."+strings.Repeat("0", 64), "malformed newer evidence"); err != nil {
			t.Fatal(err)
		}
	}
	if cause == "legacy linkage" {
		var saved guardops.Result
		_ = json.Unmarshal([]byte(stringMustAuditQuery(t, ctx, s, "SELECT result_json FROM bd_guard_operations WHERE operation_id=?", clear.OperationID)), &saved)
		var old map[string]any
		_ = json.Unmarshal([]byte(saved.ResultJSON), &old)
		delete(old, "removalEventId")
		raw, _ := json.Marshal(old)
		saved.ResultJSON = string(raw)
		raw, _ = json.Marshal(saved)
		if _, err := s.db.ExecContext(ctx, "UPDATE bd_guard_operations SET result_json=? WHERE operation_id=?", string(raw), clear.OperationID); err != nil {
			t.Fatal(err)
		}
		if err := s.Commit(ctx, "private legacy linkage fixture"); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := m.Capture(ctx, clear.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Value guardops.AuditClearance `json:"value"`
	}
	if err := json.Unmarshal([]byte(clear.Effect.ClearanceValue), &c); err != nil {
		t.Fatal(err)
	}
	var state struct {
		Config []map[string]*string `json:"config"`
	}
	if err := json.Unmarshal([]byte(expected.StateJSON), &state); err != nil {
		t.Fatal(err)
	}
	matching := [][2]string{}
	for _, row := range state.Config {
		key, value := row["key"], row["value"]
		if key != nil && value != nil && strings.HasPrefix(*key, "kv.krewe.audit.v1."+strings.Repeat("a", 64)+".") {
			matching = append(matching, [2]string{strings.TrimPrefix(*key, "kv."), *value})
		}
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i][0] < matching[j][0] })
	raw, _ := json.Marshal(matching)
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	r := clear
	r.Expected = expected
	r.OperationID = "native-audit-rehold"
	v := map[string]any{"kind": "bounded-unworkable-hold", "operationId": r.OperationID, "guardGeneration": expected.Generation, "originalToken": expected.Token, "actor": r.Actor, "heldAt": "2026-10-10T13:00:00Z", "materialVersion": "changed-material-fingerprint", "clearanceNamespace": strings.Repeat("a", 64), "clearanceContentDigest": digest, "baseline": "unknown-legacy", "historyComplete": false, "clearance": c.Value}
	record := guardedAuditRecord(t, strings.Repeat("b", 64), v)
	r.Effect = guardops.Effect{Kind: "add-human-hold", MaterialVersion: "changed-material-fingerprint", ClearanceNamespace: strings.Repeat("a", 64), ClearanceContentDigest: digest, HoldRecordKey: record.Key, HoldRecordValue: record.Value}
	return m, r
}
func stringMustAuditQuery(t *testing.T, ctx context.Context, s *DoltStore, q string, args ...any) string {
	t.Helper()
	var value string
	if err := s.db.QueryRowContext(ctx, q, args...).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestGuardedNativeAuditIdentifiedClearMaterialChangeAndRehold(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedAuditHoldRequest(t, ctx, s, "")
	before := guardedNativeObserve(t, ctx, s)
	issue, err := s.GetIssue(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if err != nil || result.Outcome != "applied" {
		t.Fatalf("positive native provenance did not admit bounded rehold: %+v %v", result, err)
	}
	after := guardedNativeObserve(t, ctx, s)
	guardedAuditRequireLifecycle(t, before, after, false)
	if after.Operations != before.Operations+1 || after.Commits != before.Commits+1 || after.Head == before.Head || after.Token == before.Token {
		t.Fatal("hold/evidence/ledger/token/history not published together")
	}
	current, err := s.GetIssue(ctx, r.Expected.IssueID)
	if err != nil || current.Description != issue.Description || !current.UpdatedAt.Equal(issue.UpdatedAt) || current.ExternalRef != issue.ExternalRef {
		t.Fatal("hold changed native material/recency")
	}
	labels, err := s.GetLabels(ctx, r.Expected.IssueID)
	if err != nil || len(labels) != 2 || labels[0] != "human-required" || labels[1] != "standing" {
		t.Fatalf("canonical hold changed other labels: %v %v", labels, err)
	}
	if raw := stringMustAuditQuery(t, ctx, s, "SELECT value FROM config AS OF 'HEAD' WHERE `key`=?", "kv."+r.Effect.HoldRecordKey); raw != r.Effect.HoldRecordValue {
		t.Fatal("same HEAD lacks exact prospective hold evidence")
	}
	var native struct {
		Held            bool  `json:"held"`
		HistoryComplete *bool `json:"historyComplete"`
	}
	if err := json.Unmarshal([]byte(result.ResultJSON), &native); err != nil || !native.Held || native.HistoryComplete == nil || *native.HistoryComplete {
		t.Fatal("native hold result fabricated complete history")
	}
	replay, err := m.Apply(ctx, r)
	if err != nil || !replay.Replayed || replay.ResultJSON != result.ResultJSON || guardedNativeObserve(t, ctx, s) != after {
		t.Fatal("rehold replay repeated labels/evidence/history")
	}
}
func TestGuardedNativeAuditHoldRefusesAmbiguousOrUnknownClearance(t *testing.T) {
	for _, cause := range []string{"manual clear", "unknown clearance", "legacy linkage"} {
		t.Run(cause, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			m, r := guardedAuditHoldRequest(t, ctx, s, cause)
			before := guardedNativeObserve(t, ctx, s)
			result, err := m.Apply(ctx, r)
			if err == nil || result.Outcome != "refused" || guardedNativeObserve(t, ctx, s) != before {
				t.Fatalf("ambiguous evidence admitted rehold: %+v %v", result, err)
			}
			var held int
			if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id=? AND label='human-required'", r.Expected.IssueID).Scan(&held); err != nil || held != 0 {
				t.Fatal("refusal left new hold")
			}
		})
	}
}
func TestGuardedNativeAuditHoldEvidenceFailureRollsBackLabel(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedAuditHoldRequest(t, ctx, s, "")
	before := guardedNativeObserve(t, ctx, s)
	fault := &guardedAuditFault{key: "kv." + r.Effect.HoldRecordKey, expectHold: true}
	original := s.db
	s.db = sql.OpenDB(guardedAuditFaultConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if !errors.Is(err, errGuardedAuditFault) || result.Outcome != "refused" || fault.calls.Load() != 1 || !fault.tentative || fault.base.commits.Load() != 0 || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("tentative native hold not rolled back: %+v %v %+v", result, err, fault)
	}
	var held int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id=? AND label='human-required'", r.Expected.IssueID).Scan(&held); err != nil || held != 0 {
		t.Fatal("hold survived failed evidence append")
	}
}
func TestGuardedNativeAuditReceiptFailureRollsBackArchiveAndReplacement(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedAuditRequest(t, ctx, s, "archive-replace")
	records, _ := guardops.DecodeAuditReceiptRecords(r.Effect.ReceiptRecordsJSON)
	fault := &guardedAuditFault{key: "kv." + records[0].Key}
	before := guardedNativeObserve(t, ctx, s)
	original := s.db
	s.db = sql.OpenDB(guardedAuditFaultConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if !errors.Is(err, errGuardedAuditFault) || result.Outcome != "refused" || fault.calls.Load() != 1 || !fault.tentative || fault.base.commits.Load() != 0 {
		t.Fatalf("fault did not prove actual tentative archive+replacement: %+v %v fault=%+v", result, err, fault)
	}
	if guardedNativeObserve(t, ctx, s) != before {
		t.Fatal("receipt failure changed lifecycle/ledger/token/history")
	}
	issue, err := s.GetIssue(ctx, r.Expected.IssueID)
	if err != nil || issue.Description != "original material" {
		t.Fatalf("replacement survived rollback: %+v %v", issue, err)
	}
	comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
	if err != nil || len(comments) != 0 {
		t.Fatal("archive survived receipt failure")
	}
}
func TestGuardedNativeAuditAckLossRecoversExactOriginalOperation(t *testing.T) {
	ctx, s, cfg := guardedNativeStore(t)
	m, r := guardedAuditRequest(t, ctx, s, "archive-replace")
	before := guardedNativeObserve(t, ctx, s)
	fault := &guardedNativeCommitAckFault{}
	original := s.db
	s.db = sql.OpenDB(guardedNativeCommitAckConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	unknown, err := m.Apply(ctx, r)
	if !errors.Is(err, io.ErrUnexpectedEOF) || unknown.Outcome != "unknown" || fault.commitCalls.Load() != 1 {
		t.Fatalf("ack loss did not preserve uncertainty: %+v %v", unknown, err)
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
		t.Fatalf("lookup did not resolve exact operation: %+v %v", found, err)
	}
	after := guardedNativeObserve(t, ctx, fresh)
	guardedAuditRequireLifecycle(t, before, after, true)
	guardedAuditRequireRecords(t, ctx, fresh, r)
	replay, err := recovery.Apply(ctx, r)
	if err != nil || !replay.Replayed || replay.ResultJSON != found.ResultJSON || guardedNativeObserve(t, ctx, fresh) != after || fault.commitCalls.Load() != 1 {
		t.Fatal("lookup/replay repeated archive/replacement")
	}
}

// The driver delegates every statement to the actual private MySQL session.
// Only the first immutable receipt insertion is paused, after native archive
// and replacement writes have already occurred inside the losing transaction.
type guardedAuditConcurrentGate struct {
	key, accepted string
	entered       chan struct{}
	resume        chan struct{}
	release       sync.Once
	calls         atomic.Int32
	tentative     bool
	base          guardedReleaseCommentFault
}

func (g *guardedAuditConcurrentGate) unblock() { g.release.Do(func() { close(g.resume) }) }

type guardedAuditConcurrentConnector struct {
	driver.Connector
	gate *guardedAuditConcurrentGate
}

func (c guardedAuditConcurrentConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &guardedAuditConcurrentConn{guardedReleaseCommentFaultConn: &guardedReleaseCommentFaultConn{Conn: conn, fault: &c.gate.base}, gate: c.gate}, nil
}

type guardedAuditConcurrentConn struct {
	*guardedReleaseCommentFaultConn
	gate *guardedAuditConcurrentGate
}

func (c *guardedAuditConcurrentConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "REPLACE INTO config (`key`, value) VALUES (?, ?)" && len(args) == 2 && args[0].Value == c.gate.key && c.gate.calls.Add(1) == 1 {
		rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, "SELECT description,assignee,status,(SELECT COUNT(*) FROM comments WHERE issue_id='guard-target') FROM issues WHERE id='guard-target'", nil)
		if err != nil {
			return nil, err
		}
		values := make([]driver.Value, 4)
		readErr := rows.Next(values)
		closeErr := rows.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		text := func(v driver.Value) string {
			if b, ok := v.([]byte); ok {
				return string(b)
			}
			return fmt.Sprint(v)
		}
		c.gate.tentative = text(values[0]) == c.gate.accepted && text(values[1]) == "" && text(values[2]) == "open" && text(values[3]) == "1"
		close(c.gate.entered)
		select {
		case <-c.gate.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}

func TestGuardedNativeAuditConcurrentOrdinaryWriterWins(t *testing.T) {
	ctx, protected, cfg := guardedNativeStore(t)
	// Open the independent ordinary native client before capture/initialization,
	// so constructor maintenance cannot be mistaken for the racing writer.
	ordinaryCfg := *cfg
	ordinaryCfg.CreateIfMissing = false
	ordinary, err := New(ctx, &ordinaryCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ordinary.Close() })
	mutator, request := guardedAuditRequest(t, ctx, protected, "archive-replace")
	records, err := guardops.DecodeAuditReceiptRecords(request.Effect.ReceiptRecordsJSON)
	if err != nil {
		t.Fatal(err)
	}
	before := guardedNativeObserve(t, ctx, ordinary)
	gate := &guardedAuditConcurrentGate{key: "kv." + records[0].Key, accepted: request.Effect.AcceptedDescription, entered: make(chan struct{}), resume: make(chan struct{})}
	originalDB := protected.db
	protected.db = sql.OpenDB(guardedAuditConcurrentConnector{Connector: guardedReleaseCommentConnector(t, protected), gate: gate})
	protected.db.SetMaxOpenConns(1)
	if err := originalDB.Close(); err != nil {
		t.Fatal(err)
	}
	applyCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	type applyResult struct {
		result guardops.Result
		err    error
	}
	done := make(chan applyResult, 1)
	finished := false
	defer func() {
		gate.unblock()
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("protected native Apply did not terminate after cancellation")
			}
		}
	}()
	go func() {
		result, err := mutator.Apply(applyCtx, request)
		done <- applyResult{result, err}
	}()
	select {
	case <-gate.entered:
		if !gate.tentative {
			t.Fatal("race boundary lacks actual tentative archive+replacement and unchanged unclaimed lifecycle")
		}
	case early := <-done:
		finished = true
		t.Fatalf("Apply never reached in-transaction race boundary: %+v %v", early.result, early.err)
	case <-applyCtx.Done():
		t.Fatal("timed out reaching in-transaction race boundary")
	}
	const winnerDescription = "ordinary writer material wins λ `literal --command`\n"
	if err := ordinary.UpdateIssue(applyCtx, request.Expected.IssueID, map[string]interface{}{"description": winnerDescription}, "ordinary competing writer"); err != nil {
		t.Fatalf("independent ordinary native writer did not commit while guarded Apply was paused: %v", err)
	}
	winner := guardedNativeObserve(t, ctx, ordinary)
	guardedAuditRequireLifecycle(t, before, winner, true)
	if winner.Head == before.Head || winner.Token == before.Token || winner.Commits != before.Commits+1 || winner.Operations != 0 {
		t.Fatalf("ordinary writer lacks its own native history/token: before=%+v winner=%+v", before, winner)
	}
	recovery, err := ordinary.GuardedMutator()
	if err != nil {
		t.Fatal(err)
	}
	winnerSnapshot, err := recovery.Capture(ctx, request.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	gate.unblock()
	var applied applyResult
	select {
	case applied = <-done:
		finished = true
	case <-applyCtx.Done():
		t.Fatal("guarded Apply did not resolve after ordinary writer committed")
	}
	if applied.err == nil || (applied.result.Outcome != "conflict" && applied.result.Outcome != "unknown") || gate.calls.Load() != 1 {
		t.Fatalf("losing guarded transaction was applied/replayed or misreported: %+v %v calls=%d", applied.result, applied.err, gate.calls.Load())
	}
	found, err := recovery.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: request.OperationID, RequestDigest: guardops.Digest(request)})
	if err != nil || found.Outcome != "absent" {
		t.Fatalf("lookup resolved a losing operation as durable: %+v %v", found, err)
	}
	afterSnapshot, err := recovery.Capture(ctx, request.Expected.IssueID)
	if err != nil || afterSnapshot != winnerSnapshot || guardedNativeObserve(t, ctx, ordinary) != winner {
		t.Fatalf("losing transaction leaked native effects/history/token beyond ordinary winner: snapshotEqual=%v err=%v", afterSnapshot == winnerSnapshot, err)
	}
	issue, err := ordinary.GetIssue(ctx, request.Expected.IssueID)
	if err != nil || issue.Description != winnerDescription {
		t.Fatalf("ordinary winner material lost: %+v %v", issue, err)
	}
	comments, err := ordinary.GetIssueComments(ctx, request.Expected.IssueID)
	if err != nil || len(comments) != 0 {
		t.Fatalf("losing archive survived: %+v %v", comments, err)
	}
	var leaked int
	if err := ordinary.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key`=?", gate.key).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("losing immutable receipt survived: count=%d err=%v", leaked, err)
	}
	if err := ordinary.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='commented'", request.Expected.IssueID).Scan(&leaked); err != nil || leaked != 0 {
		t.Fatalf("losing native archive event survived: count=%d err=%v", leaked, err)
	}
}
