package dolt

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/steveyegge/beads/guardops"
)

func guardedLinkedExplanation(t *testing.T, ctx context.Context, s *DoltStore, kind string) (guardops.Mutator, guardops.ExplanationDeliverer, guardops.ExplanationRequest) {
	t.Helper()
	var m guardops.Mutator
	var original guardops.Request
	outcome, material := "success", "accepted-material"
	switch kind {
	case "add-initial-human-hold":
		if err := s.InitializeGuard(ctx); err != nil {
			t.Fatal(err)
		}
		guardedInitialCreate(t, ctx, s, "guard-target", true)
		m, original, _, _ = guardedInitialRequest(t, ctx, s, "guard-target")
		outcome, material = "partial", original.Effect.MaterialVersion
	case "add-human-hold":
		m, original = guardedAuditHoldRequest(t, ctx, s, "")
		outcome, material = "partial", original.Effect.MaterialVersion
	default:
		m, original = guardedAuditRequest(t, ctx, s, kind)
	}
	original.ContextJSON = `{"repository":"origin/repo","reviewedSha":"pinned-reviewed-sha","scope":"bead","materialVersion":"` + material + `"}`
	result, err := m.Apply(ctx, original)
	if err != nil || result.Outcome != "applied" {
		t.Fatalf("real original primary not applied: %+v %v", result, err)
	}
	current, err := m.Capture(ctx, original.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"outcome": outcome, "materialVersion": material, "planVersion": nil, "repository": "origin/repo", "reviewedSha": "pinned-reviewed-sha", "scope": "bead", "findings": []string{"exact linked explanation λ `command  --spacing`\n"}})
	request := guardops.ExplanationRequest{Protocol: guardops.ExplanationProtocol, OperationID: guardops.ExplanationOperationID(original.OperationID), OriginalRequest: original, Expected: current, Comment: "bead-audit-result\n\n```json\n" + string(body) + "\n```\n\nLinked result, not a second receipt."}
	role, err := s.GuardedExplanationDeliverer()
	if err != nil {
		t.Fatal(err)
	}
	return m, role, request
}
func guardedRequireOneExplanation(t *testing.T, ctx context.Context, s *DoltStore, r guardops.ExplanationRequest, result guardops.ExplanationResult) {
	t.Helper()
	comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, comment := range comments {
		if comment.Text == r.Comment {
			found++
			if comment.ID != result.CommentID || comment.Author != r.OriginalRequest.Actor {
				t.Fatal("exact linked comment identity/actor lost")
			}
		}
	}
	if found != 1 {
		t.Fatalf("linked result comment count=%d", found)
	}
	var events int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='commented' AND CAST(comment AS BINARY)=CAST(? AS BINARY)", r.Expected.IssueID, r.Comment).Scan(&events); err != nil || events != 1 {
		t.Fatal("linked comment event absent/repeated", events, err)
	}
	for _, suffix := range []string{"", " AS OF 'HEAD'"} {
		var body string
		if err := s.db.QueryRowContext(ctx, "SELECT text FROM comments"+suffix+" WHERE id=?", result.CommentID).Scan(&body); err != nil || body != r.Comment {
			t.Fatal("exact linked explanation not published", err)
		}
	}
}
func TestGuardedNativeLinkedExplanationAllPrimaryEffectsPublishAndHistoricalReplayOnce(t *testing.T) {
	for _, kind := range []string{"validate", "archive-replace", "add-human-hold", "add-initial-human-hold"} {
		t.Run(kind, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			m, role, r := guardedLinkedExplanation(t, ctx, s, kind)
			before := guardedAuditObserveNullable(t, ctx, s)
			issue, err := s.GetIssue(ctx, r.Expected.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			var recordsBefore int
			if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key` LIKE 'kv.krewe.audit.v1.%'").Scan(&recordsBefore); err != nil {
				t.Fatal(err)
			}
			result, err := role.Explain(ctx, r)
			if err != nil || result.Outcome != "applied" || result.Protocol != guardops.ExplanationProtocol || result.RequestDigest != guardops.ExplanationDigest(r) || result.CommentID == "" || result.Replayed {
				t.Fatalf("first linked delivery: %+v %v", result, err)
			}
			after := guardedAuditObserveNullable(t, ctx, s)
			current, err := s.GetIssue(ctx, r.Expected.IssueID)
			if err != nil || !reflect.DeepEqual(current, issue) {
				t.Fatal("delivery changed native material/recency/lifecycle", err)
			}
			if after.RowVersion != before.RowVersion || after.Status != before.Status || after.Assignee != before.Assignee || after.LeaseJSON != before.LeaseJSON || after.Unclaimed != before.Unclaimed || after.Operations != before.Operations+1 || after.Commits != before.Commits+1 || after.Head == before.Head || after.Token == before.Token {
				t.Fatal("delivery was not only comment/event/ledger/native publication")
			}
			var recordsAfter int
			if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key` LIKE 'kv.krewe.audit.v1.%'").Scan(&recordsAfter); err != nil || recordsAfter != recordsBefore {
				t.Fatal("delivery minted receipt/hold/clearance record", err)
			}
			guardedRequireOneExplanation(t, ctx, s, r, result)
			// Exact primary retry is lookup-only and retains the saved original clock.
			primary, err := m.Apply(ctx, r.OriginalRequest)
			if err != nil || !primary.Replayed || guardedAuditObserveNullable(t, ctx, s) != after {
				t.Fatal("primary retry performed another mutation", err)
			}
			if err := s.SetConfig(ctx, "kv.later-unrelated", "later"); err != nil {
				t.Fatal(err)
			}
			later := guardedAuditObserveNullable(t, ctx, s)
			// Historical delivery lookup/replay MUST precede its now-stale permission.
			replay, err := role.Explain(ctx, r)
			if err != nil || !replay.Replayed || replay.CommentID != result.CommentID || guardedAuditObserveNullable(t, ctx, s) != later {
				t.Fatalf("historical delivery repeated or required recapture: %+v %v", replay, err)
			}
			guardedRequireOneExplanation(t, ctx, s, r, result)
		})
	}
}
func TestGuardedNativeLinkedExplanationFixedIDRejectsDifferentBytes(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	_, role, r := guardedLinkedExplanation(t, ctx, s, "validate")
	original, err := role.Explain(ctx, r)
	if err != nil || original.Outcome != "applied" {
		t.Fatal("delivery setup", err)
	}
	before := guardedAuditObserveNullable(t, ctx, s)
	changed := r
	changed.Comment += " exact extra bytes"
	result, err := role.Explain(ctx, changed)
	if err != nil || result.Outcome != "request-mismatch" || result.RequestDigest != guardops.ExplanationDigest(changed) || result.CommentID != "" || guardedAuditObserveNullable(t, ctx, s) != before {
		t.Fatalf("changed bytes got another delivery: %+v %v", result, err)
	}
	changed.OperationID += "different"
	result, err = role.Explain(ctx, changed)
	if err == nil || result.Outcome != "refused" || guardedAuditObserveNullable(t, ctx, s) != before {
		t.Fatal("alternative ID minted another delivery")
	}
	guardedRequireOneExplanation(t, ctx, s, r, original)
}
func TestGuardedNativeLinkedExplanationRefusesEveryInterveningWriterAndOldBinding(t *testing.T) {
	for _, change := range []string{"unrelated KV", "material", "claim", "manual-clear", "generation", "old-binding", "ignored heartbeat"} {
		t.Run(change, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			kind := "validate"
			if change == "manual-clear" {
				kind = "add-initial-human-hold"
			}
			m, role, r := guardedLinkedExplanation(t, ctx, s, kind)
			switch change {
			case "unrelated KV":
				if err := s.SetConfig(ctx, "kv.unrelated", "intervening"); err != nil {
					t.Fatal(err)
				}
			case "material":
				if err := s.UpdateIssue(ctx, r.Expected.IssueID, map[string]interface{}{"description": "new material"}, "ordinary"); err != nil {
					t.Fatal(err)
				}
			case "claim":
				if err := s.ClaimIssue(ctx, r.Expected.IssueID, "new-owner"); err != nil {
					t.Fatal(err)
				}
			case "manual-clear":
				if err := s.RemoveLabel(ctx, r.Expected.IssueID, "human-required", "ordinary human"); err != nil {
					t.Fatal(err)
				}
			case "generation":
				// Generation reset is explicit maintenance, not an ordinary
				// bound writer (which correctly refuses changing its own CAS).
				if _, err := s.db.ExecContext(ctx, "UPDATE bd_guard_state SET generation=? WHERE id=1", strings.Repeat("f", 64)); err != nil {
					t.Fatal(err)
				}
			case "old-binding":
				if err := s.DeleteConfig(ctx, explanationBindingKey(r.OriginalRequest.OperationID)); err != nil {
					t.Fatal(err)
				}
			case "ignored heartbeat":
				if err := s.withWriteTx(ctx, func(tx *sql.Tx) error {
					_, err := tx.ExecContext(ctx, "INSERT INTO local_metadata (`key`,value) VALUES (?,?)", "native-explanation-negative", "ignored update")
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			var err error
			r.Expected, err = m.Capture(ctx, r.Expected.IssueID)
			if err != nil {
				t.Fatal(err)
			}
			before := guardedAuditObserveNullable(t, ctx, s)
			result, err := role.Explain(ctx, r)
			if err == nil || result.Outcome != "refused" || result.CommentID != "" || guardedAuditObserveNullable(t, ctx, s) != before {
				t.Fatalf("fresh permission laundered intervening writer %s: %+v %v", change, result, err)
			}
			saved, err := role.LookupExplanation(ctx, guardops.ExplanationLookupRequest{Protocol: r.Protocol, OperationID: r.OperationID, RequestDigest: guardops.ExplanationDigest(r)})
			if err != nil || saved.Outcome != "absent" {
				t.Fatal("refusal minted delivery ledger", err)
			}
		})
	}
}
func TestGuardedNativeLinkedExplanationCommentEventFailureRollsBackThenExactRetry(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	_, role, r := guardedLinkedExplanation(t, ctx, s, "validate")
	before := guardedAuditObserveNullable(t, ctx, s)
	fault := &guardedReleaseCommentFault{phase: "comment event"}
	original := s.db
	s.db = sql.OpenDB(guardedReleaseCommentFaultConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := role.Explain(ctx, r)
	if !errors.Is(err, errGuardedReleaseCommentFault) || result.Outcome != "refused" || fault.failures.Load() != 1 || fault.tentativeComments != "1" || fault.commits.Load() != 0 || guardedAuditObserveNullable(t, ctx, s) != before {
		t.Fatalf("tentative explanation not rolled back: %+v %v %+v", result, err, fault)
	}
	comments, err := s.GetIssueComments(ctx, r.Expected.IssueID)
	if err != nil || len(comments) != 0 {
		t.Fatal("failed delivery left comment", err)
	}
	fault.phase = ""
	result, err = role.Explain(ctx, r)
	if err != nil || result.Outcome != "applied" || fault.commits.Load() != 1 {
		t.Fatalf("definite rollback exact retry could not deliver once: %+v %v", result, err)
	}
	guardedRequireOneExplanation(t, ctx, s, r, result)
}
func TestGuardedNativeLinkedExplanationAckLossFreshLookupAndReplayOnce(t *testing.T) {
	ctx, s, cfg := guardedNativeStore(t)
	_, role, r := guardedLinkedExplanation(t, ctx, s, "add-initial-human-hold")
	fault := &guardedNativeCommitAckFault{}
	original := s.db
	s.db = sql.OpenDB(guardedNativeCommitAckConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := role.Explain(ctx, r)
	if !errors.Is(err, io.ErrUnexpectedEOF) || result.Outcome != "unknown" || result.CommentID != "" || fault.commitCalls.Load() != 1 || fault.successfulCommits.Load() != 1 {
		t.Fatalf("actual delivery acknowledgement loss not unknown/once: %+v %v", result, err)
	}
	freshCfg := *cfg
	freshCfg.CreateIfMissing = false
	fresh, err := New(ctx, &freshCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	recovery, err := fresh.GuardedExplanationDeliverer()
	if err != nil {
		t.Fatal(err)
	}
	saved, err := recovery.LookupExplanation(ctx, guardops.ExplanationLookupRequest{Protocol: r.Protocol, OperationID: r.OperationID, RequestDigest: guardops.ExplanationDigest(r)})
	if err != nil || saved.Outcome != "applied" || saved.CommentID == "" {
		t.Fatalf("fresh delivery lookup lost applied comment: %+v %v", saved, err)
	}
	guardedRequireOneExplanation(t, ctx, fresh, r, saved)
	before := guardedAuditObserveNullable(t, ctx, fresh)
	replay, err := recovery.Explain(ctx, r)
	if err != nil || !replay.Replayed || replay.CommentID != saved.CommentID || guardedAuditObserveNullable(t, ctx, fresh) != before || fault.commitCalls.Load() != 1 {
		t.Fatal("lost ack retry appended another explanation", err)
	}
	primary, _ := fresh.GuardedMutator()
	old, err := primary.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: guardops.ExplanationDigest(r)})
	if err == nil || old.Outcome != "unknown" {
		t.Fatal("new delivery ledger confused old Apply lookup")
	}
	current, err := primary.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	attester, _ := fresh.GuardedRecordAttester()
	proof, err := attester.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: current, RecordKey: r.OriginalRequest.Effect.HoldRecordKey, RecordValue: r.OriginalRequest.Effect.HoldRecordValue})
	if err != nil || proof.Outcome != "identified" || proof.Operation == nil || proof.Operation.OperationID != r.OriginalRequest.OperationID {
		t.Fatalf("explanation ledger poisoned original hold attestation: %+v %v", proof, err)
	}
}
func TestGuardedNativeLinkedExplanationStalePermissionAndPublicationFault(t *testing.T) {
	for _, phase := range []string{"stale-permission", "publication"} {
		t.Run(phase, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			_, role, r := guardedLinkedExplanation(t, ctx, s, "validate")
			before := guardedAuditObserveNullable(t, ctx, s)
			if phase == "stale-permission" {
				r.Expected.Token += "wrong"
			} else {
				fault := &guardedInitialCreateFault{phase: "post-sql-history"}
				original := s.db
				s.db = sql.OpenDB(guardedInitialCreateFaultConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
				s.db.SetMaxOpenConns(1)
				if err := original.Close(); err != nil {
					t.Fatal(err)
				}
			}
			result, err := role.Explain(ctx, r)
			want := "conflict"
			if phase == "publication" {
				want = "unknown"
			}
			if err == nil || result.Outcome != want || result.CommentID != "" || guardedAuditObserveNullable(t, ctx, s) != before {
				t.Fatalf("failed delivery boundary mutated/misstated outcome: %+v %v", result, err)
			}
			saved, err := role.LookupExplanation(ctx, guardops.ExplanationLookupRequest{Protocol: r.Protocol, OperationID: r.OperationID, RequestDigest: guardops.ExplanationDigest(r)})
			if err != nil || saved.Outcome != "absent" {
				t.Fatal("uncommitted explanation survived lookup", err)
			}
		})
	}
}

// The actual inner Commit succeeds; only the subsequent exact confirmation
// query loses its response. All SQL/driver interfaces otherwise delegate.
type guardedExplanationConfirmFault struct {
	operationID string
	committed   atomic.Bool
	reads       atomic.Int32
	commits     atomic.Int32
	base        guardedReleaseCommentFault
}
type guardedExplanationConfirmConnector struct {
	driver.Connector
	fault *guardedExplanationConfirmFault
}

func (c guardedExplanationConfirmConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &guardedExplanationConfirmConn{guardedReleaseCommentFaultConn: &guardedReleaseCommentFaultConn{Conn: conn, fault: &c.fault.base}, fault: c.fault}, nil
}

type guardedExplanationConfirmConn struct {
	*guardedReleaseCommentFaultConn
	fault *guardedExplanationConfirmFault
}

func (c *guardedExplanationConfirmConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &guardedExplanationConfirmTx{Tx: tx, fault: c.fault}, nil
}
func (c *guardedExplanationConfirmConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *guardedExplanationConfirmConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if c.fault.committed.Load() && q == "SELECT request_digest,result_json FROM bd_guard_operations WHERE operation_id=?" && len(args) == 1 && args[0].Value == c.fault.operationID && c.fault.reads.CompareAndSwap(0, 1) {
		return nil, io.ErrUnexpectedEOF
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}

type guardedExplanationConfirmTx struct {
	driver.Tx
	fault *guardedExplanationConfirmFault
}

func (tx *guardedExplanationConfirmTx) Commit() error {
	tx.fault.commits.Add(1)
	err := tx.Tx.Commit()
	if err == nil {
		tx.fault.committed.Store(true)
	}
	return err
}
func TestGuardedNativeLinkedExplanationConfirmationReadLossRemainsUnknown(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	_, role, r := guardedLinkedExplanation(t, ctx, s, "validate")
	fault := &guardedExplanationConfirmFault{operationID: r.OperationID}
	original := s.db
	s.db = sql.OpenDB(guardedExplanationConfirmConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := role.Explain(ctx, r)
	if !errors.Is(err, io.ErrUnexpectedEOF) || result.Outcome != "unknown" || result.CommentID != "" || fault.commits.Load() != 1 || fault.reads.Load() != 1 {
		t.Fatalf("unresolved fresh confirmation claimed success: %+v %v", result, err)
	}
	saved, err := role.LookupExplanation(ctx, guardops.ExplanationLookupRequest{Protocol: r.Protocol, OperationID: r.OperationID, RequestDigest: guardops.ExplanationDigest(r)})
	if err != nil || saved.Outcome != "applied" {
		t.Fatalf("actual committed delivery absent after read-only recovery: %+v %v", saved, err)
	}
	before := guardedAuditObserveNullable(t, ctx, s)
	replay, err := role.Explain(ctx, r)
	if err != nil || !replay.Replayed || replay.CommentID != saved.CommentID || guardedAuditObserveNullable(t, ctx, s) != before || fault.commits.Load() != 2 {
		t.Fatalf("historical replay changed delivery effects: %+v %v", replay, err)
	}
	// Replay's ordinary SQL read transaction is committed by withWriteTx, but
	// no native publication/comment/event is repeated (physical observations).
	guardedRequireOneExplanation(t, ctx, s, r, saved)
}
