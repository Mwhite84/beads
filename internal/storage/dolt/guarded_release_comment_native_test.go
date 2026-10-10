package dolt

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/issueops"
)

const guardedReleaseCommentBody = " \nReviewed λ `command --exact`\t\nReleased for human review.\n "

type guardedReleaseCommentResult struct {
	issueops.ReleaseResult
	CommentID string `json:"commentId"`
}

func guardedReleaseCommentRequest(t *testing.T, ctx context.Context, store *DoltStore) (guardops.Mutator, guardops.Request) {
	t.Helper()
	mutator, request := guardedNativeSeed(t, ctx, store)
	request.OperationID = "native-release-comment-1"
	request.Effect = guardops.Effect{Kind: "release-with-comment", Comment: guardedReleaseCommentBody}
	return mutator, request
}

func TestGuardedNativeReleaseCommentReplayPublishesOneAtomicResult(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	mutator, request := guardedReleaseCommentRequest(t, ctx, store)
	before := guardedNativeObserve(t, ctx, store)
	result, err := mutator.Apply(ctx, request)
	if err != nil || result.Outcome != "applied" || result.Replayed {
		t.Fatalf("atomic release/comment failed: %+v err=%v", result, err)
	}
	after := guardedReleaseCommentRequireApplied(t, ctx, store, request, result, before)
	replay, err := mutator.Apply(ctx, request)
	if err != nil || !replay.Replayed {
		t.Fatalf("original release/comment replay: %+v err=%v", replay, err)
	}
	replay.Replayed = false
	if replay != result || guardedNativeObserve(t, ctx, store) != after {
		t.Fatal("exact retry changed saved result or repeated release/history")
	}
	guardedReleaseCommentRequireOneComment(t, ctx, store, request, result)
	changed := request
	changed.Effect.Comment += " "
	mismatch, err := mutator.Apply(ctx, changed)
	if err != nil || mismatch.Outcome != "request-mismatch" || guardedNativeObserve(t, ctx, store) != after {
		t.Fatalf("same operation/different exact comment was accepted: %+v err=%v", mismatch, err)
	}
	guardedReleaseCommentRequireOneComment(t, ctx, store, request, result)
}

func TestGuardedNativeReleaseCommentInsertionFailuresRollbackBothEffects(t *testing.T) {
	for _, phase := range []string{"structured comment", "comment event"} {
		t.Run(phase, func(t *testing.T) {
			ctx, store, _ := guardedNativeStore(t)
			mutator, request := guardedReleaseCommentRequest(t, ctx, store)
			before := guardedNativeObserve(t, ctx, store)
			fault := &guardedReleaseCommentFault{phase: phase}
			connector := guardedReleaseCommentConnector(t, store)
			original := store.db
			store.db = sql.OpenDB(guardedReleaseCommentFaultConnector{Connector: connector, fault: fault})
			store.db.SetMaxOpenConns(1)
			if err := original.Close(); err != nil {
				t.Fatal(err)
			}
			result, err := mutator.Apply(ctx, request)
			if !errors.Is(err, errGuardedReleaseCommentFault) || result.Outcome != "refused" || result.ResultJSON != "" || result.Replayed {
				t.Fatalf("pre-publication insertion failure was not refused: %+v err=%v", result, err)
			}
			wantTentativeComments := "0"
			if phase == "comment event" {
				wantTentativeComments = "1"
			}
			if fault.failures.Load() != 1 || !fault.tentativeReleased || fault.tentativeComments != wantTentativeComments || fault.commits.Load() != 0 {
				t.Fatalf("fault did not observe actual tentative effects or callback replayed: failures=%d released=%v comments=%s commits=%d", fault.failures.Load(), fault.tentativeReleased, fault.tentativeComments, fault.commits.Load())
			}
			if after := guardedNativeObserve(t, ctx, store); after != before {
				t.Fatalf("failed insertion left half-release/event/ledger/token/history: before=%+v after=%+v", before, after)
			}
			comments, err := store.GetIssueComments(ctx, request.Expected.IssueID)
			if err != nil || len(comments) != 0 {
				t.Fatalf("failed insertion left a structured comment: %+v err=%v", comments, err)
			}
			var commentEvents int
			if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id='guard-target' AND event_type='commented'").Scan(&commentEvents); err != nil || commentEvents != 0 {
				t.Fatalf("failed insertion left an audit comment event: %d err=%v", commentEvents, err)
			}
			lookup, err := mutator.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: request.OperationID, RequestDigest: guardops.Digest(request)})
			if err != nil || lookup.Outcome != "absent" {
				t.Fatalf("failed insertion persisted operation ledger: %+v err=%v", lookup, err)
			}
		})
	}
}

func TestGuardedNativeReleaseCommentAckLossRecoversByFreshStore(t *testing.T) {
	ctx, writer, cfg := guardedNativeStore(t)
	mutator, request := guardedReleaseCommentRequest(t, ctx, writer)
	before := guardedNativeObserve(t, ctx, writer)
	connector := guardedReleaseCommentConnector(t, writer)
	fault := &guardedNativeCommitAckFault{}
	original := writer.db
	writer.db = sql.OpenDB(guardedNativeCommitAckConnector{Connector: connector, fault: fault})
	writer.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	unknown, err := mutator.Apply(ctx, request)
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrCommitIndeterminate) || unknown.Outcome != "unknown" || unknown.ResultJSON != "" || unknown.Replayed || unknown.RequestDigest != guardops.Digest(request) {
		t.Fatalf("real successful SQL commit acknowledgement loss: %+v err=%v", unknown, err)
	}
	if fault.commitCalls.Load() != 1 || fault.successfulCommits.Load() != 1 || fault.lostAcknowledgements.Load() != 1 {
		t.Fatalf("release/comment commit repeated: calls=%d successes=%d faults=%d", fault.commitCalls.Load(), fault.successfulCommits.Load(), fault.lostAcknowledgements.Load())
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
	if err != nil || resolved.Outcome != "applied" || resolved.Replayed {
		t.Fatalf("fresh native store did not recover exact result: %+v err=%v", resolved, err)
	}
	after := guardedReleaseCommentRequireApplied(t, ctx, fresh, request, resolved, before)
	replay, err := recovery.Apply(ctx, request)
	if err != nil || !replay.Replayed {
		t.Fatalf("original request retry after unknown: %+v err=%v", replay, err)
	}
	replay.Replayed = false
	if replay != resolved || guardedNativeObserve(t, ctx, fresh) != after {
		t.Fatal("unknown recovery retry repeated native release/history or changed saved result")
	}
	guardedReleaseCommentRequireOneComment(t, ctx, fresh, request, resolved)
	if fault.commitCalls.Load() != 1 {
		t.Fatal("fresh recovery reused faulted writer")
	}
}

func TestGuardedNativeReleaseCommentLargeBodyFailsOrIsExact(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	mutator, request := guardedReleaseCommentRequest(t, ctx, store)
	// Above TEXT's usual 64KiB, below the agreed 1MiB UTF8 wire cap. A native
	// storage refusal is allowed; acknowledged success must preserve ALL bytes.
	request.Effect.Comment = " \n" + strings.Repeat("λ", 40<<10) + "\t\n "
	before := guardedNativeObserve(t, ctx, store)
	result, err := mutator.Apply(ctx, request)
	if err == nil {
		if result.Outcome != "applied" || result.Replayed {
			t.Fatalf("large body neither refused nor exactly applied: %+v", result)
		}
		guardedReleaseCommentRequireApplied(t, ctx, store, request, result, before)
		return
	}
	if result.Outcome != "refused" || result.ResultJSON != "" || result.Replayed {
		t.Fatalf("large native text refusal reported completion: %+v err=%v", result, err)
	}
	if after := guardedNativeObserve(t, ctx, store); after != before {
		t.Fatalf("large-body refusal left half-release/token/event/history: before=%+v after=%+v", before, after)
	}
	comments, readErr := store.GetIssueComments(ctx, request.Expected.IssueID)
	if readErr != nil || len(comments) != 0 {
		t.Fatalf("large-body refusal persisted structured comment: count=%d err=%v", len(comments), readErr)
	}
	var commentEvents int
	if readErr := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id='guard-target' AND event_type='commented'").Scan(&commentEvents); readErr != nil || commentEvents != 0 {
		t.Fatalf("large-body refusal persisted audit event: count=%d err=%v", commentEvents, readErr)
	}
	lookup, readErr := mutator.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: request.OperationID, RequestDigest: guardops.Digest(request)})
	if readErr != nil || lookup.Outcome != "absent" {
		t.Fatalf("large-body refusal persisted operation: %+v err=%v", lookup, readErr)
	}
	t.Logf("large-body native refusal rolled back all effects: %v", err)
}

func guardedReleaseCommentRequireApplied(t *testing.T, ctx context.Context, store *DoltStore, request guardops.Request, result guardops.Result, before guardedNativeObservation) guardedNativeObservation {
	t.Helper()
	if result.Protocol != guardops.Protocol || result.OperationID != request.OperationID || result.RequestDigest != guardops.Digest(request) {
		t.Fatalf("result lost exact request identity: %+v", result)
	}
	after := guardedNativeObserve(t, ctx, store)
	if after.Assignee != "" || after.Status != "open" || after.Started.Valid || after.RowVersion == before.RowVersion || after.LeaseJSON != "[]" || after.Unclaimed != before.Unclaimed+1 || after.Operations != 1 || after.Token == before.Token || after.Head == before.Head || after.Commits != before.Commits+1 {
		t.Fatalf("release/comment did not publish one atomic native operation: before=%+v after=%+v", before, after)
	}
	guardedReleaseCommentRequireOneComment(t, ctx, store, request, result)
	var native guardedReleaseCommentResult
	if err := json.Unmarshal([]byte(result.ResultJSON), &native); err != nil || !native.Changed || native.Issue == nil || native.Issue.ID != request.Expected.IssueID || native.Issue.Assignee != "" || native.Issue.Status != "open" || native.CommentID == "" {
		t.Fatalf("result lacks flattened native release/comment identity: %+v err=%v", native, err)
	}
	var text, author, assignee, token, digest, saved string
	if err := store.db.QueryRowContext(ctx, "SELECT text,author FROM comments AS OF 'HEAD' WHERE id=?", native.CommentID).Scan(&text, &author); err != nil || text != request.Effect.Comment || author != request.Actor {
		t.Fatalf("same native HEAD lacks exact structured comment: %q %q err=%v", text, author, err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT assignee FROM issues AS OF 'HEAD' WHERE id='guard-target'").Scan(&assignee); err != nil || assignee != "" {
		t.Fatalf("same native HEAD lacks released row: %q err=%v", assignee, err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT token FROM bd_guard_state AS OF 'HEAD' WHERE id=1").Scan(&token); err != nil || token != after.Token {
		t.Fatalf("same native HEAD lacks acknowledged token: %q err=%v", token, err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT request_digest,result_json FROM bd_guard_operations AS OF 'HEAD' WHERE operation_id=?", request.OperationID).Scan(&digest, &saved); err != nil || digest != guardops.Digest(request) {
		t.Fatalf("same native HEAD lacks operation digest/ledger: %q err=%v", digest, err)
	}
	var recorded guardops.Result
	if err := json.Unmarshal([]byte(saved), &recorded); err != nil || recorded != result {
		t.Fatalf("native HEAD result differs from recovered result: %+v err=%v", recorded, err)
	}
	return after
}

func guardedReleaseCommentRequireOneComment(t *testing.T, ctx context.Context, store *DoltStore, request guardops.Request, result guardops.Result) {
	t.Helper()
	var native guardedReleaseCommentResult
	if err := json.Unmarshal([]byte(result.ResultJSON), &native); err != nil {
		t.Fatal(err)
	}
	comments, err := store.GetIssueComments(ctx, request.Expected.IssueID)
	if err != nil || len(comments) != 1 || comments[0].ID != native.CommentID || comments[0].Author != request.Actor || comments[0].Text != request.Effect.Comment {
		t.Fatalf("exact original comment missing or repeated: %+v err=%v", comments, err)
	}
	events, err := store.GetEvents(ctx, request.Expected.IssueID, 0)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.EventType == "commented" {
			count++
			if event.Actor != request.Actor || event.Comment == nil || *event.Comment != request.Effect.Comment {
				t.Fatalf("real comment event lost exact actor/body: %+v", event)
			}
		}
	}
	if count != 1 {
		t.Fatalf("real comment event repeated or absent: %d", count)
	}
}

func guardedReleaseCommentConnector(t *testing.T, store *DoltStore) driver.Connector {
	t.Helper()
	cfg, err := mysql.ParseDSN(store.connStr)
	if err != nil {
		t.Fatal(err)
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return connector
}

var errGuardedReleaseCommentFault = errors.New("private native comment insertion fault")

type guardedReleaseCommentFault struct {
	phase             string
	failures, commits atomic.Int32
	tentativeReleased bool
	tentativeComments string
}

type guardedReleaseCommentFaultConnector struct {
	driver.Connector
	fault *guardedReleaseCommentFault
}

func (c guardedReleaseCommentFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &guardedReleaseCommentFaultConn{Conn: conn, fault: c.fault}, nil
}

type guardedReleaseCommentFaultConn struct {
	driver.Conn
	fault *guardedReleaseCommentFault
}

func (c *guardedReleaseCommentFaultConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &guardedReleaseCommentFaultTx{Tx: tx, fault: c.fault}, nil
}

func (c *guardedReleaseCommentFaultConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *guardedReleaseCommentFaultConn) faultInsertion(ctx context.Context, query string, args []driver.NamedValue) error {
	normalized := strings.Join(strings.Fields(query), " ")
	comment := strings.HasPrefix(normalized, "INSERT INTO comments (")
	commentEvent := strings.HasPrefix(normalized, "INSERT INTO events (") && len(args) > 2 && args[2].Value == "commented"
	if !(c.fault.phase == "structured comment" && comment) && !(c.fault.phase == "comment event" && commentEvent) {
		return nil
	}
	c.fault.failures.Add(1)
	// Probe the real underlying session before faulting its next statement.
	// This proves release (and, for event failure, comment) already happened
	// inside this transaction; no tentative SQL result is manufactured.
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, "SELECT assignee,status,(SELECT COUNT(*) FROM comments WHERE issue_id='guard-target') FROM issues WHERE id='guard-target'", nil)
	if err != nil {
		return err
	}
	defer rows.Close()
	values := make([]driver.Value, 3)
	if err := rows.Next(values); err != nil {
		return err
	}
	text := func(v driver.Value) string {
		if b, ok := v.([]byte); ok {
			return string(b)
		}
		return fmt.Sprint(v)
	}
	c.fault.tentativeReleased = text(values[0]) == "" && text(values[1]) == "open"
	c.fault.tentativeComments = text(values[2])
	return errGuardedReleaseCommentFault
}

func (c *guardedReleaseCommentFaultConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.faultInsertion(ctx, query, args); err != nil {
		return nil, err
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func (c *guardedReleaseCommentFaultConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func (c *guardedReleaseCommentFaultConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, query)
}

func (c *guardedReleaseCommentFaultConn) CheckNamedValue(v *driver.NamedValue) error {
	return c.Conn.(driver.NamedValueChecker).CheckNamedValue(v)
}

func (c *guardedReleaseCommentFaultConn) Ping(ctx context.Context) error {
	return c.Conn.(driver.Pinger).Ping(ctx)
}

func (c *guardedReleaseCommentFaultConn) ResetSession(ctx context.Context) error {
	return c.Conn.(driver.SessionResetter).ResetSession(ctx)
}

func (c *guardedReleaseCommentFaultConn) IsValid() bool {
	return c.Conn.(driver.Validator).IsValid()
}

type guardedReleaseCommentFaultTx struct {
	driver.Tx
	fault *guardedReleaseCommentFault
}

func (t *guardedReleaseCommentFaultTx) Commit() error {
	t.fault.commits.Add(1)
	return t.Tx.Commit()
}
