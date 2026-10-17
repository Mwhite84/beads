package dolt

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/issueops"
)

// Only the acknowledgement is faulted, after the real driver's successful
// SQL commit. No query, statement, result, native commit, or rollback is faked.
type guardedNativeCommitAckFault struct {
	commitCalls, successfulCommits, lostAcknowledgements atomic.Int32
}

type guardedNativeCommitAckConnector struct {
	driver.Connector
	fault *guardedNativeCommitAckFault
}

func (c guardedNativeCommitAckConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &guardedNativeCommitAckConn{Conn: conn, fault: c.fault}, nil
}

type guardedNativeCommitAckConn struct {
	driver.Conn
	fault *guardedNativeCommitAckFault
}

func (c *guardedNativeCommitAckConn) Begin() (driver.Tx, error) {
	tx, err := c.Conn.Begin()
	if err != nil {
		return nil, err
	}
	return &guardedNativeCommitAckTx{Tx: tx, fault: c.fault}, nil
}

func (c *guardedNativeCommitAckConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &guardedNativeCommitAckTx{Tx: tx, fault: c.fault}, nil
}

func (c *guardedNativeCommitAckConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, query)
}

func (c *guardedNativeCommitAckConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	// Preserve ErrSkip and the actual prepared-statement fallback unchanged.
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func (c *guardedNativeCommitAckConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

func (c *guardedNativeCommitAckConn) CheckNamedValue(value *driver.NamedValue) error {
	return c.Conn.(driver.NamedValueChecker).CheckNamedValue(value)
}

func (c *guardedNativeCommitAckConn) Ping(ctx context.Context) error {
	return c.Conn.(driver.Pinger).Ping(ctx)
}

func (c *guardedNativeCommitAckConn) ResetSession(ctx context.Context) error {
	return c.Conn.(driver.SessionResetter).ResetSession(ctx)
}

func (c *guardedNativeCommitAckConn) IsValid() bool {
	return c.Conn.(driver.Validator).IsValid()
}

type guardedNativeCommitAckTx struct {
	driver.Tx
	fault *guardedNativeCommitAckFault
}

func (tx *guardedNativeCommitAckTx) Commit() error {
	tx.fault.commitCalls.Add(1)
	if err := tx.Tx.Commit(); err != nil {
		return err // A real refusal must never be converted into an injected success.
	}
	tx.fault.successfulCommits.Add(1)
	if tx.fault.lostAcknowledgements.CompareAndSwap(0, 1) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

var (
	_ driver.Connector          = guardedNativeCommitAckConnector{}
	_ driver.Conn               = (*guardedNativeCommitAckConn)(nil)
	_ driver.ConnBeginTx        = (*guardedNativeCommitAckConn)(nil)
	_ driver.ConnPrepareContext = (*guardedNativeCommitAckConn)(nil)
	_ driver.ExecerContext      = (*guardedNativeCommitAckConn)(nil)
	_ driver.QueryerContext     = (*guardedNativeCommitAckConn)(nil)
	_ driver.NamedValueChecker  = (*guardedNativeCommitAckConn)(nil)
	_ driver.Pinger             = (*guardedNativeCommitAckConn)(nil)
	_ driver.SessionResetter    = (*guardedNativeCommitAckConn)(nil)
	_ driver.Validator          = (*guardedNativeCommitAckConn)(nil)
	_ driver.Tx                 = (*guardedNativeCommitAckTx)(nil)
)

func TestGuardedNativeSQLCommitAckLossRecoversByIndependentLookup(t *testing.T) {
	ctx, writer, cfg := guardedNativeStore(t)
	mutator, request := guardedNativeSeed(t, ctx, writer)
	before := guardedNativeObserve(t, ctx, writer)
	if before.Assignee != request.Actor || before.Status != "in_progress" || before.LeaseJSON == "[]" || before.Operations != 0 {
		t.Fatalf("invalid claimed native specimen: %+v", before)
	}

	// Attach only after seed/capture; the injected acknowledgement is the
	// guarded operation's outer SQL commit, never initialization or migration.
	mysqlCfg, err := mysql.ParseDSN(writer.connStr)
	if err != nil {
		t.Fatal(err)
	}
	connector, err := mysql.NewConnector(mysqlCfg)
	if err != nil {
		t.Fatal(err)
	}
	fault := &guardedNativeCommitAckFault{}
	originalPool := writer.db
	writer.db = sql.OpenDB(guardedNativeCommitAckConnector{Connector: connector, fault: fault})
	writer.db.SetMaxOpenConns(1)
	if err := originalPool.Close(); err != nil {
		t.Fatal(err)
	}

	uncertain, err := mutator.Apply(ctx, request)
	if !errors.Is(err, io.ErrUnexpectedEOF) || !errors.Is(err, ErrCommitIndeterminate) || uncertain.Outcome != "unknown" {
		t.Fatalf("lost successful SQL commit acknowledgement was not unknown: result=%+v err=%v", uncertain, err)
	}
	if uncertain.Protocol != guardops.Protocol || uncertain.OperationID != request.OperationID || uncertain.RequestDigest != guardops.Digest(request) || uncertain.ResultJSON != "" || uncertain.Replayed || uncertain.Reason != "" || uncertain.ErrorCode != guardops.CodePublicationUnconfirmed {
		t.Fatalf("unknown outcome asserted completion or lost exact request identity: %+v", uncertain)
	}
	if fault.commitCalls.Load() != 1 || fault.successfulCommits.Load() != 1 || fault.lostAcknowledgements.Load() != 1 {
		t.Fatalf("Apply retried real commit or missed post-success fault: calls=%d successes=%d faults=%d", fault.commitCalls.Load(), fault.successfulCommits.Load(), fault.lostAcknowledgements.Load())
	}

	// Independently construct an ordinary, unwrapped store/pool. No observer
	// connection or tentative result is carried out of the faulted session.
	freshCfg := *cfg
	freshCfg.CreateIfMissing = false
	fresh, err := New(ctx, &freshCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fresh.Close(); err != nil {
			t.Error(err)
		}
	})
	recovery, err := fresh.GuardedMutator()
	if err != nil {
		t.Fatal(err)
	}
	lookup := guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: request.OperationID, RequestDigest: guardops.Digest(request)}
	resolved, err := recovery.Lookup(ctx, lookup)
	if err != nil || resolved.Outcome != "applied" || resolved.Protocol != lookup.Protocol || resolved.OperationID != lookup.OperationID || resolved.RequestDigest != lookup.RequestDigest || resolved.Replayed || resolved.Reason != "" {
		t.Fatalf("independent durable lookup did not recover exact operation: %+v err=%v", resolved, err)
	}
	after := guardedNativeObserve(t, ctx, fresh)
	if after.Assignee != "" || after.Status != "open" || after.Started.Valid || after.RowVersion == before.RowVersion || after.LeaseJSON != "[]" || after.Unclaimed != before.Unclaimed+1 || after.Operations != 1 || after.Token == before.Token || after.Head == before.Head || after.Commits != before.Commits+1 {
		t.Fatalf("successful real commit did not publish release/lease/event/ledger/token/history together: before=%+v after=%+v", before, after)
	}
	var native issueops.ReleaseResult
	if err := json.Unmarshal([]byte(resolved.ResultJSON), &native); err != nil || !native.Changed || native.Issue == nil {
		t.Fatalf("lookup lacks actual native release result: %+v err=%v", native, err)
	}
	// types.Issue.RowVersion is deliberately json:"-" in the existing native
	// result. Verify that revision physically and in HEAD below, not by inventing
	// a new result wire field for this acknowledgement-loss control.
	if native.Issue.ID != request.Expected.IssueID || native.Issue.Assignee != after.Assignee || string(native.Issue.Status) != after.Status || native.Issue.StartedAt != nil {
		t.Fatalf("recovered native result differs from persisted release row: %+v observed=%+v", native.Issue, after)
	}

	// Versioned release, exact saved result, and token must coexist in the new
	// native HEAD. Normal ignored lease/event state was observed above in one
	// fresh read transaction; it is deliberately not reclassified as versioned.
	var assignee, status, digest, saved, token string
	var version int64
	if err := fresh.db.QueryRowContext(ctx, "SELECT assignee,status,row_lock FROM issues AS OF 'HEAD' WHERE id='guard-target'").Scan(&assignee, &status, &version); err != nil || assignee != after.Assignee || status != after.Status || version != after.RowVersion {
		t.Fatalf("new native HEAD lacks released row: %q %q %d err=%v", assignee, status, version, err)
	}
	if err := fresh.db.QueryRowContext(ctx, "SELECT request_digest,result_json FROM bd_guard_operations AS OF 'HEAD' WHERE operation_id=?", request.OperationID).Scan(&digest, &saved); err != nil || digest != lookup.RequestDigest {
		t.Fatalf("same HEAD lacks exact operation identity: digest=%q err=%v", digest, err)
	}
	var recorded guardops.Result
	if err := json.Unmarshal([]byte(saved), &recorded); err != nil || recorded != resolved {
		t.Fatalf("native HEAD saved result differs from independent lookup: %+v err=%v", recorded, err)
	}
	if err := fresh.db.QueryRowContext(ctx, "SELECT token FROM bd_guard_state AS OF 'HEAD' WHERE id=1").Scan(&token); err != nil || token != after.Token {
		t.Fatalf("same HEAD lacks committed conflict token: %q err=%v", token, err)
	}

	// Reuse the ORIGINAL request/capture, including its now-stale token. The
	// operation ledger must deduplicate it before any new release is attempted.
	replayed, err := recovery.Apply(ctx, request)
	if err != nil || !replayed.Replayed {
		t.Fatalf("exact retry after unknown failed deduplication: %+v err=%v", replayed, err)
	}
	replayed.Replayed = false
	if replayed != resolved || guardedNativeObserve(t, ctx, fresh) != after {
		t.Fatal("deduplicated retry changed exact result or added release/lease/event/ledger/token/history effects")
	}
	if fault.commitCalls.Load() != 1 || fault.successfulCommits.Load() != 1 || fault.lostAcknowledgements.Load() != 1 {
		t.Fatal("independent recovery reused or committed through the faulted writer")
	}
}
