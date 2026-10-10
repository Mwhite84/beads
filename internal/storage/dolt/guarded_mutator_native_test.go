package dolt

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	"github.com/steveyegge/beads/internal/types"
)

// These controls require an operator-owned, disposable loopback server. They
// never start a server/container or use the package's Docker setupTestStore.
// Run only with BEADS_TEST_SKIP=dolt and KREWE_GUARD_PRIVATE_PORT explicitly set.
func guardedNativeStore(t *testing.T) (context.Context, *DoltStore, *Config) {
	t.Helper()
	raw := os.Getenv("KREWE_GUARD_PRIVATE_PORT")
	if raw == "" {
		t.Skip("native guarded controls require explicit disposable private-port opt-in")
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1024 || port > 65535 || port == 3308 || port == DefaultSQLPort {
		t.Fatalf("invalid private guard port %q: require non-production loopback port", raw)
	}
	if os.Getenv("BEADS_TEST_SKIP") != "dolt" {
		t.Fatal("BEADS_TEST_SKIP=dolt required to suppress package Docker bootstrap")
	}
	t.Setenv("BEADS_TEST_SERVER", "1")
	t.Setenv("BEADS_DOLT_PASSWORD", "")
	t.Setenv("BEADS_DOLT_SERVER_SOCKET", "")
	t.Setenv("BEADS_DOLT_SERVER_HOST", "127.0.0.1")
	t.Setenv("BEADS_DOLT_SERVER_PORT", strconv.Itoa(port))
	t.Setenv("BEADS_DOLT_PORT", strconv.Itoa(port))
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	clientScratch := t.TempDir()
	cfg := &Config{
		Path: filepath.Join(clientScratch, "dolt"), BeadsDir: clientScratch,
		Database:   "test_guard_" + hex.EncodeToString(nonce[:]),
		ServerHost: "127.0.0.1", ServerPort: port, ServerUser: "root",
		ServerMode: true, DisableAutoStart: true, CreateIfMissing: true,
		CommitterName: "private guarded test", CommitterEmail: "guard-test@example.invalid",
		MaxOpenConns: 1, PoolReadTimeout: 30 * time.Second, PoolWriteTimeout: 30 * time.Second,
	}
	store, err := New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	// Do not force events into versioned storage: exercise normal migrations.
	var ignored int
	if err := store.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM dolt_ignore WHERE ignored=1 AND 'events' LIKE pattern").Scan(&ignored); err != nil || ignored == 0 {
		t.Fatalf("normally migrated events must be ignored: count=%d err=%v", ignored, err)
	}
	t.Logf("private native specimen database=%s endpoint=127.0.0.1:%d; server/data cleanup belongs to coordinator", cfg.Database, port)
	return ctx, store, cfg
}

func guardedNativeSeed(t *testing.T, ctx context.Context, store *DoltStore) (guardops.Mutator, guardops.Request) {
	t.Helper()
	if err := store.SetConfig(ctx, "issue_prefix", "guard"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"guard-target", "guard-blocker"} {
		if err := store.CreateIssue(ctx, &types.Issue{ID: id, Title: id, Description: "original material", Status: types.StatusOpen, Priority: 2, IssueType: types.TypeTask}, "guard-owner"); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ClaimIssue(ctx, "guard-target", "guard-owner"); err != nil {
		t.Fatal(err)
	}
	if err := store.InitializeGuard(ctx); err != nil {
		t.Fatalf("explicit guard initialization on migrated ignored-events schema: %v", err)
	}
	mutator, err := store.GuardedMutator()
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := mutator.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatalf("capture with normally ignored events: %v", err)
	}
	if err := guardops.ValidateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	return mutator, guardops.Request{
		Protocol: guardops.Protocol, OperationID: "native-operation-1", Actor: "guard-owner", Expected: snapshot,
		Effect: guardops.Effect{Kind: "release"}, ContextJSON: ` {"proof":"independent native control"} `,
	}
}

type guardedNativeObservation struct {
	Assignee, Status, LeaseJSON, Head, Token string
	RowVersion                               int64
	Started                                  sql.NullTime
	Unclaimed, Operations, Commits           int
}

// One fresh SQL read transaction observes physical regular and ignored state.
func guardedNativeObserve(t *testing.T, ctx context.Context, store *DoltStore) guardedNativeObservation {
	t.Helper()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var o guardedNativeObservation
	if err := tx.QueryRowContext(ctx, "SELECT assignee,status,row_lock,started_at FROM issues WHERE id='guard-target'").Scan(&o.Assignee, &o.Status, &o.RowVersion, &o.Started); err != nil {
		t.Fatal(err)
	}
	leases, err := guardRows(ctx, tx, "leases")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(leases)
	if err != nil {
		t.Fatal(err)
	}
	o.LeaseJSON = string(encoded)
	for _, query := range []struct {
		sql    string
		target any
	}{
		{"SELECT COUNT(*) FROM events WHERE issue_id='guard-target' AND event_type='unclaimed'", &o.Unclaimed},
		{"SELECT COUNT(*) FROM bd_guard_operations", &o.Operations},
		{"SELECT COUNT(*) FROM dolt_log", &o.Commits},
		{"SELECT DOLT_HASHOF('HEAD')", &o.Head},
		{"SELECT token FROM bd_guard_state WHERE id=1", &o.Token},
	} {
		if err := tx.QueryRowContext(ctx, query.sql).Scan(query.target); err != nil {
			t.Fatal(err)
		}
	}
	return o
}

func guardedNativeRequireOriginalClaim(t *testing.T, before, after guardedNativeObservation) {
	t.Helper()
	if after.Assignee != before.Assignee || after.Status != before.Status || after.RowVersion != before.RowVersion || after.Started != before.Started || after.LeaseJSON != before.LeaseJSON || after.Unclaimed != before.Unclaimed || after.Operations != 0 {
		t.Fatalf("refused operation leaked native release/lease/event/ledger effect: before=%+v after=%+v", before, after)
	}
}

func TestGuardedNativeReleaseReplayAndRequestMismatch(t *testing.T) {
	ctx, store, _ := guardedNativeStore(t)
	mutator, request := guardedNativeSeed(t, ctx, store)
	before := guardedNativeObserve(t, ctx, store)
	if before.Assignee != request.Actor || before.Status != "in_progress" || before.LeaseJSON == "[]" || before.Operations != 0 {
		t.Fatalf("invalid claimed native control: %+v", before)
	}
	result, err := mutator.Apply(ctx, request)
	if err != nil || result.Outcome != "applied" || result.Replayed || result.RequestDigest != guardops.Digest(request) {
		t.Fatalf("native guarded release: result=%+v err=%v", result, err)
	}
	after := guardedNativeObserve(t, ctx, store)
	if after.Assignee != "" || after.Status != "open" || after.Started.Valid || after.RowVersion == before.RowVersion || after.LeaseJSON != "[]" || after.Unclaimed != before.Unclaimed+1 || after.Operations != 1 || after.Token == before.Token || after.Head == before.Head || after.Commits != before.Commits+1 {
		t.Fatalf("native release and ledger/history did not publish together: before=%+v after=%+v", before, after)
	}
	var assignee, status, digest, saved, token string
	var version int64
	if err := store.db.QueryRowContext(ctx, "SELECT assignee,status,row_lock FROM issues AS OF 'HEAD' WHERE id='guard-target'").Scan(&assignee, &status, &version); err != nil || assignee != "" || status != "open" || version != after.RowVersion {
		t.Fatalf("native HEAD lacks exact released row: %q %q %d err=%v", assignee, status, version, err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT request_digest,result_json FROM bd_guard_operations AS OF 'HEAD' WHERE operation_id=?", request.OperationID).Scan(&digest, &saved); err != nil || digest != guardops.Digest(request) {
		t.Fatalf("same native HEAD lacks exact operation ledger: digest=%q err=%v", digest, err)
	}
	var recorded guardops.Result
	if err := json.Unmarshal([]byte(saved), &recorded); err != nil || recorded != result {
		t.Fatalf("published ledger result differs from confirmed response: %+v err=%v", recorded, err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT token FROM bd_guard_state AS OF 'HEAD' WHERE id=1").Scan(&token); err != nil || token != after.Token {
		t.Fatalf("same native HEAD lacks protected token: %q err=%v", token, err)
	}
	replayed, err := mutator.Apply(ctx, request)
	if err != nil || !replayed.Replayed {
		t.Fatalf("exact replay failed: %+v err=%v", replayed, err)
	}
	replayed.Replayed = false
	if replayed != result || guardedNativeObserve(t, ctx, store) != after {
		t.Fatal("exact replay added effect/event/ledger/history or changed saved result")
	}
	changed := request
	changed.ContextJSON += " "
	mismatch, err := mutator.Apply(ctx, changed)
	if err != nil || mismatch.Outcome != "request-mismatch" {
		t.Fatalf("same ID/different exact request not refused: %+v err=%v", mismatch, err)
	}
	lookup, err := mutator.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: request.OperationID, RequestDigest: guardops.Digest(changed)})
	if err != nil || lookup.Outcome != "request-mismatch" || guardedNativeObserve(t, ctx, store) != after {
		t.Fatalf("mismatched lookup changed native state or lost identity: %+v err=%v", lookup, err)
	}
}

func TestGuardedNativeOriginalCaptureRefusesOrdinaryNativeChanges(t *testing.T) {
	for _, name := range []string{"SetConfig", "AddLabel", "AddDependency", "material update"} {
		t.Run(name, func(t *testing.T) {
			ctx, store, _ := guardedNativeStore(t)
			mutator, request := guardedNativeSeed(t, ctx, store)
			var err error
			switch name {
			case "SetConfig":
				err = store.SetConfig(ctx, "kv.native-clearance", `{"accepted":true}`)
			case "AddLabel":
				err = store.AddLabel(ctx, request.Expected.IssueID, "human-required", "writer-b")
			case "AddDependency":
				err = store.AddDependency(ctx, &types.Dependency{IssueID: request.Expected.IssueID, DependsOnID: "guard-blocker", Type: types.DepBlocks}, "writer-b")
			case "material update":
				err = store.UpdateIssue(ctx, request.Expected.IssueID, map[string]interface{}{"description": "changed native material"}, "writer-b")
			}
			if err != nil {
				t.Fatalf("ordinary native write not acknowledged: %v", err)
			}
			before := guardedNativeObserve(t, ctx, store)
			if before.Token == request.Expected.Token {
				t.Fatal("ordinary native change failed to participate in protected token")
			}
			result, err := mutator.Apply(ctx, request)
			if !errors.Is(err, guardtx.ErrConflict) || result.Outcome != "conflict" {
				t.Fatalf("original capture was refreshed or accepted: %+v err=%v", result, err)
			}
			after := guardedNativeObserve(t, ctx, store)
			guardedNativeRequireOriginalClaim(t, before, after)
			if after != before {
				t.Fatal("stale refusal changed token or native history")
			}
		})
	}
}

// Only timing is instrumented. Every connection/query/result is delegated to
// the actual mysql driver; B uses an unwrapped ordinary DoltStore.SetConfig.
type guardedNativePause struct {
	arrived, resume chan struct{}
	once            sync.Once
	probeErr        error // published before closing arrived
}

type guardedNativeConnector struct {
	driver.Connector
	pause *guardedNativePause
}

func (c guardedNativeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &guardedNativeConn{Conn: conn, pause: c.pause}, nil
}

type guardedNativeConn struct {
	driver.Conn
	pause *guardedNativePause
}

func (c *guardedNativeConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}
func (c *guardedNativeConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, query)
}
func (c *guardedNativeConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}
func (c *guardedNativeConn) CheckNamedValue(value *driver.NamedValue) error {
	return c.Conn.(driver.NamedValueChecker).CheckNamedValue(value)
}
func (c *guardedNativeConn) Ping(ctx context.Context) error {
	return c.Conn.(driver.Pinger).Ping(ctx)
}
func (c *guardedNativeConn) ResetSession(ctx context.Context) error {
	return c.Conn.(driver.SessionResetter).ResetSession(ctx)
}
func (c *guardedNativeConn) IsValid() bool { return c.Conn.(driver.Validator).IsValid() }

func guardedNativeDriverText(value driver.Value) string {
	if value == nil {
		return "<nil>"
	}
	if b, ok := value.([]byte); ok {
		return string(b)
	}
	return fmt.Sprint(value)
}

func (c *guardedNativeConn) probeTentativeRelease(ctx context.Context) error {
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, `SELECT assignee,status,
		(SELECT COUNT(*) FROM leases WHERE issue_id='guard-target'),
		(SELECT COUNT(*) FROM events WHERE issue_id='guard-target' AND event_type='unclaimed'),
		(SELECT COUNT(*) FROM bd_guard_operations)
		FROM issues WHERE id='guard-target'`, nil)
	if err != nil {
		return err
	}
	defer rows.Close()
	values := make([]driver.Value, 5)
	if err := rows.Next(values); err != nil {
		return err
	}
	if guardedNativeDriverText(values[0]) != "" || guardedNativeDriverText(values[1]) != "open" || guardedNativeDriverText(values[2]) != "0" || guardedNativeDriverText(values[3]) != "1" || guardedNativeDriverText(values[4]) != "0" {
		return fmt.Errorf("pause is not after tentative native release and before ledger insertion: %v", values)
	}
	if err := rows.Next(values); err != io.EOF {
		return fmt.Errorf("unexpected tentative probe rows: %v", err)
	}
	return nil
}

func (c *guardedNativeConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(strings.TrimSpace(query), "INSERT INTO bd_guard_operations") {
		c.pause.once.Do(func() {
			c.pause.probeErr = c.probeTentativeRelease(ctx)
			close(c.pause.arrived)
		})
		select {
		case <-c.pause.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if c.pause.probeErr != nil {
			return nil, c.pause.probeErr
		}
	}
	// Preserve ErrSkip so database/sql can use the real prepared-statement
	// fallback when mysql does not interpolate arguments. The pause already
	// happened before any form of the actual INSERT reached the server.
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func TestGuardedNativeOrderedOrdinaryConfigRacePreservesClaim(t *testing.T) {
	ctx, storeA, cfg := guardedNativeStore(t)
	mutator, request := guardedNativeSeed(t, ctx, storeA)
	otherCfg := *cfg
	otherCfg.CreateIfMissing = false
	storeB, err := New(ctx, &otherCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := storeB.Close(); err != nil {
			t.Error(err)
		}
	})
	before := guardedNativeObserve(t, ctx, storeB)
	mysqlCfg, err := mysql.ParseDSN(storeA.connStr)
	if err != nil {
		t.Fatal(err)
	}
	connector, err := mysql.NewConnector(mysqlCfg)
	if err != nil {
		t.Fatal(err)
	}
	pause := &guardedNativePause{arrived: make(chan struct{}), resume: make(chan struct{})}
	var unblock sync.Once
	release := func() { unblock.Do(func() { close(pause.resume) }) }
	t.Cleanup(release)
	originalPool := storeA.db
	storeA.db = sql.OpenDB(guardedNativeConnector{Connector: connector, pause: pause})
	storeA.db.SetMaxOpenConns(1)
	if err := originalPool.Close(); err != nil {
		t.Fatal(err)
	}
	type answer struct {
		result guardops.Result
		err    error
	}
	done := make(chan answer, 1)
	finished := make(chan struct{})
	applyCtx, cancelApply := context.WithCancel(ctx)
	go func() {
		defer close(finished)
		result, err := mutator.Apply(applyCtx, request)
		done <- answer{result, err}
	}()
	// Teardown always unblocks and cancels before waiting for this owned call.
	defer func() {
		release()
		cancelApply()
		select {
		case <-finished:
		case <-time.After(35 * time.Second):
			t.Error("owned Apply did not finish after pause release; coordinator must retain server scratch")
		}
	}()
	select {
	case <-pause.arrived:
		if pause.probeErr != nil {
			t.Fatal(pause.probeErr)
		}
	case answer := <-done:
		t.Fatalf("Apply ended before ordered boundary: %+v err=%v", answer.result, answer.err)
	case <-time.After(20 * time.Second):
		t.Fatal("Apply did not reach actual ledger insertion boundary")
	}
	// The actual ordinary public writer must commit and be publicly/physically
	// acknowledged BEFORE A is unblocked; no cooperating direct-SQL B writer.
	bctx, cancelB := context.WithTimeout(ctx, 15*time.Second)
	defer cancelB()
	if err := storeB.SetConfig(bctx, "kv.native-clearance-race", `{"accepted":true}`); err != nil {
		t.Fatalf("ordinary B did not complete while A paused (inconclusive ordering): %v", err)
	}
	value, err := storeB.GetConfig(bctx, "kv.native-clearance-race")
	if err != nil || value != `{"accepted":true}` {
		t.Fatalf("ordinary B public acknowledgment missing: %q err=%v", value, err)
	}
	var physical string
	if err := storeB.db.QueryRowContext(bctx, "SELECT value FROM config WHERE `key`='kv.native-clearance-race'").Scan(&physical); err != nil || physical != value {
		t.Fatalf("ordinary B physical acknowledgment missing: %q err=%v", physical, err)
	}
	whilePaused := guardedNativeObserve(t, ctx, storeB)
	guardedNativeRequireOriginalClaim(t, before, whilePaused)
	if whilePaused.Token == before.Token {
		t.Fatal("acknowledged ordinary B did not stamp protected conflict token")
	}
	release()
	var completed answer
	select {
	case completed = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Apply failed to finish after ordered writer acknowledgment")
	}
	if completed.result.Outcome != "refused" && completed.result.Outcome != "conflict" && completed.result.Outcome != "unknown" {
		t.Fatalf("ordered native race lacked conservative outcome: %+v err=%v", completed.result, completed.err)
	}
	after := guardedNativeObserve(t, ctx, storeB)
	guardedNativeRequireOriginalClaim(t, before, after)
	if after.Head != whilePaused.Head || after.Commits != whilePaused.Commits || after.Token != whilePaused.Token {
		t.Fatal("failed guarded Apply published token or native history after B acknowledgment")
	}
	lookup, err := mutator.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: request.OperationID, RequestDigest: guardops.Digest(request)})
	if err != nil || lookup.Outcome != "absent" {
		t.Fatalf("failed ordered Apply left an operation record: %+v err=%v", lookup, err)
	}
}
