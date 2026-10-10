package guardtx

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// This literal is the independently reviewed scope, not the implementation's
// constant: every ignored runtime writer table must join the versioned DB.
const guardExpectedRootExpression = "CONCAT(DOLT_HASHOF_DB(), ':', DOLT_HASHOF_TABLE('leases'), ':', DOLT_HASHOF_TABLE('events'), ':', DOLT_HASHOF_TABLE('wisps'), ':', DOLT_HASHOF_TABLE('wisp_labels'), ':', DOLT_HASHOF_TABLE('wisp_dependencies'), ':', DOLT_HASHOF_TABLE('wisp_events'), ':', DOLT_HASHOF_TABLE('wisp_comments'), ':', DOLT_HASHOF_TABLE('wisp_child_counters'), ':', DOLT_HASHOF_TABLE('local_metadata'), ':', DOLT_HASHOF_TABLE('repo_mtimes'), ':', DOLT_HASHOF_TABLE('bd_events_journal'), ':', DOLT_HASHOF_TABLE('bd_events_seq'))"

// This driver models ordinary transactional SQL state and injected transport
// failures. It proves guard protocol behavior, not Dolt hashing or concurrency.
type guardImage struct {
	root, token, generation, value string
}

type guardFake struct {
	image                                   guardImage
	enabled                                 bool
	bindErr, rootErr, stampErr, affectedErr error
	affectedZero                            bool
	commits, rollbacks, stampCalls          int
	queries                                 []string
	stampArgs                               [][]driver.NamedValue
}

type guardConnector struct{ fake *guardFake }

func (c guardConnector) Connect(context.Context) (driver.Conn, error) {
	return &guardConn{fake: c.fake}, nil
}
func (c guardConnector) Driver() driver.Driver { return guardDriver{} }

type guardDriver struct{}

func (guardDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("only the test's isolated connector is supported")
}

type guardConn struct {
	fake   *guardFake
	active *guardImage
}

func (c *guardConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepared statement")
}
func (c *guardConn) Close() error { return nil }
func (c *guardConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *guardConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	if c.active != nil {
		return nil, errors.New("nested fake transaction")
	}
	image := c.fake.image
	c.active = &image
	return guardDriverTx{conn: c}, nil
}

type guardDriverTx struct{ conn *guardConn }

func (t guardDriverTx) Commit() error {
	t.conn.fake.commits++
	t.conn.fake.image = *t.conn.active
	t.conn.active = nil
	return nil
}
func (t guardDriverTx) Rollback() error {
	t.conn.fake.rollbacks++
	t.conn.active = nil
	return nil
}

type guardRows struct {
	columns []string
	values  []driver.Value
	done    bool
}

func (r *guardRows) Columns() []string { return r.columns }
func (r *guardRows) Close() error      { return nil }
func (r *guardRows) Next(dest []driver.Value) error {
	if r.done || r.values == nil {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}

func (c *guardConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.fake.queries = append(c.fake.queries, query)
	switch {
	case strings.Contains(query, "information_schema.tables"):
		n := int64(0)
		if c.fake.enabled {
			n = 1
		}
		return &guardRows{columns: []string{"count"}, values: []driver.Value{n}}, nil
	case query == "SELECT "+guardExpectedRootExpression+", token, generation FROM bd_guard_state WHERE id = 1":
		if c.fake.bindErr != nil {
			return nil, c.fake.bindErr
		}
		if c.active == nil {
			return nil, errors.New("guard seed read outside transaction")
		}
		return &guardRows{columns: []string{"root", "token", "generation"}, values: []driver.Value{
			c.active.root, c.active.token, c.active.generation,
		}}, nil
	case query == "SELECT "+guardExpectedRootExpression:
		if c.fake.rootErr != nil {
			return nil, c.fake.rootErr
		}
		if c.active == nil {
			return nil, errors.New("root read outside transaction")
		}
		return &guardRows{columns: []string{"root"}, values: []driver.Value{c.active.root}}, nil
	case query == "CALL DOLT_ADD(?)":
		if len(args) != 1 || args[0].Value != StateTable {
			return nil, errors.New("unexpected staged table")
		}
		return &guardRows{columns: []string{"result"}}, nil
	default:
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
}

type guardResult struct {
	n   int64
	err error
}

func (r guardResult) LastInsertId() (int64, error) { return 0, nil }
func (r guardResult) RowsAffected() (int64, error) { return r.n, r.err }

func (c *guardConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.active == nil {
		return nil, errors.New("mutation outside transaction")
	}
	if strings.HasPrefix(query, "UPDATE bd_guard_state SET token") {
		c.fake.stampCalls++
		c.fake.stampArgs = append(c.fake.stampArgs, append([]driver.NamedValue(nil), args...))
		if c.fake.stampErr != nil {
			return nil, c.fake.stampErr
		}
		if len(args) != 3 {
			return nil, errors.New("unexpected token update arguments")
		}
		if c.fake.affectedZero || args[1].Value != c.active.token || args[2].Value != c.active.generation {
			return guardResult{}, nil
		}
		c.active.token = args[0].Value.(string)
		c.active.root = "stamped-" + c.active.token
		return guardResult{n: 1, err: c.fake.affectedErr}, nil
	}
	if query == "UPDATE guard_fixture SET value = ?" || query == "REPLACE INTO guard_fixture VALUES (?)" {
		if len(args) != 1 {
			return nil, errors.New("unexpected native fixture arguments")
		}
		value := args[0].Value.(string)
		changed := value != c.active.value
		if changed {
			c.active.value = value
			c.active.root = "mutation-" + value
		}
		if strings.HasPrefix(query, "REPLACE") {
			return guardResult{n: 2}, nil
		}
		if changed {
			return guardResult{n: 1}, nil
		}
		return guardResult{}, nil
	}
	return nil, fmt.Errorf("unexpected exec: %s", query)
}

func guardFixture(t *testing.T) (*sql.DB, *guardFake) {
	t.Helper()
	fake := &guardFake{enabled: true, image: guardImage{
		root: "root-original", token: "token-original", generation: "generation-original", value: "old",
	}}
	db := sql.OpenDB(guardConnector{fake: fake})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db, fake
}

func guardBegin(t *testing.T, db *sql.DB) *sql.Tx {
	t.Helper()
	tx, err := BeginTx(context.Background(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Rollback(tx) })
	return tx
}

func guardMutate(t *testing.T, tx *sql.Tx, value string) {
	t.Helper()
	if _, err := tx.ExecContext(context.Background(), "UPDATE guard_fixture SET value = ?", value); err != nil {
		t.Fatal(err)
	}
}

func guardNoScope(t *testing.T, tx *sql.Tx, fake *guardFake) {
	t.Helper()
	before := len(fake.queries)
	if err := Prepare(context.Background(), tx); err != nil {
		t.Fatalf("scope survived finalization: %v", err)
	}
	if len(fake.queries) != before {
		t.Fatal("finalized scope still performs reads")
	}
}

func TestGuardRootExpressionIncludesRequiredIgnoredComponents(t *testing.T) {
	if RootExpression != guardExpectedRootExpression {
		t.Fatalf("guard root scope differs from reviewed versioned/ignored inputs: %q", RootExpression)
	}
}

func TestGuardCommitStampsActualMutationWithOriginalIdentity(t *testing.T) {
	db, fake := guardFixture(t)
	tx := guardBegin(t, db)
	guardMutate(t, tx, "new")
	if err := Commit(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if fake.commits != 1 || fake.rollbacks != 0 || fake.stampCalls != 1 {
		t.Fatalf("commits=%d rollbacks=%d stamps=%d", fake.commits, fake.rollbacks, fake.stampCalls)
	}
	if fake.image.value != "new" || fake.image.token == "token-original" || fake.image.token == "" {
		t.Fatalf("actual mutation and distinct token did not commit together: %+v", fake.image)
	}
	if fake.stampArgs[0][1].Value != "token-original" || fake.stampArgs[0][2].Value != "generation-original" {
		t.Fatal("token write lost the original token/generation predicate")
	}
	guardNoScope(t, tx, fake)
}

func TestGuardSameValueReplaceDoesNotStampDespiteRowsAffectedTwo(t *testing.T) {
	db, fake := guardFixture(t)
	tx := guardBegin(t, db)
	result, err := tx.ExecContext(context.Background(), "REPLACE INTO guard_fixture VALUES (?)", "old")
	if err != nil {
		t.Fatal(err)
	}
	n, err := result.RowsAffected()
	if err != nil || n != 2 {
		t.Fatalf("ordinary REPLACE result=%d error=%v", n, err)
	}
	if err := Prepare(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err := Commit(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if fake.stampCalls != 0 || fake.image.token != "token-original" || fake.image.root != "root-original" {
		t.Fatalf("same-value write minted a token: %+v", fake)
	}
	guardNoScope(t, tx, fake)
}

func TestGuardRepeatedPrepareOnlyStampsAfterAnotherRealMutation(t *testing.T) {
	db, fake := guardFixture(t)
	tx := guardBegin(t, db)
	guardMutate(t, tx, "first")
	for range 3 {
		if err := Prepare(context.Background(), tx); err != nil {
			t.Fatal(err)
		}
	}
	if fake.stampCalls != 1 {
		t.Fatalf("repeated preparation minted %d tokens", fake.stampCalls)
	}
	first := fake.stampArgs[0][0].Value
	guardMutate(t, tx, "second")
	if err := Prepare(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if fake.stampCalls != 2 || fake.stampArgs[1][1].Value != first || fake.stampArgs[1][0].Value == first {
		t.Fatal("new mutation did not use the current token and mint a distinct replacement")
	}
	if err := Commit(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if fake.stampCalls != 2 || fake.image.value != "second" {
		t.Fatal("Commit restamped an unchanged prepared root")
	}
}

func TestGuardFailedPrepareCannotCommitEvenWhenCallerIgnoresError(t *testing.T) {
	for _, name := range []string{"stamp error", "token mismatch", "RowsAffected error", "root read error"} {
		t.Run(name, func(t *testing.T) {
			db, fake := guardFixture(t)
			tx := guardBegin(t, db)
			original := fake.image
			guardMutate(t, tx, "unsafe")
			switch name {
			case "stamp error":
				fake.stampErr = errors.New("token write unavailable")
			case "token mismatch":
				fake.affectedZero = true
			case "RowsAffected error":
				fake.affectedErr = errors.New("affected count unavailable")
			case "root read error":
				fake.rootErr = errors.New("working root unavailable")
			}
			first := Prepare(context.Background(), tx)
			if first == nil {
				t.Fatal("unsafe preparation unexpectedly succeeded")
			}
			var intended error
			switch name {
			case "stamp error":
				intended = fake.stampErr
			case "token mismatch":
				intended = ErrConflict
			case "RowsAffected error":
				intended = fake.affectedErr
			case "root read error":
				intended = fake.rootErr
			}
			if !errors.Is(first, intended) {
				t.Fatalf("unrelated error replaced intended refusal %v: %v", intended, first)
			}
			// Restore the transport: ignoring the original error must not cure the scope.
			fake.stampErr, fake.affectedErr, fake.rootErr = nil, nil, nil
			fake.affectedZero = false
			if err := Commit(context.Background(), tx); !errors.Is(err, first) {
				t.Fatalf("Commit failed to retain original failure: %v; first=%v", err, first)
			}
			if fake.commits != 0 || fake.rollbacks != 1 || fake.image != original {
				t.Fatalf("failed guard leaked mutation: commits=%d rollbacks=%d image=%+v", fake.commits, fake.rollbacks, fake.image)
			}
			guardNoScope(t, tx, fake)
		})
	}
}

func TestGuardUnsupportedBindRollsBackOwnedTransaction(t *testing.T) {
	for _, name := range []string{"unsupported root hash", "empty root", "empty token", "empty generation"} {
		t.Run(name, func(t *testing.T) {
			db, fake := guardFixture(t)
			switch name {
			case "unsupported root hash":
				fake.bindErr = errors.New("DOLT_HASHOF_DB is unavailable")
			case "empty root":
				fake.image.root = ""
			case "empty token":
				fake.image.token = ""
			case "empty generation":
				fake.image.generation = ""
			}
			tx, err := BeginTx(context.Background(), db, nil)
			if err == nil || tx != nil {
				t.Fatalf("unsupported Bind returned usable transaction: tx=%v err=%v", tx, err)
			}
			if fake.commits != 0 || fake.rollbacks != 1 || fake.stampCalls != 0 {
				t.Fatalf("unsupported Bind did not roll back: %+v", fake)
			}
		})
	}
}

func TestGuardRollbackDiscardsMutationAndClearsScope(t *testing.T) {
	db, fake := guardFixture(t)
	tx := guardBegin(t, db)
	original := fake.image
	guardMutate(t, tx, "discard")
	if err := Prepare(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if err := Rollback(tx); err != nil {
		t.Fatal(err)
	}
	if fake.commits != 0 || fake.rollbacks != 1 || fake.image != original {
		t.Fatal("rollback persisted protected state")
	}
	guardNoScope(t, tx, fake)
}

func TestGuardDisabledDatabaseRetainsOrdinaryCommitWithoutHashOrStamp(t *testing.T) {
	db, fake := guardFixture(t)
	fake.enabled = false
	tx := guardBegin(t, db)
	guardMutate(t, tx, "ordinary")
	if err := Commit(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if fake.commits != 1 || fake.stampCalls != 0 || len(fake.queries) != 1 || fake.image.value != "ordinary" {
		t.Fatal("disabled database acquired guard behavior")
	}
}
