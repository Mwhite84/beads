// Package guardtx couples a versioned-state conflict token to native writes.
// It keeps the original SQL runner identity: journal scopes keyed by *sql.Tx
// or *sql.Conn remain valid. Enabling is an explicit database operation.
package guardtx

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

const StateTable = "bd_guard_state"
const OperationsTable = "bd_guard_operations"

// RootExpression covers every ignored table mutated by supported runtime
// writers, including shared UOW journal and cache bookkeeping. A table being
// ignored for history must not hide its changes from audit concurrency.
// ignored_schema_migrations belongs to exclusive schema maintenance instead.
const RootExpression = "CONCAT(DOLT_HASHOF_DB(), " +
	"':', DOLT_HASHOF_TABLE('leases'), ':', DOLT_HASHOF_TABLE('events'), " +
	"':', DOLT_HASHOF_TABLE('wisps'), ':', DOLT_HASHOF_TABLE('wisp_labels'), " +
	"':', DOLT_HASHOF_TABLE('wisp_dependencies'), ':', DOLT_HASHOF_TABLE('wisp_events'), " +
	"':', DOLT_HASHOF_TABLE('wisp_comments'), ':', DOLT_HASHOF_TABLE('wisp_child_counters'), " +
	"':', DOLT_HASHOF_TABLE('local_metadata'), ':', DOLT_HASHOF_TABLE('repo_mtimes'), " +
	"':', DOLT_HASHOF_TABLE('bd_events_journal'), ':', DOLT_HASHOF_TABLE('bd_events_seq'))"

var ErrUnsupported = errors.New("guard: unsupported transaction or storage state")
var ErrConflict = errors.New("guard: original expectation no longer matches")

type Runner interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type starter interface {
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

type scope struct {
	root        string
	token       string
	generation  string
	failure     error
	publication map[string]bool
}

// Native transactions are serially owned by their caller. The map only owns
// registration/removal; it does not make SQL runners safe for concurrent use.
var scopes sync.Map

func Enabled(ctx context.Context, r Runner) (bool, error) {
	var n int
	err := r.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema = DATABASE() AND table_name IN ('bd_guard_state', 'bd_guard_operations')`).Scan(&n)
	if err != nil {
		return false, err
	}
	// A half-installed capability must never look like an ordinary unenrolled
	// database. In particular, an operations-only schema otherwise bypasses
	// Bind and allows native writes with no conflict-token participation.
	switch n {
	case 0:
		return false, nil
	case 2:
		return true, nil
	default:
		return false, fmt.Errorf("%w: incomplete guard capability (%d tables)", ErrUnsupported, n)
	}
}

// Bind must run after BEGIN and before native mutation. Disabled databases do
// not acquire a guard scope and never have their schema or data changed here.
func Bind(ctx context.Context, r Runner) error {
	if _, exists := scopes.Load(r); exists {
		return fmt.Errorf("%w: runner already bound", ErrUnsupported)
	}
	enabled, err := Enabled(ctx, r)
	if err != nil {
		return fmt.Errorf("guard: inspect capability: %w", err)
	}
	if !enabled {
		return nil
	}
	var s scope
	if err := r.QueryRowContext(ctx, "SELECT "+RootExpression+", token, generation FROM bd_guard_state WHERE id = 1").Scan(&s.root, &s.token, &s.generation); err != nil {
		return fmt.Errorf("guard: read working root/token (no HEAD fallback): %w", err)
	}
	if s.root == "" || s.token == "" || s.generation == "" {
		return fmt.Errorf("%w: incomplete guard identity", ErrUnsupported)
	}
	scopes.Store(r, &s)
	return nil
}

func BeginTx(ctx context.Context, db starter, opts *sql.TxOptions) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if err := Bind(ctx, tx); err != nil {
		return nil, errors.Join(err, tx.Rollback())
	}
	return tx, nil
}

// Prepare must precede BOTH SQL COMMIT and an in-transaction DOLT_COMMIT.
// Comparing actual working roots preserves same-value and zero-row no-ops;
// RowsAffected cannot make that distinction for native REPLACE operations.
func Prepare(ctx context.Context, r Runner) error {
	entry, ok := scopes.Load(r)
	if !ok {
		return nil
	}
	s := entry.(*scope)
	if s.failure != nil {
		return s.failure
	}
	var root string
	if err := r.QueryRowContext(ctx, "SELECT "+RootExpression).Scan(&root); err != nil {
		s.failure = fmt.Errorf("guard: inspect changed working root: %w", err)
		return s.failure
	}
	if root == "" {
		s.failure = fmt.Errorf("%w: empty changed working root", ErrUnsupported)
		return s.failure
	}
	if root == s.root {
		return nil
	}
	token, err := FreshIdentity()
	if err != nil {
		s.failure = err
		return err
	}
	result, err := r.ExecContext(ctx, `UPDATE bd_guard_state SET token = ?
		WHERE id = 1 AND token = ? AND generation = ?`, token, s.token, s.generation)
	if err != nil {
		s.failure = fmt.Errorf("guard: stamp protected transaction: %w", err)
		return s.failure
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		s.failure = errors.Join(ErrConflict, err)
		return s.failure
	}
	s.token = token
	if err := r.QueryRowContext(ctx, "SELECT "+RootExpression).Scan(&s.root); err != nil {
		s.failure = fmt.Errorf("guard: read stamped working root: %w", err)
		return s.failure
	}
	if s.root == "" {
		s.failure = fmt.Errorf("%w: empty stamped working root", ErrUnsupported)
		return s.failure
	}
	return nil
}

// Stage is called only AFTER the native staged-change check succeeds. It must
// never turn an unrelated pending token into a native no-op history commit.
func Stage(ctx context.Context, r Runner) error {
	enabled, err := Enabled(ctx, r)
	if err != nil || !enabled {
		return err
	}
	rows, err := r.QueryContext(ctx, "CALL DOLT_ADD(?)", StateTable)
	if err != nil {
		return fmt.Errorf("guard: stage token: %w", err)
	}
	defer rows.Close()
	for {
		for rows.Next() {
		} // DOLT_ADD results are intentionally discarded.
		if err := rows.Err(); err != nil {
			return err
		}
		if !rows.NextResultSet() {
			break
		}
	}
	return rows.Err()
}

func Commit(ctx context.Context, tx *sql.Tx) error {
	defer Forget(tx)
	if err := Prepare(ctx, tx); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}

func Rollback(tx *sql.Tx) error { Forget(tx); return tx.Rollback() }
func Forget(r Runner)           { scopes.Delete(r) }

func Bound(r Runner) bool { _, ok := scopes.Load(r); return ok }

func FreshIdentity() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("guard: random identity: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// NotePublicationTables records only native work actually inserted by this
// registered transaction. It does not change runner identity or enable guards.
func NotePublicationTables(r Runner, tables ...string) {
	entry, ok := scopes.Load(r)
	if !ok {
		return
	}
	s := entry.(*scope)
	if s.publication == nil {
		s.publication = map[string]bool{}
	}
	for _, table := range tables {
		s.publication[table] = true
	}
}

// PublicationTables returns a detached copy BEFORE Commit/Forget.
func PublicationTables(r Runner) map[string]bool {
	result := map[string]bool{}
	entry, ok := scopes.Load(r)
	if !ok {
		return result
	}
	for table := range entry.(*scope).publication {
		result[table] = true
	}
	return result
}
