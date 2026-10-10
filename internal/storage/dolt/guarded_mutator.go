package dolt

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	storageissueops "github.com/steveyegge/beads/internal/storage/issueops"
	"github.com/steveyegge/beads/internal/workapi"
	"github.com/steveyegge/beads/issueops"
)

type guardedMutator struct{ store *DoltStore }

// GuardedMutator is deliberately optional: this initial role supports the
// single-session durable server path, with related ignored graphs refused.
func (s *DoltStore) GuardedMutator() (guardops.Mutator, error) {
	if s == nil {
		return nil, guardtx.ErrUnsupported
	}
	return &guardedMutator{store: s}, nil
}

// InitializeGuard is explicit maintenance, never an automatic migration. The
// local experiment initializes only disposable data. A production cutover
// requires compatible writers and separate operating approval.
func (s *DoltStore) InitializeGuard(ctx context.Context) error {
	if storageissueops.VersionCommitDeferred(ctx) {
		return fmt.Errorf("%w: guard initialization requires native history publication", guardtx.ErrUnsupported)
	}
	// Pin probe, DDL, seed and publication to one native session. The ordinary
	// guard Begin cannot bind until the singleton has been inserted.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	enabled, err := guardtx.Enabled(ctx, tx)
	if err != nil {
		return err
	}
	if enabled {
		return fmt.Errorf("guard already initialized; generation reset is maintenance")
	}
	for _, statement := range []string{
		`CREATE TABLE bd_guard_state (id INT PRIMARY KEY, generation VARCHAR(64) NOT NULL, token VARCHAR(64) NOT NULL)`,
		`CREATE TABLE bd_guard_operations (operation_id VARCHAR(128) PRIMARY KEY, request_digest VARCHAR(64) NOT NULL, result_json LONGTEXT NOT NULL)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	generation, err := guardtx.FreshIdentity()
	if err != nil {
		return err
	}
	token, err := guardtx.FreshIdentity()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO bd_guard_state VALUES (1, ?, ?)`, generation, token); err != nil {
		return err
	}
	if err := s.doltAddAndCommitInTx(ctx, tx, []string{guardtx.StateTable, guardtx.OperationsTable}, "bd: initialize guarded mutation capability"); err != nil {
		return err
	}
	return tx.Commit()
}

func (g *guardedMutator) Capture(ctx context.Context, id string) (guardops.Snapshot, error) {
	if strings.TrimSpace(id) == "" {
		return guardops.Snapshot{}, guardops.ErrValidation
	}
	var captured guardops.Snapshot
	err := g.withGuardReadTx(ctx, func(tx *sql.Tx) error {
		var err error
		captured, err = captureGuardState(ctx, tx, id)
		return err
	})
	return captured, err
}

func (g *guardedMutator) withGuardReadTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := guardtx.BeginTx(ctx, g.store.db, nil)
	if err != nil {
		return err
	}
	defer guardtx.Rollback(tx)
	return fn(tx)
}

func captureGuardState(ctx context.Context, tx *sql.Tx, id string) (guardops.Snapshot, error) {
	var s guardops.Snapshot
	if !guardtx.Bound(tx) {
		return s, fmt.Errorf("%w: database capability not initialized", guardtx.ErrUnsupported)
	}
	s.Protocol = guardops.Protocol
	s.IssueID = id
	if err := tx.QueryRowContext(ctx, "SELECT DATABASE(), active_branch(), DOLT_HASHOF('HEAD'), "+
		guardtx.RootExpression+", generation, token FROM bd_guard_state WHERE id=1").Scan(&s.Database, &s.Branch, &s.Head, &s.Root, &s.Generation, &s.Token); err != nil {
		return s, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM issues WHERE id=?`, id).Scan(&count); err != nil {
		return s, err
	}
	if count != 1 {
		return s, fmt.Errorf("%w: canonical durable issue required", guardtx.ErrUnsupported)
	}
	var canonicalID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM issues WHERE id=?`, id).Scan(&canonicalID); err != nil {
		return s, err
	}
	if canonicalID != id {
		return s, fmt.Errorf("%w: exact canonical issue identity required", guardtx.ErrUnsupported)
	}
	// A versioned-only graph cannot certify a related ignored endpoint. For
	// the local v1 role we conservatively refuse any mixed graph in this DB.
	for _, query := range []string{
		`SELECT COUNT(*) FROM dependencies WHERE depends_on_wisp_id IS NOT NULL`,
		`SELECT COUNT(*) FROM wisp_dependencies WHERE depends_on_issue_id IS NOT NULL`,
		`SELECT COUNT(*) FROM dolt_ignore WHERE ignored=1 AND
		('issues' LIKE pattern OR 'labels' LIKE pattern OR 'dependencies' LIKE pattern OR
		'config' LIKE pattern OR 'comments' LIKE pattern OR
		'bd_guard_state' LIKE pattern OR 'bd_guard_operations' LIKE pattern)`,
	} {
		if err := tx.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return s, err
		}
		if count != 0 {
			return s, fmt.Errorf("%w: related ignored graph or protected table", guardtx.ErrUnsupported)
		}
	}
	// Fixed server-selected tables form a conservative application snapshot.
	// Every scalar is retained as an exact string or null; int64 row_lock is
	// never rounded by a JavaScript JSON parser. All config/KV rows are kept,
	// including malformed application values, rather than a caller's filter.
	state := map[string]any{"issueId": id}
	for _, table := range []string{"issues", "labels", "dependencies", "config", "events", "comments", "leases"} {
		rows, err := guardRows(ctx, tx, table)
		if err != nil {
			return s, err
		}
		state[table] = rows
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return s, err
	}
	if len(encoded) > guardops.MaxStateBytes {
		return s, fmt.Errorf("%w: snapshot exceeds admission limit", guardtx.ErrUnsupported)
	}
	s.StateJSON = string(encoded)
	return s, guardops.ValidateSnapshot(s)
}

func guardRows(ctx context.Context, tx *sql.Tx, table string) ([]map[string]any, error) {
	// table is selected from the fixed literal list above, never request SQL.
	rows, err := tx.QueryContext(ctx, "SELECT * FROM `"+table+"`")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0)
	for rows.Next() {
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(columns))
		for i, column := range columns {
			switch v := values[i].(type) {
			case nil:
				row[column] = nil
			case []byte:
				row[column] = string(v)
			case time.Time:
				row[column] = v.Format(time.RFC3339Nano)
			default:
				row[column] = fmt.Sprint(v)
			}
		}
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// SQL row order is unspecified. Canonical server JSON sorts complete
	// detached rows; map keys themselves are sorted by encoding/json.
	sort.Slice(result, func(i, j int) bool {
		a, _ := json.Marshal(result[i])
		b, _ := json.Marshal(result[j])
		return string(a) < string(b)
	})
	return result, nil
}

func lookupGuardOperation(ctx context.Context, tx *sql.Tx, r guardops.LookupRequest) (guardops.Result, error) {
	result := guardops.Result{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: r.RequestDigest, Outcome: "absent"}
	if !guardtx.Bound(tx) {
		return result, guardtx.ErrUnsupported
	}
	var digest, raw string
	err := tx.QueryRowContext(ctx, `SELECT request_digest,result_json FROM bd_guard_operations WHERE operation_id=?`, r.OperationID).Scan(&digest, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if digest != r.RequestDigest {
		result.Outcome = "request-mismatch"
		return result, nil
	}
	var saved guardops.Result
	if err := json.Unmarshal([]byte(raw), &saved); err != nil {
		return result, err
	}
	if saved.Protocol != guardops.Protocol || saved.Outcome != "applied" || saved.OperationID != r.OperationID || saved.RequestDigest != digest {
		return result, fmt.Errorf("guard: invalid durable operation record")
	}
	return saved, nil
}

func (g *guardedMutator) Lookup(ctx context.Context, r guardops.LookupRequest) (guardops.Result, error) {
	result := guardops.Result{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: r.RequestDigest, Outcome: "unknown"}
	if err := guardops.ValidateLookup(r); err != nil {
		return result, err
	}
	err := g.withGuardReadTx(ctx, func(tx *sql.Tx) error {
		var err error
		result, err = lookupGuardOperation(ctx, tx, r)
		return err
	})
	if err != nil {
		result.Outcome = "unknown"
		result.Reason = err.Error()
	}
	return result, err
}

func (g *guardedMutator) Apply(ctx context.Context, r guardops.Request) (guardops.Result, error) {
	// Request fields are values/strings: detached at entry without shared maps
	// or pointers. The ORIGINAL capture is never replaced by a retry read.
	digest := guardops.Digest(r)
	result := guardops.Result{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: digest, Outcome: "refused"}
	if err := guardops.ValidateRequest(r); err != nil {
		result.Reason = err.Error()
		return result, err
	}
	if storageissueops.VersionCommitDeferred(ctx) {
		err := fmt.Errorf("%w: guarded application requires native history publication", guardtx.ErrUnsupported)
		result.Reason = err.Error()
		return result, err
	}
	lookup := guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: digest}
	publicationStarted := false
	// No callback replay: even a known rolled-back conflict returns the
	// ORIGINAL expectation to its caller. Recovery is a separate lookup.
	err := g.store.withWriteTx(ctx, func(tx *sql.Tx) error {
		prior, err := lookupGuardOperation(ctx, tx, lookup)
		if err != nil {
			return err
		}
		if prior.Outcome != "absent" {
			result = prior
			result.Replayed = true
			return nil
		}
		current, err := captureGuardState(ctx, tx, r.Expected.IssueID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, r.Expected) {
			return guardtx.ErrConflict
		}
		var nativeResult any
		tablesChanged := storageissueops.ChangedTables{}
		if r.Effect.Kind == "clear-human-hold" {
			nativeResult, err = applyHumanClearanceInTx(ctx, tx, r)
			if err != nil {
				return err
			}
			tablesChanged.Add("labels", "events", "config")
		} else {
			before, err := storageissueops.GetIssueInTx(ctx, tx, r.Expected.IssueID)
			if err != nil {
				return err
			}
			expectedAssignee := before.Assignee
			nativeRequest := issueops.ReleaseRequest{
				Actor: r.Actor, IssueID: r.Expected.IssueID, ExpectedAssignee: &expectedAssignee,
			}
			if err := workapi.ValidateReleaseRequest(nativeRequest); err != nil {
				return err
			}
			native, write, err := storageissueops.ReleaseIssueInTx(ctx, tx, nativeRequest)
			if err != nil {
				return err
			}
			nativeResult = native
			if r.Effect.Kind == "release-with-comment" {
				comment, err := storageissueops.AddIssueCommentInTx(ctx, tx, r.Expected.IssueID, r.Actor, r.Effect.Comment)
				if err != nil {
					return err
				}
				var storedText string
				if err := tx.QueryRowContext(ctx, "SELECT text FROM comments WHERE id=?", comment.ID).Scan(&storedText); err != nil {
					return err
				}
				if storedText != r.Effect.Comment {
					return fmt.Errorf("%w: native structured comment did not preserve exact text", guardtx.ErrUnsupported)
				}
				// The native audit column can be narrower than structured comments.
				// Compare binary text counts around the native insert inside this TX:
				// a warning/truncation must never become an acknowledged exact effect.
				const exactEventCount = "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='commented' AND actor=? AND CAST(comment AS BINARY)=CAST(? AS BINARY)"
				var priorComments, currentComments int64
				if err := tx.QueryRowContext(ctx, exactEventCount, r.Expected.IssueID, r.Actor, r.Effect.Comment).Scan(&priorComments); err != nil {
					return err
				}
				if err := storageissueops.AddCommentEventInTx(ctx, tx, r.Expected.IssueID, r.Actor, r.Effect.Comment); err != nil {
					return err
				}
				if err := tx.QueryRowContext(ctx, exactEventCount, r.Expected.IssueID, r.Actor, r.Effect.Comment).Scan(&currentComments); err != nil {
					return err
				}
				if currentComments != priorComments+1 {
					return fmt.Errorf("%w: native audit comment did not preserve exact text", guardtx.ErrUnsupported)
				}
				write.Tables.Add("comments")
				write.Tables.Add("events")
				nativeResult = struct {
					issueops.ReleaseResult
					CommentID string `json:"commentId"`
				}{ReleaseResult: native, CommentID: comment.ID}
			}
			tablesChanged = write.Tables
		}
		raw, err := json.Marshal(nativeResult)
		if err != nil {
			return err
		}
		result.Outcome = "applied"
		result.ResultJSON = string(raw)
		saved, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO bd_guard_operations(operation_id,request_digest,result_json) VALUES(?,?,?)`, r.OperationID, digest, string(saved)); err != nil {
			return err
		}
		tablesChanged.Add(guardtx.OperationsTable)
		tables := make([]string, 0, len(tablesChanged))
		for table := range tablesChanged {
			tables = append(tables, table)
		}
		sort.Strings(tables)
		if err := guardtx.Prepare(ctx, tx); err != nil {
			return err
		}
		publicationStarted = true
		message := "bd: guarded unclaim " + r.Expected.IssueID + " op " + r.OperationID
		if r.Effect.Kind == "clear-human-hold" {
			message = "bd: guarded clear human hold " + r.Expected.IssueID + " op " + r.OperationID
		}
		return g.store.doltAddAndCommitInTx(ctx, tx, tables, message)
	})
	if err != nil {
		result.ResultJSON = ""
		result.Reason = err.Error()
		switch {
		case publicationStarted, errors.Is(err, ErrCommitIndeterminate):
			result.Outcome = "unknown"
		case errors.Is(err, guardtx.ErrConflict), isSerializationError(err):
			result.Outcome = "conflict"
		default:
			result.Outcome = "refused"
		}
		return result, err
	}
	if result.Outcome != "applied" {
		return result, nil
	}
	// Applied is confirmed by a fresh durable operation lookup, not by a row
	// post-state that a different operation could also have produced.
	verified, err := g.Lookup(ctx, lookup)
	if err != nil || verified.Outcome != "applied" {
		result.Outcome = "unknown"
		result.ResultJSON = ""
		result.Reason = "protected commit not yet resolved by operation lookup"
		return result, err
	}
	verified.Replayed = result.Replayed
	return verified, nil
}

// applyHumanClearanceInTx publishes only prospective identified evidence. The
// original full native expectation has already matched; no legacy-history
// completeness is inferred here, and the claim/lease/material remain unchanged.
func applyHumanClearanceInTx(ctx context.Context, tx *sql.Tx, r guardops.Request) (any, error) {
	var held int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id=? AND CAST(label AS BINARY)=CAST('human-required' AS BINARY)", r.Expected.IssueID).Scan(&held); err != nil {
		return nil, err
	}
	if held != 1 {
		return nil, fmt.Errorf("%w: current human-required hold required", guardtx.ErrUnsupported)
	}
	for _, key := range []string{r.Effect.ClearanceKey, r.Effect.HistoryKey} {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key`=?", "kv."+key).Scan(&count); err != nil {
			return nil, err
		}
		if count != 0 {
			return nil, fmt.Errorf("%w: immutable clearance record key already exists", guardtx.ErrUnsupported)
		}
	}
	if err := storageissueops.RemoveLabelInTx(ctx, tx, "labels", "events", r.Expected.IssueID, "human-required", r.Actor); err != nil {
		return nil, err
	}
	for _, record := range []struct{ key, value string }{{r.Effect.ClearanceKey, r.Effect.ClearanceValue}, {r.Effect.HistoryKey, r.Effect.HistoryValue}} {
		key := "kv." + record.key
		if err := storageissueops.SetConfigInTx(ctx, tx, key, record.value); err != nil {
			return nil, err
		}
		var storedKey, storedValue string
		if err := tx.QueryRowContext(ctx, "SELECT `key`,value FROM config WHERE `key`=?", key).Scan(&storedKey, &storedValue); err != nil {
			return nil, err
		}
		if storedKey != key || storedValue != record.value {
			return nil, fmt.Errorf("%w: native clearance record did not preserve exact bytes", guardtx.ErrUnsupported)
		}
	}
	var clearance struct {
		Value struct {
			MaterialVersion string `json:"materialVersion"`
		} `json:"value"`
	}
	if err := json.Unmarshal([]byte(r.Effect.ClearanceValue), &clearance); err != nil {
		return nil, err
	}
	return struct {
		IssueID         string `json:"issueId"`
		Cleared         bool   `json:"cleared"`
		MaterialVersion string `json:"materialVersion"`
		HistoryComplete bool   `json:"historyComplete"`
	}{r.Expected.IssueID, true, clearance.Value.MaterialVersion, false}, nil
}
