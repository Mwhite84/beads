package dolt

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/steveyegge/beads/internal/storage/guardbirth"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	storageissueops "github.com/steveyegge/beads/internal/storage/issueops"
	"github.com/steveyegge/beads/internal/types"
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
		if r.Effect.Kind == "audit-comment" {
			if _, err := auditUnclaimedIssue(ctx, tx, r.Expected.IssueID); err != nil {
				return err
			}
			commentID, err := addExactAuditComment(ctx, tx, r.Expected.IssueID, r.Actor, r.Effect.Comment)
			if err != nil {
				return err
			}
			nativeResult = struct {
				IssueID   string `json:"issueId"`
				Commented bool   `json:"commented"`
				CommentID string `json:"commentId"`
			}{IssueID: r.Expected.IssueID, Commented: true, CommentID: commentID}
			tablesChanged.Add("comments", "events")
		} else if r.Effect.Kind == "clear-human-hold" {
			nativeResult, err = applyHumanClearanceInTx(ctx, tx, r)
			if err != nil {
				return err
			}
			tablesChanged.Add("labels", "events", "config")
		} else if r.Effect.Kind == "archive-replace" || r.Effect.Kind == "validate" {
			nativeResult, tablesChanged, err = applyAuditValidationInTx(ctx, tx, r)
			if err != nil {
				return err
			}
		} else if r.Effect.Kind == "add-initial-human-hold" {
			nativeResult, err = applyInitialAuditHumanHoldInTx(ctx, tx, r)
			if err != nil {
				return err
			}
			tablesChanged.Add("labels", "events", "config")
		} else if r.Effect.Kind == "add-human-hold" {
			nativeResult, err = applyAuditHumanHoldInTx(ctx, tx, r)
			if err != nil {
				return err
			}
			tablesChanged.Add("labels", "events", "config")
		} else {
			before, err := storageissueops.GetIssueInTx(ctx, tx, r.Expected.IssueID)
			if err != nil {
				return err
			}
			var retiredMetadata map[string]json.RawMessage
			if r.Effect.Kind == "release-retire-pointer" {
				if before.Status != "open" && before.Status != "in_progress" {
					return guardtx.ErrUnsupported
				}
				retiredMetadata, err = guardops.RetirePointerMetadata(before.Metadata, r.Effect.ClaimPointer)
				if err != nil {
					return err
				}
			}
			native := issueops.ReleaseResult{Issue: before, Changed: false}
			write := storageissueops.ReleaseWrite{Tables: storageissueops.ChangedTables{}}
			// The guarded role can acknowledge an already-completed lifecycle
			// effect under this EXACT full-state expectation. Ordinary Releaser
			// still requires a holder; no row, lease or unclaimed event is forged.
			// Requested comments and the protected operation ledger follow below.
			if before.Status != "open" || before.Assignee != "" {
				expectedAssignee := before.Assignee
				nativeRequest := issueops.ReleaseRequest{
					Actor: r.Actor, IssueID: r.Expected.IssueID, ExpectedAssignee: &expectedAssignee,
				}
				if err := workapi.ValidateReleaseRequest(nativeRequest); err != nil {
					return err
				}
				native, write, err = storageissueops.ReleaseIssueInTx(ctx, tx, nativeRequest)
				if err != nil {
					return err
				}
			}
			nativeResult = native
			if r.Effect.Kind == "release-retire-pointer" {
				if err := storageissueops.DeleteMetadataInTx(ctx, tx, r.Expected.IssueID, "krewe_claim_run", r.Actor); err != nil {
					return err
				}
				updated, err := storageissueops.GetIssueInTx(ctx, tx, r.Expected.IssueID)
				if err != nil {
					return err
				}
				actual := map[string]json.RawMessage{}
				if len(updated.Metadata) > 0 && json.Unmarshal(updated.Metadata, &actual) != nil {
					return guardtx.ErrUnsupported
				}
				if len(actual) != len(retiredMetadata) {
					return guardtx.ErrUnsupported
				}
				for key, expected := range retiredMetadata {
					if string(actual[key]) != string(expected) {
						return guardtx.ErrUnsupported
					}
				}
				if _, exists := actual["krewe_claim_run"]; exists || updated.Status != "open" || updated.Assignee != "" {
					return guardtx.ErrUnsupported
				}
				native.Issue = updated
				commentID, err := addExactAuditComment(ctx, tx, r.Expected.IssueID, r.Actor, r.Effect.Comment)
				if err != nil {
					return err
				}
				write.Tables.Add("issues", "events", "comments")
				nativeResult = struct {
					issueops.ReleaseResult
					CommentID           string `json:"commentId"`
					RetiredClaimPointer string `json:"retiredClaimPointer"`
				}{native, commentID, r.Effect.ClaimPointer}
			} else if r.Effect.Kind == "release-with-comment" {
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
		if err := prepareAuditExplanationBinding(ctx, tx, r); err != nil {
			return err
		}
		publicationStarted = true
		message := "bd: guarded unclaim " + r.Expected.IssueID + " op " + r.OperationID
		if r.Effect.Kind == "clear-human-hold" {
			message = "bd: guarded clear human hold " + r.Expected.IssueID + " op " + r.OperationID
		} else if r.Effect.Kind == "archive-replace" || r.Effect.Kind == "validate" || r.Effect.Kind == "add-human-hold" || r.Effect.Kind == "add-initial-human-hold" || r.Effect.Kind == "audit-comment" {
			message = "bd: guarded audit " + r.Effect.Kind + " " + r.Expected.IssueID + " op " + r.OperationID
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
	priorEvents, err := auditHoldRemovalIDs(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	if err := storageissueops.RemoveLabelInTx(ctx, tx, "labels", "events", r.Expected.IssueID, "human-required", r.Actor); err != nil {
		return nil, err
	}
	currentEvents, err := auditHoldRemovalIDs(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	var removalEventID string
	for id := range currentEvents {
		if !priorEvents[id] {
			if removalEventID != "" {
				return nil, fmt.Errorf("%w: ambiguous native hold removal event", guardtx.ErrUnsupported)
			}
			removalEventID = id
		}
	}
	if removalEventID == "" || len(currentEvents) != len(priorEvents)+1 {
		return nil, fmt.Errorf("%w: missing native hold removal event", guardtx.ErrUnsupported)
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
	eventDigest, err := auditHoldLabelEventIDsDigest(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	return struct {
		IssueID                  string `json:"issueId"`
		Cleared                  bool   `json:"cleared"`
		MaterialVersion          string `json:"materialVersion"`
		HistoryComplete          bool   `json:"historyComplete"`
		RemovalEventID           string `json:"removalEventId"`
		ClearanceKey             string `json:"clearanceKey"`
		HistoryKey               string `json:"historyKey"`
		ClearLabelEventIDsDigest string `json:"clearLabelEventIdsDigest"`
	}{r.Expected.IssueID, true, clearance.Value.MaterialVersion, false, removalEventID, r.Effect.ClearanceKey, r.Effect.HistoryKey, eventDigest}, nil
}

// Audit policy is deliberately separate from release/clearance primitives. An
// exact snapshot does not authorize editing a claimed or completed work item.
func auditUnclaimedIssue(ctx context.Context, tx *sql.Tx, id string) (*types.Issue, error) {
	issue, err := storageissueops.GetIssueInTx(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	category, err := storageissueops.ReopenCategoryInTx(ctx, tx, issue.Status)
	if err != nil {
		return nil, err
	}
	metadata := map[string]json.RawMessage{}
	// The ordinary native reader represents the SQL NULL/empty default as an
	// empty RawMessage. That positively absent field has no claim pointer;
	// nonempty JSON must still be a known object, never null/array/scalar.
	if len(issue.Metadata) > 0 && (json.Unmarshal(issue.Metadata, &metadata) != nil || metadata == nil) {
		return nil, fmt.Errorf("%w: unknown native claim metadata", guardtx.ErrUnsupported)
	}
	var pointer string
	if raw, exists := metadata["krewe_claim_run"]; exists {
		var value any
		if json.Unmarshal(raw, &value) != nil {
			return nil, fmt.Errorf("%w: malformed native claim pointer", guardtx.ErrUnsupported)
		}
		var valid bool
		pointer, valid = value.(string)
		if !valid {
			return nil, fmt.Errorf("%w: malformed native claim pointer", guardtx.ErrUnsupported)
		}
	}
	if category == types.CategoryDone || issue.Status == types.StatusInProgress || issue.Assignee != "" || pointer != "" {
		return nil, fmt.Errorf("%w: audit requires unclaimed unclosed work", guardtx.ErrUnsupported)
	}
	return issue, nil
}

func requireAbsentAuditRecords(ctx context.Context, tx *sql.Tx, records []guardops.AuditRecord) error {
	for _, record := range records {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key`=?", "kv."+record.Key).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("%w: immutable audit key already exists", guardtx.ErrUnsupported)
		}
	}
	return nil
}
func appendAuditRecords(ctx context.Context, tx *sql.Tx, records []guardops.AuditRecord) error {
	for _, record := range records {
		key := "kv." + record.Key
		if err := storageissueops.SetConfigInTx(ctx, tx, key, record.Value); err != nil {
			return err
		}
		var actualKey, actualValue string
		if err := tx.QueryRowContext(ctx, "SELECT `key`,value FROM config WHERE `key`=?", key).Scan(&actualKey, &actualValue); err != nil {
			return err
		}
		if actualKey != key || actualValue != record.Value {
			return fmt.Errorf("%w: native audit KV did not preserve exact bytes", guardtx.ErrUnsupported)
		}
	}
	return nil
}
func addExactAuditComment(ctx context.Context, tx *sql.Tx, id, actor, body string) (string, error) {
	comment, err := storageissueops.AddIssueCommentInTx(ctx, tx, id, actor, body)
	if err != nil {
		return "", err
	}
	var stored string
	if err := tx.QueryRowContext(ctx, "SELECT text FROM comments WHERE id=?", comment.ID).Scan(&stored); err != nil {
		return "", err
	}
	if stored != body {
		return "", fmt.Errorf("%w: exact audit archive readback failed", guardtx.ErrUnsupported)
	}
	const query = "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='commented' AND actor=? AND CAST(comment AS BINARY)=CAST(? AS BINARY)"
	var before, after int
	if err := tx.QueryRowContext(ctx, query, id, actor, body).Scan(&before); err != nil {
		return "", err
	}
	if err := storageissueops.AddCommentEventInTx(ctx, tx, id, actor, body); err != nil {
		return "", err
	}
	if err := tx.QueryRowContext(ctx, query, id, actor, body).Scan(&after); err != nil {
		return "", err
	}
	if after != before+1 {
		return "", fmt.Errorf("%w: native archive event lost exact text", guardtx.ErrUnsupported)
	}
	return comment.ID, nil
}
func applyAuditValidationInTx(ctx context.Context, tx *sql.Tx, r guardops.Request) (any, storageissueops.ChangedTables, error) {
	tables := storageissueops.ChangedTables{}
	before, err := auditUnclaimedIssue(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, tables, err
	}
	records, err := guardops.DecodeAuditReceiptRecords(r.Effect.ReceiptRecordsJSON)
	if err != nil {
		return nil, tables, err
	}
	if err := requireAbsentAuditRecords(ctx, tx, records); err != nil {
		return nil, tables, err
	}
	archiveID := ""
	if r.Effect.Kind == "archive-replace" {
		parts := strings.SplitN(r.Effect.ArchiveComment, "\n", 4)
		if len(parts) != 4 || parts[3] != before.Description || r.Effect.AcceptedDescription == before.Description {
			return nil, tables, fmt.Errorf("%w: archive must preserve exact original before a changed replacement", guardtx.ErrUnsupported)
		}
		archiveID, err = addExactAuditComment(ctx, tx, r.Expected.IssueID, r.Actor, r.Effect.ArchiveComment)
		if err != nil {
			return nil, tables, err
		}
		// Native helper receives ONLY description. Archive/readback has already
		// completed in this transaction before any issue material is updated.
		update, err := storageissueops.UpdateIssueInTx(ctx, tx, r.Expected.IssueID, map[string]interface{}{"description": r.Effect.AcceptedDescription}, r.Actor)
		if err != nil {
			return nil, tables, err
		}
		if !update.Changed || update.IsWisp {
			return nil, tables, fmt.Errorf("%w: exact durable replacement required", guardtx.ErrUnsupported)
		}
		after, err := storageissueops.GetIssueInTx(ctx, tx, r.Expected.IssueID)
		if err != nil {
			return nil, tables, err
		}
		if after.Description != r.Effect.AcceptedDescription {
			return nil, tables, fmt.Errorf("%w: exact replacement readback failed", guardtx.ErrUnsupported)
		}
		tables.Add("issues", "events", "comments")
	}
	if err := appendAuditRecords(ctx, tx, records); err != nil {
		return nil, tables, err
	}
	tables.Add("config")
	keys := make([]string, 0, len(records))
	for _, record := range records {
		keys = append(keys, record.Key)
	}
	return struct {
		IssueID          string   `json:"issueId"`
		Validated        bool     `json:"validated"`
		ReceiptKeys      []string `json:"receiptKeys"`
		Replaced         bool     `json:"replaced,omitempty"`
		ArchiveCommentID string   `json:"archiveCommentId,omitempty"`
	}{r.Expected.IssueID, true, keys, archiveID != "", archiveID}, tables, nil
}

func auditHoldRemovalIDs(ctx context.Context, tx *sql.Tx, id string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM events WHERE issue_id=? AND event_type='label_removed' AND CAST(comment AS BINARY)=CAST('Removed label: human-required' AS BINARY)", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[string]bool{}
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			return nil, err
		}
		ids[eventID] = true
	}
	return ids, rows.Err()
}

func auditNamespaceRows(ctx context.Context, tx *sql.Tx, namespace string) ([]guardops.AuditRecord, error) {
	// Filtering in Go avoids LIKE wildcard/collation aliases of immutable keys.
	rows, err := tx.QueryContext(ctx, "SELECT `key`,value FROM config ORDER BY `key`")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []guardops.AuditRecord{}
	prefix := "kv.krewe.audit.v1." + namespace + "."
	for rows.Next() {
		var key string
		var raw sql.NullString
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		if strings.HasPrefix(key, prefix) {
			if !raw.Valid {
				return nil, fmt.Errorf("%w: unknown matching namespace record", guardtx.ErrUnsupported)
			}
			records = append(records, guardops.AuditRecord{Key: strings.TrimPrefix(key, "kv."), Value: raw.String})
		}
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Key < records[j].Key })
	return records, rows.Err()
}

func auditNamespaceDigest(records []guardops.AuditRecord) (string, error) {
	// Match JSON.stringify([[appKey,rawValue],...]) exactly. Go's default HTML
	// escaping differs from JS and must not change this original content proof.
	matching := make([][2]string, 0, len(records))
	for _, r := range records {
		matching = append(matching, [2]string{r.Key, r.Value})
	}
	var buffer strings.Builder
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(matching); err != nil {
		return "", err
	}
	encoded := strings.TrimSuffix(buffer.String(), "\n")
	var js strings.Builder
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '\\' && i+1 < len(encoded) {
			if strings.HasPrefix(encoded[i:], `\u2028`) {
				js.WriteRune('\u2028')
				i += 5
				continue
			}
			if strings.HasPrefix(encoded[i:], `\u2029`) {
				js.WriteRune('\u2029')
				i += 5
				continue
			}
			js.WriteByte(encoded[i])
			i++
			js.WriteByte(encoded[i])
			continue
		}
		js.WriteByte(encoded[i])
	}
	digest := sha256.Sum256([]byte(js.String()))
	return hex.EncodeToString(digest[:]), nil
}

func applyAuditHumanHoldInTx(ctx context.Context, tx *sql.Tx, r guardops.Request) (any, error) {
	if _, err := auditUnclaimedIssue(ctx, tx, r.Expected.IssueID); err != nil {
		return nil, err
	}
	hold, err := guardops.DecodeAuditHoldRecord(r)
	if err != nil {
		return nil, err
	}
	var held int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id=? AND CAST(label AS BINARY)=CAST('human-required' AS BINARY)", r.Expected.IssueID).Scan(&held); err != nil {
		return nil, err
	}
	if held != 0 {
		return nil, fmt.Errorf("%w: hold already exists", guardtx.ErrUnsupported)
	}
	records, err := auditNamespaceRows(ctx, tx, r.Effect.ClearanceNamespace)
	if err != nil {
		return nil, err
	}
	digest, err := auditNamespaceDigest(records)
	if err != nil {
		return nil, err
	}
	if digest != r.Effect.ClearanceContentDigest {
		return nil, fmt.Errorf("%w: original clearance content mismatch", guardtx.ErrUnsupported)
	}
	var latest guardops.AuditClearance
	var latestAt time.Time
	var latestKey string
	for _, record := range records {
		c, err := guardops.ParseAuditClearance(record.Key, record.Value, r.Effect.ClearanceNamespace)
		if err != nil {
			return nil, fmt.Errorf("%w: unknown clearance record", guardtx.ErrUnsupported)
		}
		at, err := time.Parse(time.RFC3339Nano, c.ClearedAt)
		if err != nil {
			return nil, err
		}
		if at.Equal(latestAt) {
			return nil, fmt.Errorf("%w: ambiguous clearance ordering", guardtx.ErrUnsupported)
		}
		if at.After(latestAt) {
			latest = c
			latestAt = at
			latestKey = record.Key
		}
	}
	if latestKey == "" || latest != hold.Value.Clearance || latest.MaterialVersion == r.Effect.MaterialVersion {
		return nil, fmt.Errorf("%w: identified changed-material clearance required; no-prior/legacy history is unknown", guardtx.ErrUnsupported)
	}
	// Positive provenance is the native operation result's exact keys and
	// removal event ID, never caller time versus server time. Old result rows
	// without this linkage remain unknown. Every observed removal must link.
	if err := verifyAuditClearanceProvenance(ctx, tx, r, hold, latestKey); err != nil {
		return nil, err
	}
	newRecord := guardops.AuditRecord{Key: r.Effect.HoldRecordKey, Value: r.Effect.HoldRecordValue}
	if err := requireAbsentAuditRecords(ctx, tx, []guardops.AuditRecord{newRecord}); err != nil {
		return nil, err
	}
	priorAdditions, err := auditHoldAdditionIDs(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	if err := storageissueops.AddLabelInTx(ctx, tx, "labels", "events", r.Expected.IssueID, "human-required", r.Actor); err != nil {
		return nil, err
	}
	if err := appendAuditRecords(ctx, tx, []guardops.AuditRecord{newRecord}); err != nil {
		return nil, err
	}
	additions, err := auditHoldAdditionIDs(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	holdEventID := ""
	for id := range additions {
		if !priorAdditions[id] {
			if holdEventID != "" {
				return nil, guardtx.ErrUnsupported
			}
			holdEventID = id
		}
	}
	if holdEventID == "" || len(additions) != len(priorAdditions)+1 {
		return nil, guardtx.ErrUnsupported
	}
	eventDigest, err := auditHoldLabelEventIDsDigest(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"issueId": r.Expected.IssueID, "held": true, "materialVersion": r.Effect.MaterialVersion, "historyComplete": false,
		"holdRecordKey": r.Effect.HoldRecordKey, "holdRecordValueDigest": guardops.RecordValueDigest(r.Effect.HoldRecordValue),
		"heldAt": hold.Value.HeldAt, "guardGeneration": r.Expected.Generation, "originalToken": r.Expected.Token,
		"clearanceNamespace": r.Effect.ClearanceNamespace, "clearanceContentDigest": r.Effect.ClearanceContentDigest, "holdEventId": holdEventID, "holdLabelEventIdsDigest": eventDigest,
	}, nil
}

func verifyAuditClearanceProvenance(ctx context.Context, tx *sql.Tx, r guardops.Request, hold guardops.AuditHoldEnvelope, latestKey string) error {
	records, err := auditNamespaceRows(ctx, tx, hold.Namespace)
	if err != nil {
		return err
	}
	linked := map[string]bool{}
	latestLinked := false
	for _, record := range records {
		var discriminator struct {
			Value struct {
				Kind string `json:"kind"`
			} `json:"value"`
		}
		if json.Unmarshal([]byte(record.Value), &discriminator) != nil {
			return fmt.Errorf("%w: unknown prospective hold history", guardtx.ErrUnsupported)
		}
		if discriminator.Value.Kind == "initial-unworkable-hold" {
			var initial guardops.InitialAuditHoldEnvelope
			if json.Unmarshal([]byte(record.Value), &initial) != nil {
				return guardtx.ErrUnsupported
			}
			var savedRaw string
			if err := tx.QueryRowContext(ctx, "SELECT result_json FROM bd_guard_operations WHERE operation_id=?", initial.Value.OperationID).Scan(&savedRaw); err != nil {
				return err
			}
			var saved guardops.Result
			if json.Unmarshal([]byte(savedRaw), &saved) != nil || saved.Protocol != guardops.Protocol || saved.Outcome != "applied" || saved.OperationID != initial.Value.OperationID {
				return guardtx.ErrUnsupported
			}
			linked, err := attestInitialNativeRecord(ctx, tx, guardops.RecordAttestationRequest{Expected: r.Expected, RecordKey: record.Key, RecordValue: record.Value}, saved)
			if err != nil {
				return err
			}
			if !linked {
				return guardtx.ErrUnsupported
			}
			continue
		}
		if discriminator.Value.Kind == "bounded-unworkable-hold" {
			var prior guardops.AuditHoldEnvelope
			if json.Unmarshal([]byte(record.Value), &prior) != nil {
				return guardtx.ErrUnsupported
			}
			proof := guardops.Request{OperationID: prior.Value.OperationID, Actor: prior.Value.Actor, Expected: guardops.Snapshot{Generation: prior.Value.GuardGeneration, Token: prior.Value.OriginalToken}, Effect: guardops.Effect{Kind: "add-human-hold", MaterialVersion: prior.Value.MaterialVersion, ClearanceNamespace: prior.Value.ClearanceNamespace, ClearanceContentDigest: prior.Value.ClearanceContentDigest, HoldRecordKey: record.Key, HoldRecordValue: record.Value}}
			if _, err := guardops.DecodeAuditHoldRecord(proof); err != nil {
				return fmt.Errorf("%w: malformed prospective hold history", guardtx.ErrUnsupported)
			}
			continue // This record claims no complete history or clearance event.
		}
		h, err := guardops.ParseAuditClearanceHistory(record.Key, record.Value, hold.Namespace)
		if err != nil {
			return fmt.Errorf("%w: unknown prospective clearance history", guardtx.ErrUnsupported)
		}
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT result_json FROM bd_guard_operations WHERE operation_id=?", h.Value.OperationID).Scan(&raw); err != nil {
			return fmt.Errorf("%w: missing native clearance operation", guardtx.ErrUnsupported)
		}
		var saved guardops.Result
		var result struct {
			IssueID                  string `json:"issueId"`
			Cleared                  bool   `json:"cleared"`
			MaterialVersion          string `json:"materialVersion"`
			HistoryComplete          *bool  `json:"historyComplete"`
			RemovalEventID           string `json:"removalEventId"`
			ClearanceKey             string `json:"clearanceKey"`
			HistoryKey               string `json:"historyKey"`
			ClearLabelEventIDsDigest string `json:"clearLabelEventIdsDigest"`
		}
		if json.Unmarshal([]byte(raw), &saved) != nil || saved.Protocol != guardops.Protocol || saved.Outcome != "applied" || saved.OperationID != h.Value.OperationID || json.Unmarshal([]byte(saved.ResultJSON), &result) != nil || result.IssueID != r.Expected.IssueID || !result.Cleared || result.HistoryComplete == nil || *result.HistoryComplete || result.MaterialVersion != h.Value.Clearance.MaterialVersion || result.RemovalEventID == "" || result.HistoryKey != record.Key || h.Value.GuardGeneration != r.Expected.Generation {
			return fmt.Errorf("%w: legacy or unlinked native clearance result", guardtx.ErrUnsupported)
		}
		var clearanceRaw string
		if err := tx.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+result.ClearanceKey).Scan(&clearanceRaw); err != nil {
			return err
		}
		clearance, err := guardops.ParseAuditClearance(result.ClearanceKey, clearanceRaw, r.Effect.ClearanceNamespace)
		if err != nil || clearance != h.Value.Clearance {
			return fmt.Errorf("%w: native clearance keys do not bind exact evidence", guardtx.ErrUnsupported)
		}
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE id=? AND issue_id=? AND event_type='label_removed' AND CAST(actor AS BINARY)=CAST(? AS BINARY) AND CAST(comment AS BINARY)=CAST('Removed label: human-required' AS BINARY)", result.RemovalEventID, r.Expected.IssueID, clearance.ClearedBy).Scan(&count); err != nil {
			return err
		}
		if count != 1 || linked[result.RemovalEventID] {
			return fmt.Errorf("%w: ambiguous native clearance event linkage", guardtx.ErrUnsupported)
		}
		linked[result.RemovalEventID] = true
		if !validStoredEventDigest(result.ClearLabelEventIDsDigest) {
			return fmt.Errorf("%w: unbound native clearance event set", guardtx.ErrUnsupported)
		}
		if result.ClearanceKey == latestKey {
			currentDigest, err := auditHoldLabelEventIDsDigest(ctx, tx, r.Expected.IssueID)
			if err != nil {
				return err
			}
			if result.ClearLabelEventIDsDigest != currentDigest {
				return fmt.Errorf("%w: later native or manual hold label event", guardtx.ErrUnsupported)
			}
			latestLinked = true
		}
	}
	removals, err := auditHoldRemovalIDs(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return err
	}
	if !latestLinked || len(removals) != len(linked) {
		return fmt.Errorf("%w: unknown legacy/manual clearance events", guardtx.ErrUnsupported)
	}
	for id := range removals {
		if !linked[id] {
			return fmt.Errorf("%w: unlinked manual clearance event", guardtx.ErrUnsupported)
		}
	}
	return nil
}

func (s *DoltStore) GuardedRecordAttester() (guardops.RecordAttester, error) {
	if s == nil {
		return nil, guardtx.ErrUnsupported
	}
	return &guardedMutator{store: s}, nil
}

func auditHoldAdditionIDs(ctx context.Context, tx *sql.Tx, id string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM events WHERE issue_id=? AND event_type='label_added' AND CAST(comment AS BINARY)=CAST('Added label: human-required' AS BINARY)", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := map[string]bool{}
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			return nil, err
		}
		if !nativeEventID(eventID) {
			return nil, guardtx.ErrUnsupported
		}
		ids[eventID] = true
	}
	return ids, rows.Err()
}
func nativeEventID(id string) bool {
	if parsed, err := uuid.Parse(id); err == nil && parsed.String() == id && parsed != uuid.Nil {
		return true
	}
	if id == "" || id[0] == '0' {
		return false
	}
	for _, ch := range id {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(id, 10, 64)
	return err == nil
}

// Attestation authenticates a currently captured immutable record against a
// durable native operation and its actual event. It grants no complete-history
// or current-episode inference; callers must account for later captured events.
func (g *guardedMutator) AttestRecord(ctx context.Context, r guardops.RecordAttestationRequest) (guardops.RecordAttestationResult, error) {
	result := guardops.RecordAttestationResult{Protocol: guardops.Protocol, RecordKey: r.RecordKey, RecordValueDigest: guardops.RecordValueDigest(r.RecordValue), Outcome: "unknown"}
	if err := guardops.ValidateRecordAttestation(r); err != nil {
		return result, err
	}
	err := g.withGuardReadTx(ctx, func(tx *sql.Tx) error {
		current, err := captureGuardState(ctx, tx, r.Expected.IssueID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, r.Expected) {
			result.Outcome = "conflict"
			result.Reason = "current native capture differs"
			return nil
		}
		var value string
		if err := tx.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+r.RecordKey).Scan(&value); err != nil {
			return err
		}
		if value != r.RecordValue {
			return guardtx.ErrUnsupported
		}
		rows, err := tx.QueryContext(ctx, "SELECT operation_id,request_digest,result_json FROM bd_guard_operations ORDER BY operation_id")
		if err != nil {
			return err
		}
		// Close the cursor before reading config/events on this single native session.
		type entry struct{ id, digest, raw string }
		entries := []entry{}
		for rows.Next() {
			var e entry
			if err := rows.Scan(&e.id, &e.digest, &e.raw); err != nil {
				rows.Close()
				return err
			}
			entries = append(entries, e)
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return rowErr
		}
		var identified *guardops.Result
		for _, e := range entries {
			// Distinct delivery ledgers are not audit mutation evidence.
			var discriminator struct {
				Protocol string `json:"protocol"`
			}
			if json.Unmarshal([]byte(e.raw), &discriminator) != nil || discriminator.Protocol != guardops.Protocol {
				continue
			}
			var saved guardops.Result
			if json.Unmarshal([]byte(e.raw), &saved) != nil || saved.Protocol != guardops.Protocol || saved.Outcome != "applied" || saved.OperationID != e.id || saved.RequestDigest != e.digest || guardops.ValidateLookup(guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: e.id, RequestDigest: e.digest}) != nil {
				continue
			}
			linked, err := attestNativeAuditRecord(ctx, tx, r, saved)
			if err != nil {
				return err
			}
			if linked {
				if identified != nil {
					return guardtx.ErrUnsupported
				}
				copy := saved
				identified = &copy
			}
		}
		if identified != nil {
			result.Outcome = "identified"
			result.Operation = identified
			var kind struct {
				Value struct {
					Kind string `json:"kind"`
				} `json:"value"`
			}
			if json.Unmarshal([]byte(r.RecordValue), &kind) != nil {
				return guardtx.ErrUnsupported
			}
			if kind.Value.Kind == "native-create-birth" || kind.Value.Kind == "initial-unworkable-hold" {
				intact, err := guardbirth.Intact(ctx, tx, r.Expected.IssueID)
				if err != nil {
					return err
				}
				result.CurrentIncarnationIntact = &intact
				if kind.Value.Kind == "native-create-birth" {
					eligible, err := nativeBirthAdmission(ctx, tx, r.Expected.IssueID)
					if err != nil {
						return err
					}
					result.InitialHoldEligible = &eligible
				}
			}
		} else {
			result.Reason = "record lacks exact native ledger and event binding"
		}
		return nil
	})
	if err != nil {
		result.Outcome = "unknown"
		result.Operation = nil
		result.InitialHoldEligible = nil
		result.CurrentIncarnationIntact = nil
		result.Reason = err.Error()
	}
	return result, err
}

func attestNativeAuditRecord(ctx context.Context, tx *sql.Tx, r guardops.RecordAttestationRequest, saved guardops.Result) (bool, error) {
	var kind struct {
		Value struct {
			Kind string `json:"kind"`
		} `json:"value"`
	}
	if json.Unmarshal([]byte(r.RecordValue), &kind) == nil && (kind.Value.Kind == "native-create-birth" || kind.Value.Kind == "initial-unworkable-hold") {
		return attestInitialNativeRecord(ctx, tx, r, saved)
	}
	var body struct {
		IssueID                  string `json:"issueId"`
		Held                     bool   `json:"held"`
		Cleared                  bool   `json:"cleared"`
		MaterialVersion          string `json:"materialVersion"`
		HistoryComplete          *bool  `json:"historyComplete"`
		HoldRecordKey            string `json:"holdRecordKey"`
		HoldRecordValueDigest    string `json:"holdRecordValueDigest"`
		HeldAt                   string `json:"heldAt"`
		GuardGeneration          string `json:"guardGeneration"`
		OriginalToken            string `json:"originalToken"`
		ClearanceNamespace       string `json:"clearanceNamespace"`
		ClearanceContentDigest   string `json:"clearanceContentDigest"`
		HoldEventID              string `json:"holdEventId"`
		HoldLabelEventIDsDigest  string `json:"holdLabelEventIdsDigest"`
		ClearanceKey             string `json:"clearanceKey"`
		HistoryKey               string `json:"historyKey"`
		ClearLabelEventIDsDigest string `json:"clearLabelEventIdsDigest"`
		RemovalEventID           string `json:"removalEventId"`
	}
	if json.Unmarshal([]byte(saved.ResultJSON), &body) != nil || body.IssueID != r.Expected.IssueID || body.HistoryComplete == nil || *body.HistoryComplete {
		return false, nil
	}
	var actor, eventID, eventType, eventComment string
	if body.Held && !body.Cleared && body.HoldRecordKey == r.RecordKey && body.HoldRecordValueDigest == guardops.RecordValueDigest(r.RecordValue) {
		var h guardops.AuditHoldEnvelope
		if json.Unmarshal([]byte(r.RecordValue), &h) != nil {
			return false, nil
		}
		proof := guardops.Request{OperationID: saved.OperationID, Actor: h.Value.Actor, Expected: guardops.Snapshot{Generation: r.Expected.Generation, Token: body.OriginalToken}, Effect: guardops.Effect{Kind: "add-human-hold", MaterialVersion: body.MaterialVersion, ClearanceNamespace: body.ClearanceNamespace, ClearanceContentDigest: body.ClearanceContentDigest, HoldRecordKey: r.RecordKey, HoldRecordValue: r.RecordValue}}
		parsed, err := guardops.DecodeAuditHoldRecord(proof)
		if err != nil || body.GuardGeneration != r.Expected.Generation || body.HeldAt != parsed.Value.HeldAt || !nativeEventID(body.HoldEventID) {
			return false, nil
		}
		// Historical authenticity survives later native clears. Current-episode
		// consumers separately compare this stored event-set digest with their
		// current captured image; the reader never grants active hold age.
		if !validStoredEventDigest(body.HoldLabelEventIDsDigest) {
			return false, nil
		}
		actor = parsed.Value.Actor
		eventID = body.HoldEventID
		eventType = "label_added"
		eventComment = "Added label: human-required"
	} else if body.Cleared && !body.Held && (body.ClearanceKey == r.RecordKey || body.HistoryKey == r.RecordKey) {
		var historyRaw, clearanceRaw string
		if err := tx.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+body.HistoryKey).Scan(&historyRaw); err != nil {
			return false, err
		}
		if err := tx.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+body.ClearanceKey).Scan(&clearanceRaw); err != nil {
			return false, err
		}
		var namespaces struct {
			Namespace string `json:"namespace"`
		}
		if json.Unmarshal([]byte(historyRaw), &namespaces) != nil {
			return false, nil
		}
		h, err := guardops.ParseAuditClearanceHistory(body.HistoryKey, historyRaw, namespaces.Namespace)
		if !validStoredEventDigest(body.ClearLabelEventIDsDigest) || err != nil || h.Value.OperationID != saved.OperationID || h.Value.GuardGeneration != r.Expected.Generation || body.MaterialVersion != h.Value.Clearance.MaterialVersion || !nativeEventID(body.RemovalEventID) {
			return false, nil
		}
		if json.Unmarshal([]byte(clearanceRaw), &namespaces) != nil {
			return false, nil
		}
		c, err := guardops.ParseAuditClearance(body.ClearanceKey, clearanceRaw, namespaces.Namespace)
		if err != nil || c != h.Value.Clearance {
			return false, nil
		}
		actor = c.ClearedBy
		eventID = body.RemovalEventID
		eventType = "label_removed"
		eventComment = "Removed label: human-required"
	} else {
		return false, nil
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE id=? AND issue_id=? AND event_type=? AND CAST(actor AS BINARY)=CAST(? AS BINARY) AND CAST(comment AS BINARY)=CAST(? AS BINARY)", eventID, r.Expected.IssueID, eventType, actor, eventComment).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

// Native events are immutable runtime facts. Comparing the complete target
// label-event set proves no subsequent ordinary clear/readd even when UUID IDs
// and second-precision timestamps carry no total causal ordering.
func auditHoldLabelEventIDsDigest(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id FROM events WHERE issue_id=? AND ((event_type='label_added' AND CAST(comment AS BINARY)=CAST('Added label: human-required' AS BINARY)) OR (event_type='label_removed' AND CAST(comment AS BINARY)=CAST('Removed label: human-required' AS BINARY)))", id)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var eventID string
		if err := rows.Scan(&eventID); err != nil {
			return "", err
		}
		if !nativeEventID(eventID) {
			return "", guardtx.ErrUnsupported
		}
		ids = append(ids, eventID)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	sort.Strings(ids)
	raw, err := json.Marshal(ids)
	if err != nil {
		return "", err
	}
	return guardops.RecordValueDigest(string(raw)), nil
}

func validStoredEventDigest(digest string) bool {
	b, err := hex.DecodeString(digest)
	return err == nil && len(b) == 32 && strings.ToLower(digest) == digest
}
