package dolt

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	storageissueops "github.com/steveyegge/beads/internal/storage/issueops"
)

const explanationBindingProtocol = "beads.guard.explanation-binding.v1"

type explanationBinding struct {
	Protocol      string `json:"protocol"`
	OperationID   string `json:"operationId"`
	RequestDigest string `json:"requestDigest"`
	IssueID       string `json:"issueId"`
	Database      string `json:"database"`
	Branch        string `json:"branch"`
	Generation    string `json:"generation"`
	Token         string `json:"token"`
	Actor         string `json:"actor"`
}

func explanationBindingKey(id string) string {
	return "bd.guard.explanation.binding.v1." + guardops.RecordValueDigest(id)
}
func explainsAuditKind(kind string) bool {
	return kind == "validate" || kind == "archive-replace" || kind == "add-human-hold" || kind == "add-initial-human-hold"
}

// This companion belongs to the ORIGINAL successful primary transaction. No
// current capture can reconstruct a missing historical permission binding.
func prepareAuditExplanationBinding(ctx context.Context, tx *sql.Tx, r guardops.Request) error {
	if !explainsAuditKind(r.Effect.Kind) {
		return guardtx.Prepare(ctx, tx)
	}
	token, err := guardtx.FreshIdentity()
	if err != nil {
		return err
	}
	e := r.Expected
	binding := explanationBinding{Protocol: explanationBindingProtocol, OperationID: r.OperationID, RequestDigest: guardops.Digest(r), IssueID: e.IssueID, Database: e.Database, Branch: e.Branch, Generation: e.Generation, Token: token, Actor: r.Actor}
	raw, err := json.Marshal(binding)
	if err != nil {
		return err
	}
	key := explanationBindingKey(r.OperationID)
	var n int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key`=?", key).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return fmt.Errorf("%w: immutable primary explanation binding already exists", guardtx.ErrUnsupported)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO config (`key`,value) VALUES (?,?)", key, string(raw)); err != nil {
		return err
	}
	var stored string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", key).Scan(&stored); err != nil {
		return err
	}
	if stored != string(raw) {
		return guardtx.ErrUnsupported
	}
	return guardtx.PrepareWithReservedToken(ctx, tx, token)
}
func (s *DoltStore) GuardedExplanationDeliverer() (guardops.ExplanationDeliverer, error) {
	if s == nil {
		return nil, guardtx.ErrUnsupported
	}
	return &guardedMutator{store: s}, nil
}
func lookupExplanation(ctx context.Context, tx *sql.Tx, r guardops.ExplanationLookupRequest) (guardops.ExplanationResult, error) {
	result := guardops.ExplanationResult{Protocol: guardops.ExplanationProtocol, OperationID: r.OperationID, RequestDigest: r.RequestDigest, Outcome: "absent"}
	if !guardtx.Bound(tx) {
		return result, guardtx.ErrUnsupported
	}
	var digest, raw string
	err := tx.QueryRowContext(ctx, "SELECT request_digest,result_json FROM bd_guard_operations WHERE operation_id=?", r.OperationID).Scan(&digest, &raw)
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
	var saved guardops.ExplanationResult
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&saved) != nil || saved.Protocol != guardops.ExplanationProtocol || saved.OperationID != r.OperationID || saved.RequestDigest != digest || saved.Outcome != "applied" || !nativeEventID(saved.CommentID) || saved.Reason != "" {
		return result, fmt.Errorf("guard: invalid durable explanation delivery")
	}
	return saved, nil
}
func (g *guardedMutator) LookupExplanation(ctx context.Context, r guardops.ExplanationLookupRequest) (guardops.ExplanationResult, error) {
	result := guardops.ExplanationResult{Protocol: guardops.ExplanationProtocol, OperationID: r.OperationID, RequestDigest: r.RequestDigest, Outcome: "unknown"}
	if err := guardops.ValidateExplanationLookup(r); err != nil {
		result.Reason = err.Error()
		return result, err
	}
	err := g.withGuardReadTx(ctx, func(tx *sql.Tx) error { var err error; result, err = lookupExplanation(ctx, tx, r); return err })
	if err != nil {
		result.Outcome = "unknown"
		result.CommentID = ""
		result.Reason = err.Error()
	}
	return result, err
}
func (g *guardedMutator) Explain(ctx context.Context, r guardops.ExplanationRequest) (guardops.ExplanationResult, error) {
	digest := guardops.ExplanationDigest(r)
	result := guardops.ExplanationResult{Protocol: guardops.ExplanationProtocol, OperationID: r.OperationID, RequestDigest: digest, Outcome: "refused"}
	if err := guardops.ValidateExplanation(r); err != nil {
		result.Reason = err.Error()
		return result, err
	}
	if storageissueops.VersionCommitDeferred(ctx) {
		err := fmt.Errorf("%w: explanation requires native history publication", guardtx.ErrUnsupported)
		result.Reason = err.Error()
		return result, err
	}
	publicationStarted := false
	err := g.store.withWriteTx(ctx, func(tx *sql.Tx) error {
		prior, err := lookupExplanation(ctx, tx, guardops.ExplanationLookupRequest{Protocol: r.Protocol, OperationID: r.OperationID, RequestDigest: digest})
		if err != nil {
			return err
		}
		if prior.Outcome != "absent" {
			result = prior
			result.Replayed = prior.Outcome == "applied"
			return nil
		}
		original := r.OriginalRequest
		saved, err := lookupGuardOperation(ctx, tx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: original.OperationID, RequestDigest: guardops.Digest(original)})
		if err != nil {
			return err
		}
		if saved.Outcome != "applied" {
			return fmt.Errorf("%w: original audit operation is not confirmed applied", guardtx.ErrUnsupported)
		}
		current, err := captureGuardState(ctx, tx, r.Expected.IssueID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, r.Expected) {
			return guardtx.ErrConflict
		}
		// Exact current token equality refuses EVERY intervening supported writer,
		// including unrelated config/lease/ignored writes and recreate/import paths.
		var raw string
		if err := tx.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", explanationBindingKey(original.OperationID)).Scan(&raw); err != nil {
			return err
		}
		expected := explanationBinding{Protocol: explanationBindingProtocol, OperationID: original.OperationID, RequestDigest: guardops.Digest(original), IssueID: current.IssueID, Database: current.Database, Branch: current.Branch, Generation: current.Generation, Token: current.Token, Actor: original.Actor}
		canonical, err := json.Marshal(expected)
		if err != nil {
			return err
		}
		if raw != string(canonical) {
			return fmt.Errorf("%w: primary audit lineage has changed or is unknown", guardtx.ErrUnsupported)
		}
		if _, err := auditUnclaimedIssue(ctx, tx, current.IssueID); err != nil {
			return err
		}
		commentID, err := addExactAuditComment(ctx, tx, current.IssueID, original.Actor, r.Comment)
		if err != nil {
			return err
		}
		if !nativeEventID(commentID) {
			return fmt.Errorf("%w: native comment identity unavailable", guardtx.ErrUnsupported)
		}
		result.Outcome = "applied"
		result.CommentID = commentID
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO bd_guard_operations(operation_id,request_digest,result_json) VALUES(?,?,?)", result.OperationID, digest, string(encoded)); err != nil {
			return err
		}
		if err := guardtx.Prepare(ctx, tx); err != nil {
			return err
		}
		publicationStarted = true
		return g.store.doltAddAndCommitInTx(ctx, tx, []string{"comments", "events", guardtx.OperationsTable}, "bd: guarded audit explanation "+current.IssueID+" op "+result.OperationID)
	})
	if err != nil {
		result.CommentID = ""
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
	// As with the original Apply role, a fresh durable ledger lookup is the
	// confirmation boundary; unavailable readback cannot claim delivery success.
	verified, err := g.LookupExplanation(ctx, guardops.ExplanationLookupRequest{Protocol: r.Protocol, OperationID: r.OperationID, RequestDigest: digest})
	if err != nil || verified.Outcome != "applied" {
		result.Outcome = "unknown"
		result.CommentID = ""
		result.Reason = "protected explanation not yet resolved by operation lookup"
		return result, err
	}
	verified.Replayed = result.Replayed
	return verified, nil
}
