package dolt

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardbirth"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	storageissueops "github.com/steveyegge/beads/internal/storage/issueops"
)

func nativeBirthAdmission(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	intact, err := guardbirth.Intact(ctx, tx, id)
	if err != nil || !intact {
		return false, err
	}
	if _, err := auditUnclaimedIssue(ctx, tx, id); err != nil {
		if errors.Is(err, guardtx.ErrUnsupported) {
			return false, nil
		}
		return false, err
	}
	var held int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id=? AND CAST(label AS BINARY)=CAST('human-required' AS BINARY)", id).Scan(&held); err != nil {
		return false, err
	}
	if held != 0 {
		return false, nil
	}
	digest, err := auditHoldLabelEventIDsDigest(ctx, tx, id)
	return err == nil && digest == guardops.RecordValueDigest("[]"), err
}
func applyInitialAuditHumanHoldInTx(ctx context.Context, tx *sql.Tx, r guardops.Request) (any, error) {
	hold, err := guardops.DecodeInitialAuditHoldRecord(r)
	if err != nil {
		return nil, err
	}
	var raw string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+r.Effect.BirthRecordKey).Scan(&raw); err != nil {
		return nil, err
	}
	if guardops.RecordValueDigest(raw) != r.Effect.BirthRecordValueDigest {
		return nil, guardtx.ErrUnsupported
	}
	birth, _, err := guardbirth.Authenticate(ctx, tx, r.Expected.IssueID, r.Expected.Generation, r.Effect.BirthRecordKey, raw)
	if err != nil {
		return nil, err
	}
	if birth.Value.Incarnation != hold.Value.Birth.Incarnation || birth.Value.CreatedEventID != hold.Value.Birth.CreatedEventID {
		return nil, guardtx.ErrUnsupported
	}
	eligible, err := nativeBirthAdmission(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	if !eligible {
		return nil, guardtx.ErrUnsupported
	}
	for _, namespace := range []string{r.Effect.ClearanceNamespace, hold.Namespace} {
		records, err := auditNamespaceRows(ctx, tx, namespace)
		if err != nil {
			return nil, err
		}
		if len(records) != 0 {
			return nil, guardtx.ErrUnsupported
		}
	}
	record := guardops.AuditRecord{Key: r.Effect.HoldRecordKey, Value: r.Effect.HoldRecordValue}
	if err := requireAbsentAuditRecords(ctx, tx, []guardops.AuditRecord{record}); err != nil {
		return nil, err
	}
	if err := storageissueops.AddLabelInTx(ctx, tx, "labels", "events", r.Expected.IssueID, "human-required", r.Actor); err != nil {
		return nil, err
	}
	if err := appendAuditRecords(ctx, tx, []guardops.AuditRecord{record}); err != nil {
		return nil, err
	}
	additions, err := auditHoldAdditionIDs(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	if len(additions) != 1 {
		return nil, guardtx.ErrUnsupported
	}
	holdEventID := ""
	for id := range additions {
		holdEventID = id
	}
	digest, err := auditHoldLabelEventIDsDigest(ctx, tx, r.Expected.IssueID)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"issueId": r.Expected.IssueID, "held": true, "materialVersion": r.Effect.MaterialVersion, "historyComplete": false,
		"holdRecordKey": r.Effect.HoldRecordKey, "holdRecordValueDigest": guardops.RecordValueDigest(r.Effect.HoldRecordValue),
		"heldAt": hold.Value.HeldAt, "guardGeneration": r.Expected.Generation, "originalToken": r.Expected.Token,
		"clearanceNamespace": r.Effect.ClearanceNamespace, "clearanceContentDigest": r.Effect.ClearanceContentDigest,
		"holdEventId": holdEventID, "holdLabelEventIdsDigest": digest,
		"birthRecordKey": r.Effect.BirthRecordKey, "birthRecordValueDigest": r.Effect.BirthRecordValueDigest,
		"incarnation": birth.Value.Incarnation, "createdEventId": birth.Value.CreatedEventID,
	}, nil
}

func attestInitialNativeRecord(ctx context.Context, tx *sql.Tx, r guardops.RecordAttestationRequest, saved guardops.Result) (bool, error) {
	var outer struct {
		Value struct {
			Kind string `json:"kind"`
		} `json:"value"`
	}
	if json.Unmarshal([]byte(r.RecordValue), &outer) != nil {
		return false, nil
	}
	if outer.Value.Kind == "native-create-birth" {
		if saved.OperationID != guardops.NativeBirthOperationID(r.Expected.IssueID) {
			return false, nil
		}
		_, actual, err := guardbirth.Authenticate(ctx, tx, r.Expected.IssueID, r.Expected.Generation, r.RecordKey, r.RecordValue)
		if err != nil {
			return false, err
		}
		return actual == saved, nil
	}
	if outer.Value.Kind != "initial-unworkable-hold" {
		return false, nil
	}
	var h guardops.InitialAuditHoldEnvelope
	if json.Unmarshal([]byte(r.RecordValue), &h) != nil {
		return false, nil
	}
	e := guardops.Effect{Kind: "add-initial-human-hold", MaterialVersion: h.Value.MaterialVersion, ClearanceNamespace: h.Value.ClearanceNamespace, ClearanceContentDigest: h.Value.ClearanceContentDigest, HoldRecordKey: r.RecordKey, HoldRecordValue: r.RecordValue, BirthRecordKey: h.Value.Birth.RecordKey, BirthRecordValueDigest: h.Value.Birth.RecordValueDigest}
	proof := guardops.Request{OperationID: saved.OperationID, Actor: h.Value.Actor, Expected: guardops.Snapshot{IssueID: r.Expected.IssueID, Generation: r.Expected.Generation, Token: h.Value.OriginalToken}, Effect: e}
	if _, err := guardops.DecodeInitialAuditHoldRecord(proof); err != nil {
		return false, nil
	}
	var body struct {
		IssueID                 string `json:"issueId"`
		Held                    bool   `json:"held"`
		HistoryComplete         *bool  `json:"historyComplete"`
		MaterialVersion         string `json:"materialVersion"`
		HoldRecordKey           string `json:"holdRecordKey"`
		HoldRecordValueDigest   string `json:"holdRecordValueDigest"`
		HeldAt                  string `json:"heldAt"`
		GuardGeneration         string `json:"guardGeneration"`
		OriginalToken           string `json:"originalToken"`
		ClearanceNamespace      string `json:"clearanceNamespace"`
		ClearanceContentDigest  string `json:"clearanceContentDigest"`
		HoldEventID             string `json:"holdEventId"`
		HoldLabelEventIDsDigest string `json:"holdLabelEventIdsDigest"`
		BirthRecordKey          string `json:"birthRecordKey"`
		BirthRecordValueDigest  string `json:"birthRecordValueDigest"`
		Incarnation             string `json:"incarnation"`
		CreatedEventID          string `json:"createdEventId"`
	}
	if json.Unmarshal([]byte(saved.ResultJSON), &body) != nil || body.IssueID != r.Expected.IssueID || !body.Held || body.HistoryComplete == nil || *body.HistoryComplete || body.MaterialVersion != h.Value.MaterialVersion || body.HoldRecordKey != r.RecordKey || body.HoldRecordValueDigest != guardops.RecordValueDigest(r.RecordValue) || body.HeldAt != h.Value.HeldAt || body.GuardGeneration != h.Value.GuardGeneration || body.OriginalToken != h.Value.OriginalToken || body.ClearanceNamespace != h.Value.ClearanceNamespace || body.ClearanceContentDigest != h.Value.ClearanceContentDigest || body.BirthRecordKey != e.BirthRecordKey || body.BirthRecordValueDigest != e.BirthRecordValueDigest || body.Incarnation != h.Value.Birth.Incarnation || body.CreatedEventID != h.Value.Birth.CreatedEventID || !nativeEventID(body.HoldEventID) || !validStoredEventDigest(body.HoldLabelEventIDsDigest) {
		return false, nil
	}
	var raw string
	if err := tx.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+body.BirthRecordKey).Scan(&raw); err != nil {
		return false, err
	}
	if guardops.RecordValueDigest(raw) != body.BirthRecordValueDigest {
		return false, nil
	}
	birth, _, err := guardbirth.Authenticate(ctx, tx, r.Expected.IssueID, r.Expected.Generation, body.BirthRecordKey, raw)
	if err != nil {
		return false, err
	}
	if birth.Value.Incarnation != body.Incarnation || birth.Value.CreatedEventID != body.CreatedEventID {
		return false, nil
	}
	var n int
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE id=? AND issue_id=? AND event_type='label_added' AND CAST(actor AS BINARY)=CAST(? AS BINARY) AND CAST(comment AS BINARY)=CAST('Added label: human-required' AS BINARY)", body.HoldEventID, r.Expected.IssueID, h.Value.Actor).Scan(&n)
	return n == 1, err
}
