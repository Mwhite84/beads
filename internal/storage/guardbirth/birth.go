// Package guardbirth records prospective durable identity in an already bound
// native transaction. Its per-ID reservation and spent ledgers survive row and
// event deletion; config absence never makes a previously used ID new again.
package guardbirth

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
)

func Reserved(ctx context.Context, r guardtx.Runner, id string) (bool, error) {
	var n int
	err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id IN (?,?)", guardops.NativeBirthOperationID(id), guardops.NativeBirthSpentOperationID(id)).Scan(&n)
	return n != 0, err
}
func Spent(ctx context.Context, r guardtx.Runner, id string) (bool, error) {
	var n int
	err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id=?", guardops.NativeBirthSpentOperationID(id)).Scan(&n)
	if err != nil || n != 0 {
		return true, err
	}
	err = r.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key`=?", guardops.NativeBirthSpentKey(id)).Scan(&n)
	return n != 0, err
}

// Spend never rewrites a positive reservation. A native immutable operation is
// the enduring invalidator even if ordinary config later removes the marker.
func Spend(ctx context.Context, r guardtx.Runner, id, actor, reason string) (bool, error) {
	if !guardtx.Bound(r) {
		return false, nil
	}
	var n int
	if err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id=?", guardops.NativeBirthSpentOperationID(id)).Scan(&n); err != nil {
		return false, err
	}
	if n != 0 {
		return false, nil
	}
	raw, err := json.Marshal(map[string]any{"issueId": id, "spent": true, "actor": actor, "reason": reason, "scope": guardops.NativeBirthScope, "historyComplete": false})
	if err != nil {
		return false, err
	}
	digest := guardops.RecordValueDigest(string(raw))
	saved := guardops.Result{Protocol: guardops.Protocol, OperationID: guardops.NativeBirthSpentOperationID(id), RequestDigest: digest, Outcome: "applied", ResultJSON: string(raw)}
	encoded, err := json.Marshal(saved)
	if err != nil {
		return false, err
	}
	// A preexisting marker is conservative unknown; never overwrite its bytes.
	if err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key`=?", guardops.NativeBirthSpentKey(id)).Scan(&n); err != nil {
		return false, err
	}
	if n == 0 {
		if _, err := r.ExecContext(ctx, "INSERT INTO config (`key`,value) VALUES (?,?)", guardops.NativeBirthSpentKey(id), string(raw)); err != nil {
			return false, err
		}
	}
	if _, err := r.ExecContext(ctx, "INSERT INTO bd_guard_operations(operation_id,request_digest,result_json) VALUES(?,?,?)", saved.OperationID, digest, string(encoded)); err != nil {
		return false, err
	}
	guardtx.NotePublicationTables(r, "config", guardtx.OperationsTable)
	return true, nil
}

// Enroll runs only after successful durable CreateOnly and exact native create
// event insertion. Existing reservations/spent markers prohibit replacement.
func Enroll(ctx context.Context, r guardtx.Runner, id, actor, eventID string) (bool, error) {
	if !guardtx.Bound(r) {
		return false, nil
	}
	reserved, err := Reserved(ctx, r, id)
	if err != nil || reserved {
		return false, err
	}
	spent, err := Spent(ctx, r, id)
	if err != nil || spent {
		return false, err
	}
	var n int
	if err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=? AND ((event_type='label_added' AND CAST(comment AS BINARY)=CAST('Added label: human-required' AS BINARY)) OR (event_type='label_removed' AND CAST(comment AS BINARY)=CAST('Removed label: human-required' AS BINARY)))", id).Scan(&n); err != nil {
		return false, err
	}
	if n != 0 {
		return Spend(ctx, r, id, actor, "initial-human-label-history")
	}
	incarnation, err := guardtx.FreshIdentity()
	if err != nil {
		return false, err
	}
	var generation string
	if err := r.QueryRowContext(ctx, "SELECT generation FROM bd_guard_state WHERE id=1").Scan(&generation); err != nil {
		return false, err
	}
	incomplete := false
	b := guardops.NativeBirthEnvelope{Version: 1, Namespace: guardops.NativeBirthNamespace(id), Value: guardops.NativeBirthValue{Kind: "native-create-birth", Protocol: guardops.Protocol, IssueID: id, GuardGeneration: generation, Incarnation: incarnation, CreatedEventID: eventID, Actor: actor, InitialHumanLabelEventIDsDigest: guardops.RecordValueDigest("[]"), Scope: guardops.NativeBirthScope, HistoryComplete: &incomplete}}
	encoded, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	raw := string(encoded)
	key := guardops.AuditContentKey(b.Namespace, raw)
	if _, err := guardops.ParseNativeBirth(key, raw, id); err != nil {
		return Spend(ctx, r, id, actor, "unidentified-native-create")
	}
	// Orphaned namespace/config evidence cannot be enrolled as a clean birth.
	if err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key` LIKE ?", "kv.krewe.audit.v1."+b.Namespace+".%").Scan(&n); err != nil {
		return false, err
	}
	if n != 0 {
		return Spend(ctx, r, id, actor, "preexisting-birth-namespace")
	}
	result := guardops.NativeBirthResult{IssueID: id, Born: true, GuardGeneration: generation, Incarnation: incarnation, CreatedEventID: eventID, Actor: actor, BirthRecordKey: key, BirthRecordValueDigest: guardops.RecordValueDigest(raw), InitialHumanLabelEventIDsDigest: b.Value.InitialHumanLabelEventIDsDigest, Scope: guardops.NativeBirthScope, HistoryComplete: false}
	body, err := json.Marshal(result)
	if err != nil {
		return false, err
	}
	digest := guardops.NativeBirthDigest(b.Value, key, raw)
	saved, err := json.Marshal(guardops.Result{Protocol: guardops.Protocol, OperationID: guardops.NativeBirthOperationID(id), RequestDigest: digest, Outcome: "applied", ResultJSON: string(body)})
	if err != nil {
		return false, err
	}
	if _, err := r.ExecContext(ctx, "INSERT INTO config (`key`,value) VALUES (?,?)", "kv."+key, raw); err != nil {
		return false, err
	}
	var stored string
	if err := r.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+key).Scan(&stored); err != nil || stored != raw {
		return false, errors.Join(guardtx.ErrUnsupported, err)
	}
	if _, err := r.ExecContext(ctx, "INSERT INTO bd_guard_operations(operation_id,request_digest,result_json) VALUES(?,?,?)", guardops.NativeBirthOperationID(id), digest, string(saved)); err != nil {
		return false, err
	}
	guardtx.NotePublicationTables(r, "config", guardtx.OperationsTable)
	return true, nil
}

// Authenticate is historical only. Active continuity must additionally call
// Intact; neither routine treats a timestamp or UUID as an event ordering.
func Authenticate(ctx context.Context, r guardtx.Runner, id, generation, key, raw string) (guardops.NativeBirthEnvelope, guardops.Result, error) {
	b, err := guardops.ParseNativeBirth(key, raw, id)
	if err != nil {
		return b, guardops.Result{}, err
	}
	if b.Value.GuardGeneration != generation {
		return b, guardops.Result{}, guardtx.ErrUnsupported
	}
	var value, encoded, digest string
	if err := r.QueryRowContext(ctx, "SELECT value FROM config WHERE `key`=?", "kv."+key).Scan(&value); err != nil {
		return b, guardops.Result{}, err
	}
	if value != raw {
		return b, guardops.Result{}, guardtx.ErrUnsupported
	}
	if err := r.QueryRowContext(ctx, "SELECT request_digest,result_json FROM bd_guard_operations WHERE operation_id=?", guardops.NativeBirthOperationID(id)).Scan(&digest, &encoded); err != nil {
		return b, guardops.Result{}, err
	}
	var saved guardops.Result
	var result guardops.NativeBirthResult
	if json.Unmarshal([]byte(encoded), &saved) != nil {
		return b, saved, guardtx.ErrUnsupported
	}
	result, err = guardops.ParseNativeBirthResult(saved.ResultJSON)
	if err != nil || saved.Protocol != guardops.Protocol || saved.Outcome != "applied" || saved.OperationID != guardops.NativeBirthOperationID(id) || saved.RequestDigest != digest || digest != guardops.NativeBirthDigest(b.Value, key, raw) || result != (guardops.NativeBirthResult{IssueID: id, Born: true, GuardGeneration: generation, Incarnation: b.Value.Incarnation, CreatedEventID: b.Value.CreatedEventID, Actor: b.Value.Actor, BirthRecordKey: key, BirthRecordValueDigest: guardops.RecordValueDigest(raw), InitialHumanLabelEventIDsDigest: guardops.RecordValueDigest("[]"), Scope: guardops.NativeBirthScope, HistoryComplete: false}) {
		return b, saved, guardtx.ErrUnsupported
	}
	var n int
	if err := r.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE id=? AND issue_id=? AND event_type='created' AND CAST(actor AS BINARY)=CAST(? AS BINARY)", b.Value.CreatedEventID, id, b.Value.Actor).Scan(&n); err != nil {
		return b, saved, err
	}
	if n != 1 {
		return b, saved, guardtx.ErrUnsupported
	}
	return b, saved, nil
}
func Intact(ctx context.Context, r guardtx.Runner, id string) (bool, error) {
	spent, err := Spent(ctx, r, id)
	return !spent, err
}

// PublicationTables adds only the tables these bound native identity hooks own.
// Disabled databases preserve all original staging and SQL behavior.
func PublicationTables(r guardtx.Runner, tables []string) []string {
	touched := guardtx.PublicationTables(r)
	result := append([]string(nil), tables...)
	for _, name := range []string{"config", guardtx.OperationsTable} {
		if !touched[name] {
			continue
		}
		found := false
		for _, old := range result {
			if old == name {
				found = true
			}
		}
		if !found {
			result = append(result, name)
		}
	}
	return result
}
