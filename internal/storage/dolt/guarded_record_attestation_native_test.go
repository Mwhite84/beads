package dolt

import (
	"encoding/json"
	"github.com/steveyegge/beads/guardops"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestGuardedNativeRecordAttestationHoldClearanceHistoryAndReadOnlyRefusals(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedAuditHoldRequest(t, ctx, s, "")
	held, err := m.Apply(ctx, r)
	if err != nil || held.Outcome != "applied" {
		t.Fatalf("linked hold setup: %+v %v", held, err)
	}
	role, err := s.GuardedRecordAttester()
	if err != nil {
		t.Fatal(err)
	}
	current, err := m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	var clear guardops.Result
	if json.Unmarshal([]byte(stringMustAuditQuery(t, ctx, s, "SELECT result_json FROM bd_guard_operations WHERE operation_id=?", "native-human-clearance-1")), &clear) != nil {
		t.Fatal("missing actual native clear operation")
	}
	var keys struct {
		ClearanceKey string `json:"clearanceKey"`
		HistoryKey   string `json:"historyKey"`
	}
	if json.Unmarshal([]byte(clear.ResultJSON), &keys) != nil || keys.HistoryKey == "" {
		t.Fatal("missing actual native result record keys")
	}
	before := guardedNativeObserve(t, ctx, s)
	for _, key := range []string{r.Effect.HoldRecordKey, keys.ClearanceKey, keys.HistoryKey} {
		raw := stringMustAuditQuery(t, ctx, s, "SELECT value FROM config WHERE `key`=?", "kv."+key)
		request := guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: current, RecordKey: key, RecordValue: raw}
		result, err := role.AttestRecord(ctx, request)
		want := clear
		if key == r.Effect.HoldRecordKey {
			want = held
		}
		if err != nil || result.Outcome != "identified" || result.RecordKey != key || result.RecordValueDigest != guardops.RecordValueDigest(raw) || result.Operation == nil || !reflect.DeepEqual(*result.Operation, want) {
			t.Fatalf("exact native record not attested: %+v %v", result, err)
		}
	}
	after, err := m.Capture(ctx, r.Expected.IssueID)
	if err != nil || after != current || guardedNativeObserve(t, ctx, s) != before {
		t.Fatal("read-only attestation changed native state/history")
	}
	request := guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: current, RecordKey: r.Effect.HoldRecordKey, RecordValue: r.Effect.HoldRecordValue}
	// A positively recorded subsequent native clear must not destroy the
	// authenticity of the original hold record. Its age/active episode is a
	// different question: the current target event set must now differ.
	clearLater := r
	clearLater.Expected = current
	clearLater.OperationID = "native-human-clearance-2"
	clearance := map[string]any{"clearedBy": r.Actor, "clearedAt": "2026-10-10T13:30:00Z", "materialVersion": r.Effect.MaterialVersion}
	history := map[string]any{"kind": "identified-clearance", "operationId": clearLater.OperationID, "guardGeneration": current.Generation, "originalToken": current.Token, "baseline": "unknown-legacy", "historyComplete": false, "clearance": clearance}
	c := guardedAuditRecord(t, strings.Repeat("a", 64), clearance)
	h := guardedAuditRecord(t, strings.Repeat("b", 64), history)
	clearLater.Effect = guardops.Effect{Kind: "clear-human-hold", ClearanceKey: c.Key, ClearanceValue: c.Value, HistoryKey: h.Key, HistoryValue: h.Value}
	cleared, err := m.Apply(ctx, clearLater)
	if err != nil || cleared.Outcome != "applied" {
		t.Fatalf("recorded later clear failed: %+v %v", cleared, err)
	}
	request.Expected, err = m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	var latestClear struct {
		Digest string `json:"clearLabelEventIdsDigest"`
	}
	if json.Unmarshal([]byte(cleared.ResultJSON), &latestClear) != nil || latestClear.Digest == "" || latestClear.Digest != guardedCapturedHumanLabelEventSetDigest(t, request.Expected) {
		t.Fatal("new native clear lacks exact post-removal event-set binding")
	}
	before = guardedNativeObserve(t, ctx, s)
	historical, err := role.AttestRecord(ctx, request)
	if err != nil || historical.Outcome != "identified" || historical.Operation == nil || !reflect.DeepEqual(*historical.Operation, held) || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("native clear invalidated authentic historical hold: %+v %v", historical, err)
	}
	guardedRequireHistoricalHoldSetChanged(t, request.Expected, held)
	// A new ordinary material writer makes the original read expectation conflict.
	if err := s.UpdateIssue(ctx, r.Expected.IssueID, map[string]interface{}{"description": "ordinary later material"}, r.Actor); err != nil {
		t.Fatal(err)
	}
	before = guardedNativeObserve(t, ctx, s)
	conflict, err := role.AttestRecord(ctx, request)
	if err != nil || conflict.Outcome != "conflict" || conflict.Operation != nil || conflict.RecordValueDigest != guardops.RecordValueDigest(request.RecordValue) || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("stale record read fabricated attestation: %+v %v", conflict, err)
	}
	// Old ledger rows missing an addition-event binding must stay unknown.
	originalHeld := held
	var body map[string]any
	_ = json.Unmarshal([]byte(held.ResultJSON), &body)
	delete(body, "holdEventId")
	raw, _ := json.Marshal(body)
	held.ResultJSON = string(raw)
	saved, _ := json.Marshal(held)
	if _, err := s.db.ExecContext(ctx, "UPDATE bd_guard_operations SET result_json=? WHERE operation_id=?", string(saved), held.OperationID); err != nil {
		t.Fatal(err)
	}
	request.Expected, err = m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	before = guardedNativeObserve(t, ctx, s)
	unknown, err := role.AttestRecord(ctx, request)
	if err != nil || unknown.Outcome != "unknown" || unknown.Operation != nil || unknown.RecordKey != request.RecordKey || unknown.RecordValueDigest != guardops.RecordValueDigest(request.RecordValue) || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("legacy missing event binding inferred: %+v %v", unknown, err)
	}
	originalSaved, _ := json.Marshal(originalHeld)
	if _, err := s.db.ExecContext(ctx, "UPDATE bd_guard_operations SET result_json=? WHERE operation_id=?", string(originalSaved), originalHeld.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveLabel(ctx, r.Expected.IssueID, "human-required", "ordinary later human"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddLabel(ctx, r.Expected.IssueID, "human-required", "ordinary later human"); err != nil {
		t.Fatal(err)
	}
	request.Expected, err = m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	before = guardedNativeObserve(t, ctx, s)
	manual, err := role.AttestRecord(ctx, request)
	if err != nil || manual.Outcome != "identified" || manual.Operation == nil || !reflect.DeepEqual(*manual.Operation, originalHeld) || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("manual clear/readd erased historical authenticity: %+v %v", manual, err)
	}
	guardedRequireHistoricalHoldSetChanged(t, request.Expected, originalHeld)
	if latestClear.Digest == guardedCapturedHumanLabelEventSetDigest(t, request.Expected) {
		t.Fatal("later manual label changes retained current clear binding")
	}
	// Historical authentic native clear records remain identified after later
	// changes, but an older result without the prospective set field is unknown.
	clearRead := guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: request.Expected, RecordKey: c.Key, RecordValue: c.Value}
	before = guardedNativeObserve(t, ctx, s)
	identified, err := role.AttestRecord(ctx, clearRead)
	if err != nil || identified.Outcome != "identified" || identified.Operation == nil || !reflect.DeepEqual(*identified.Operation, cleared) || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("historical clear authenticity erased: %+v %v", identified, err)
	}
	var clearBody map[string]any
	_ = json.Unmarshal([]byte(cleared.ResultJSON), &clearBody)
	delete(clearBody, "clearLabelEventIdsDigest")
	oldBody, _ := json.Marshal(clearBody)
	cleared.ResultJSON = string(oldBody)
	oldSaved, _ := json.Marshal(cleared)
	if _, err := s.db.ExecContext(ctx, "UPDATE bd_guard_operations SET result_json=? WHERE operation_id=?", string(oldSaved), cleared.OperationID); err != nil {
		t.Fatal(err)
	}
	clearRead.Expected, err = m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	before = guardedNativeObserve(t, ctx, s)
	oldClear, err := role.AttestRecord(ctx, clearRead)
	if err != nil || oldClear.Outcome != "unknown" || oldClear.Operation != nil || guardedNativeObserve(t, ctx, s) != before {
		t.Fatalf("unbound old native clear became prospective evidence: %+v %v", oldClear, err)
	}

}

func TestGuardedNativeRecordAttestationEventIDsPreserveSelectedNativeUUIDsAndLegacyDecimals(t *testing.T) {
	for _, id := range []string{"84fbd648-cc0a-5aaa-95c9-2e0a2e85bfc5", "9007199254740993"} {
		if !nativeEventID(id) {
			t.Fatalf("actual native ID refused %s", id)
		}
	}
	for _, id := range []string{"", "0", "01", "-1", "1.5", "00000000-0000-0000-0000-000000000000", "84FBD648-CC0A-5AAA-95C9-2E0A2E85BFC5", "unknown", "9223372036854775808"} {
		if nativeEventID(id) {
			t.Fatalf("malformed native ID accepted %s", id)
		}
	}
}

func guardedRequireHistoricalHoldSetChanged(t *testing.T, snapshot guardops.Snapshot, held guardops.Result) {
	t.Helper()
	var bound struct {
		Digest string `json:"holdLabelEventIdsDigest"`
	}
	if json.Unmarshal([]byte(held.ResultJSON), &bound) != nil || bound.Digest == "" {
		t.Fatal("missing native bound original event set")
	}
	if guardedCapturedHumanLabelEventSetDigest(t, snapshot) == bound.Digest {
		t.Fatal("later clear/readd still authenticated old CURRENT episode")
	}
}
func guardedCapturedHumanLabelEventSetDigest(t *testing.T, snapshot guardops.Snapshot) string {
	t.Helper()
	var state struct {
		Events []map[string]*string `json:"events"`
	}
	if json.Unmarshal([]byte(snapshot.StateJSON), &state) != nil {
		t.Fatal("malformed current event capture")
	}
	ids := []string{}
	for _, event := range state.Events {
		if event["issue_id"] == nil || *event["issue_id"] != snapshot.IssueID || event["event_type"] == nil || event["comment"] == nil {
			continue
		}
		kind, comment := *event["event_type"], *event["comment"]
		if (kind == "label_added" && comment == "Added label: human-required") || (kind == "label_removed" && comment == "Removed label: human-required") {
			if event["id"] == nil {
				t.Fatal("missing target event ID")
			}
			ids = append(ids, *event["id"])
		}
	}
	sort.Strings(ids)
	raw, _ := json.Marshal(ids)
	return guardops.RecordValueDigest(string(raw))
}
