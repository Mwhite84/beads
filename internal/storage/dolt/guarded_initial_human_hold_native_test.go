package dolt

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage"
	"github.com/steveyegge/beads/internal/storage/domain"
	nativedb "github.com/steveyegge/beads/internal/storage/domain/db"
	"github.com/steveyegge/beads/internal/types"
	publicops "github.com/steveyegge/beads/issueops"
)

func guardedInitialCreate(t *testing.T, ctx context.Context, s *DoltStore, id string, only bool) {
	t.Helper()
	guardedInitialCreateAs(t, ctx, s, id, only, "birth-owner", "genuine original material")
}

func guardedInitialReplacementCreate(t *testing.T, ctx context.Context, s *DoltStore, id string) {
	t.Helper()
	// Rename retains the old created event under its original UUID. A genuine
	// replacement uses a distinct actor so same-second native event derivation
	// cannot collide with that retained event before birth refusal is exercised.
	guardedInitialCreateAs(t, ctx, s, id, true, "replacement-owner-"+id, "genuine replacement material")
}

func guardedInitialCreateAs(t *testing.T, ctx context.Context, s *DoltStore, id string, only bool, actor, description string) {
	t.Helper()
	if err := s.SetConfig(ctx, "issue_prefix", "guard"); err != nil {
		t.Fatal(err)
	}
	issue := &types.Issue{ID: id, Title: id, Description: description, Status: types.StatusOpen, Priority: 2, IssueType: types.TypeTask}
	if err := s.CreateIssuesWithFullOptions(ctx, []*types.Issue{issue}, actor, storage.BatchCreateOptions{CreateOnly: only, SkipPrefixValidation: true}); err != nil {
		t.Fatal(err)
	}
}

type guardedAuditNullableObservation struct {
	Assignee                       sql.NullString
	Status, LeaseJSON, Head, Token string
	RowVersion                     int64
	Started                        sql.NullTime
	Unclaimed, Operations, Commits int
}

// CreateOnly genuinely stores an unassigned assignee as SQL NULL. Retain that
// physical validity bit in every before/after comparison instead of changing
// the native fixture or normalizing NULL into an empty string.
func guardedAuditObserveNullable(t *testing.T, ctx context.Context, store *DoltStore) guardedAuditNullableObservation {
	t.Helper()
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var o guardedAuditNullableObservation
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
func guardedInitialRequest(t *testing.T, ctx context.Context, s *DoltStore, id string) (guardops.Mutator, guardops.Request, string, string) {
	t.Helper()
	m, err := s.GuardedMutator()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := m.Capture(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	ns := guardops.RecordValueDigest("beads.guard.birth.v1\x00" + id)
	rows, err := s.db.QueryContext(ctx, "SELECT `key`,value FROM config WHERE `key` LIKE ?", "kv.krewe.audit.v1."+ns+".%")
	if err != nil {
		t.Fatal(err)
	}
	var key, raw string
	for rows.Next() {
		if key != "" {
			t.Fatal("duplicate native birth records")
		}
		if err := rows.Scan(&key, &raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	if key == "" {
		t.Fatal("genuine CreateOnly lacks native birth enrollment")
	}
	key = strings.TrimPrefix(key, "kv.")
	var birth struct {
		Value struct {
			Incarnation    string `json:"incarnation"`
			CreatedEventID string `json:"createdEventId"`
		}
	}
	if err := json.Unmarshal([]byte(raw), &birth); err != nil {
		t.Fatal(err)
	}
	r := guardops.Request{Protocol: guardops.Protocol, OperationID: "native-initial-hold-1", Actor: "birth-owner", Expected: snap, ContextJSON: `{"boundedReview":"cold-unworkable"}`}
	reference := map[string]any{"recordKey": key, "recordValueDigest": guardops.RecordValueDigest(raw), "incarnation": birth.Value.Incarnation, "createdEventId": birth.Value.CreatedEventID}
	v := map[string]any{"kind": "initial-unworkable-hold", "operationId": r.OperationID, "guardGeneration": snap.Generation, "originalToken": snap.Token, "actor": r.Actor, "heldAt": "2026-10-10T12:34:56Z", "materialVersion": "first-material", "clearanceNamespace": strings.Repeat("a", 64), "clearanceContentDigest": guardops.RecordValueDigest("[]"), "baseline": "native-create-birth", "scope": "native-incarnation-since-create", "historyComplete": false, "clearance": nil, "birth": reference}
	record := guardedAuditRecord(t, strings.Repeat("b", 64), v)
	// Decode through the public wire: tests don't need future Effect fields to compile on RED.
	wire := map[string]any{"protocol": r.Protocol, "operationId": r.OperationID, "actor": r.Actor, "expected": snap, "contextJson": r.ContextJSON, "effect": map[string]any{"kind": "add-initial-human-hold", "materialVersion": "first-material", "clearanceNamespace": strings.Repeat("a", 64), "clearanceContentDigest": guardops.RecordValueDigest("[]"), "holdRecordKey": record.Key, "holdRecordValue": record.Value, "birthRecordKey": key, "birthRecordValueDigest": guardops.RecordValueDigest(raw)}}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	r, err = guardops.DecodeRequest(encoded)
	if err != nil {
		t.Fatalf("initial effect public wire: %v", err)
	}
	return m, r, key, raw
}
func TestGuardedNativeInitialHumanHoldGenuineCreateAndHistoricalAttestation(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	guardedInitialCreate(t, ctx, s, "guard-target", true)
	m, r, key, raw := guardedInitialRequest(t, ctx, s, "guard-target")
	role, err := s.GuardedRecordAttester()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := role.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: r.Expected, RecordKey: key, RecordValue: raw})
	if err != nil || proof.Outcome != "identified" || proof.Operation == nil || proof.InitialHoldEligible == nil || !*proof.InitialHoldEligible || proof.CurrentIncarnationIntact == nil || !*proof.CurrentIncarnationIntact {
		t.Fatalf("native birth not attested: %+v %v", proof, err)
	}
	applied, err := m.Apply(ctx, r)
	if err != nil || applied.Outcome != "applied" {
		t.Fatalf("first hold: %+v %v", applied, err)
	}
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id=? AND label='human-required'", r.Expected.IssueID).Scan(&count); err != nil || count != 1 {
		t.Fatal("initial hold not durable", err)
	}
	current, err := m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range []struct{ key, raw string }{{key, raw}, {r.Effect.HoldRecordKey, r.Effect.HoldRecordValue}} {
		result, err := role.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: current, RecordKey: record.key, RecordValue: record.raw})
		if err != nil || result.Outcome != "identified" {
			t.Fatalf("historical birth/hold lost authenticity: %+v %v", result, err)
		}
	}
	replay, err := m.Apply(ctx, r)
	if err != nil || replay.Outcome != "applied" || replay.ResultJSON != applied.ResultJSON {
		t.Fatalf("exact initial operation not deduplicated: %+v %v", replay, err)
	}
}
func TestGuardedNativeInitialHumanHoldNoImportOrReplacementBirth(t *testing.T) {
	for _, mode := range []string{"upsert", "delete-recreate", "bulk-delete-recreate", "legacy", "legacy-rename-recreate"} {
		t.Run(mode, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			if strings.HasPrefix(mode, "legacy") {
				guardedInitialCreate(t, ctx, s, "guard-target", true)
			}
			if err := s.InitializeGuard(ctx); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(mode, "legacy") {
				guardedInitialCreate(t, ctx, s, "guard-target", mode != "upsert")
			}
			if mode == "delete-recreate" {
				if err := s.DeleteIssue(ctx, "guard-target"); err != nil {
					t.Fatal(err)
				}
				guardedInitialCreate(t, ctx, s, "guard-target", true)
			}
			if mode == "bulk-delete-recreate" {
				if _, err := s.DeleteIssues(ctx, []string{"guard-target"}, false, true, false); err != nil {
					t.Fatal(err)
				}
				guardedInitialCreate(t, ctx, s, "guard-target", true)
			}
			if mode == "legacy-rename-recreate" {
				issue, err := s.GetIssue(ctx, "guard-target")
				if err != nil {
					t.Fatal(err)
				}
				if err := s.UpdateIssueID(ctx, "guard-target", "guard-renamed", issue, "ordinary"); err != nil {
					t.Fatal(err)
				}
				guardedInitialReplacementCreate(t, ctx, s, "guard-target")
				if err := s.DeleteIssue(ctx, "guard-renamed"); err != nil {
					t.Fatal(err)
				}
				guardedInitialReplacementCreate(t, ctx, s, "guard-renamed")
				var reserved int
				if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id IN (?,?)", guardops.NativeBirthOperationID("guard-target"), guardops.NativeBirthOperationID("guard-renamed")).Scan(&reserved); err != nil || reserved != 0 {
					t.Fatal("legacy rename minted replacement birth", reserved, err)
				}
			}
			var births int
			ns := guardops.RecordValueDigest("beads.guard.birth.v1\x00guard-target")
			if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key` LIKE ?", "kv.krewe.audit.v1."+ns+".%").Scan(&births); err != nil {
				t.Fatal(err)
			}
			if mode == "upsert" || strings.HasPrefix(mode, "legacy") {
				if births != 0 {
					t.Fatal("unknown history enrolled positive birth")
				}
			} else {
				if births != 1 {
					t.Fatal("deletion replaced/removed immutable birth")
				}
				m, r, key, raw := guardedInitialRequest(t, ctx, s, "guard-target")
				role, _ := s.GuardedRecordAttester()
				proof, err := role.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: r.Expected, RecordKey: key, RecordValue: raw})
				if proof.Outcome == "identified" && err == nil && (proof.CurrentIncarnationIntact == nil || *proof.CurrentIncarnationIntact || proof.InitialHoldEligible == nil || *proof.InitialHoldEligible) {
					t.Fatal("historical proof failed to refuse spent current incarnation")
				}
				result, err := m.Apply(ctx, r)
				if err == nil && result.Outcome == "applied" {
					t.Fatal("spent birth authorized replacement hold")
				}
			}
		})
	}
}

func guardedInitialRebind(t *testing.T, ctx context.Context, m guardops.Mutator, r guardops.Request) guardops.Request {
	t.Helper()
	current, err := m.Capture(ctx, r.Expected.IssueID)
	if err != nil {
		t.Fatal(err)
	}
	var h guardops.InitialAuditHoldEnvelope
	if err := json.Unmarshal([]byte(r.Effect.HoldRecordValue), &h); err != nil {
		t.Fatal(err)
	}
	r.Expected = current
	h.Value.GuardGeneration = current.Generation
	h.Value.OriginalToken = current.Token
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	r.Effect.HoldRecordValue = string(raw)
	r.Effect.HoldRecordKey = guardops.AuditContentKey(h.Namespace, string(raw))
	return r
}
func TestGuardedNativeInitialHumanHoldRefusesActualEvidenceChanges(t *testing.T) {
	for _, mode := range []string{"claimed", "manual-label-cycle", "clearance-kv", "history-kv", "same-value-upsert", "removed-spent-config", "generation", "forged-birth", "stale-material"} {
		t.Run(mode, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			if err := s.InitializeGuard(ctx); err != nil {
				t.Fatal(err)
			}
			guardedInitialCreate(t, ctx, s, "guard-target", true)
			m, r, key, raw := guardedInitialRequest(t, ctx, s, "guard-target")
			switch mode {
			case "claimed":
				if err := s.ClaimIssue(ctx, "guard-target", "new-owner"); err != nil {
					t.Fatal(err)
				}
			case "manual-label-cycle":
				if err := s.AddLabel(ctx, "guard-target", "human-required", "manual human"); err != nil {
					t.Fatal(err)
				}
				if err := s.RemoveLabel(ctx, "guard-target", "human-required", "manual human"); err != nil {
					t.Fatal(err)
				}
			case "clearance-kv", "history-kv":
				ns := r.Effect.ClearanceNamespace
				if mode == "history-kv" {
					var h guardops.InitialAuditHoldEnvelope
					_ = json.Unmarshal([]byte(r.Effect.HoldRecordValue), &h)
					ns = h.Namespace
				}
				if err := s.SetConfig(ctx, "kv.krewe.audit.v1."+ns+"."+strings.Repeat("9", 64), "malformed relevant record"); err != nil {
					t.Fatal(err)
				}
			case "same-value-upsert", "removed-spent-config":
				issue, err := s.GetIssue(ctx, "guard-target")
				if err != nil {
					t.Fatal(err)
				}
				if err := s.CreateIssue(ctx, issue, "birth-owner"); err != nil {
					t.Fatal(err)
				}
				if mode == "removed-spent-config" {
					if err := s.DeleteConfig(ctx, guardops.NativeBirthSpentKey("guard-target")); err != nil {
						t.Fatal(err)
					}
				}
			case "generation":
				if _, err := s.db.ExecContext(ctx, "UPDATE bd_guard_state SET generation=? WHERE id=1", strings.Repeat("e", 64)); err != nil {
					t.Fatal(err)
				}
			case "forged-birth":
				changed := strings.Replace(raw, `"actor":"birth-owner"`, `"actor":"forged-owner"`, 1)
				if changed == raw {
					t.Fatal("birth fixture actor mismatch")
				}
				if err := s.SetConfig(ctx, "kv."+key, changed); err != nil {
					t.Fatal(err)
				}
			case "stale-material":
				if err := s.UpdateIssue(ctx, "guard-target", map[string]interface{}{"description": "new ordinary material"}, "ordinary"); err != nil {
					t.Fatal(err)
				}
			}
			if mode != "stale-material" {
				r = guardedInitialRebind(t, ctx, m, r)
			}
			before := guardedAuditObserveNullable(t, ctx, s)
			result, err := m.Apply(ctx, r)
			if err == nil && result.Outcome == "applied" {
				t.Fatalf("%s admitted initial hold", mode)
			}
			if guardedAuditObserveNullable(t, ctx, s) != before {
				t.Fatalf("%s refusal changed native publication/lifecycle", mode)
			}
			var holds int
			if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id='guard-target' AND label='human-required'").Scan(&holds); err != nil || holds != 0 {
				t.Fatal("refusal added hold", err)
			}
		})
	}
}
func TestGuardedNativeInitialHumanHoldRecordFailureRollsBackLabelEventAndLedger(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	guardedInitialCreate(t, ctx, s, "guard-target", true)
	m, r, _, _ := guardedInitialRequest(t, ctx, s, "guard-target")
	before := guardedAuditObserveNullable(t, ctx, s)
	fault := &guardedAuditFault{key: "kv." + r.Effect.HoldRecordKey, expectHold: true}
	connector := guardedReleaseCommentConnector(t, s)
	original := s.db
	s.db = sql.OpenDB(guardedAuditFaultConnector{Connector: connector, fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if !errors.Is(err, errGuardedAuditFault) || result.Outcome != "refused" || fault.calls.Load() != 1 || !fault.tentative || fault.base.commits.Load() != 0 {
		t.Fatalf("real tentative label fault not rolled back: %+v %v", result, err)
	}
	if guardedAuditObserveNullable(t, ctx, s) != before {
		t.Fatal("rollback changed lifecycle/token/history/ledger")
	}
	var n int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id='guard-target' AND label='human-required'").Scan(&n); err != nil || n != 0 {
		t.Fatal("tentative hold survived", err)
	}
}
func TestGuardedNativeInitialHumanHoldAckLossLookupAndReplayOnce(t *testing.T) {
	ctx, s, cfg := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	guardedInitialCreate(t, ctx, s, "guard-target", true)
	m, r, _, _ := guardedInitialRequest(t, ctx, s, "guard-target")
	before := guardedAuditObserveNullable(t, ctx, s)
	fault := &guardedNativeCommitAckFault{}
	connector := guardedReleaseCommentConnector(t, s)
	original := s.db
	s.db = sql.OpenDB(guardedNativeCommitAckConnector{Connector: connector, fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if !errors.Is(err, io.ErrUnexpectedEOF) || result.Outcome != "unknown" || fault.commitCalls.Load() != 1 || fault.successfulCommits.Load() != 1 {
		t.Fatalf("real successful commit response loss not unknown: %+v %v", result, err)
	}
	freshCfg := *cfg
	freshCfg.CreateIfMissing = false
	fresh, err := New(ctx, &freshCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	role, err := fresh.GuardedMutator()
	if err != nil {
		t.Fatal(err)
	}
	saved, err := role.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: guardops.Digest(r)})
	if err != nil || saved.Outcome != "applied" {
		t.Fatalf("fresh original lookup failed: %+v %v", saved, err)
	}
	after := guardedAuditObserveNullable(t, ctx, fresh)
	if after.Status != before.Status || after.Assignee != before.Assignee || after.RowVersion != before.RowVersion || after.LeaseJSON != before.LeaseJSON || after.Head == before.Head || after.Token == before.Token || after.Operations != before.Operations+1 || after.Commits != before.Commits+1 {
		t.Fatal("initial hold wasn't one atomic native publication")
	}
	replay, err := role.Apply(ctx, r)
	if err != nil || !replay.Replayed || replay.ResultJSON != saved.ResultJSON || guardedAuditObserveNullable(t, ctx, fresh) != after || fault.commitCalls.Load() != 1 {
		t.Fatal("original replay repeated hold/event/history")
	}
}

func TestGuardedNativeInitialHumanHoldSupportedIdentityLossWriters(t *testing.T) {
	for _, mode := range []string{"source-repo-delete", "rename-both", "compaction-restore", "demote-promote", "named-persistence-move", "domain-event-loss", "domain-insert", "domain-delete", "domain-bulk-delete"} {
		t.Run(mode, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			if err := s.InitializeGuard(ctx); err != nil {
				t.Fatal(err)
			}
			guardedInitialCreate(t, ctx, s, "guard-target", true)
			m, r, key, raw := guardedInitialRequest(t, ctx, s, "guard-target")
			switch mode {
			case "source-repo-delete":
				if err := s.UpdateIssue(ctx, "guard-target", map[string]interface{}{"source_repo": "native-source"}, "ordinary"); err != nil {
					t.Fatal(err)
				}
				n, err := s.DeleteIssuesBySourceRepo(ctx, "native-source")
				if err != nil || n != 1 {
					t.Fatal("actual source deletion did not occur", n, err)
				}
				guardedInitialCreate(t, ctx, s, "guard-target", true)
			case "rename-both":
				issue, err := s.GetIssue(ctx, "guard-target")
				if err != nil {
					t.Fatal(err)
				}
				if err := s.UpdateIssueID(ctx, "guard-target", "guard-renamed", issue, "ordinary"); err != nil {
					t.Fatal(err)
				}
				guardedInitialReplacementCreate(t, ctx, s, "guard-target")
				var spent int
				if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id IN (?,?)", guardops.NativeBirthSpentOperationID("guard-target"), guardops.NativeBirthSpentOperationID("guard-renamed")).Scan(&spent); err != nil || spent != 2 {
					t.Fatal("rename did not invalidate both IDs", spent, err)
				}
				if err := s.DeleteIssue(ctx, "guard-renamed"); err != nil {
					t.Fatal(err)
				}
				guardedInitialReplacementCreate(t, ctx, s, "guard-renamed")
				var replacementBirth int
				if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id=?", guardops.NativeBirthOperationID("guard-renamed")).Scan(&replacementBirth); err != nil || replacementBirth != 0 {
					t.Fatal("rename minted destination birth", err)
				}
			case "compaction-restore":
				if err := s.SnapshotIssue(ctx, "guard-target", 1); err != nil {
					t.Fatal(err)
				}
				if err := s.UpdateIssue(ctx, "guard-target", map[string]interface{}{"description": "ordinary changed text"}, "ordinary"); err != nil {
					t.Fatal(err)
				}
				snapshot, err := s.RestoreFromSnapshot(ctx, "guard-target")
				if err != nil || snapshot == nil {
					t.Fatal("actual restore not performed", err)
				}
			case "demote-promote":
				if err := s.DemoteToWisp(ctx, "guard-target", map[string]interface{}{"wisp": true}, "ordinary"); err != nil {
					t.Fatal(err)
				}
				if err := s.PromoteFromEphemeral(ctx, "guard-target", "ordinary"); err != nil {
					t.Fatal(err)
				}
			case "named-persistence-move":
				role, err := s.IssueLifecycle()
				if err != nil {
					t.Fatal(err)
				}
				for _, mode := range []publicops.PersistenceMode{publicops.PersistenceModeEphemeral, publicops.PersistenceModePersistent} {
					_, err := role.Update(ctx, publicops.UpdateRequest{IssueID: "guard-target", Actor: "ordinary", Patch: publicops.IssuePatch{Persistence: publicops.Field[publicops.PersistenceMode]{Set: true, Value: mode}}})
					if err != nil {
						t.Fatal(err)
					}
				}
			case "domain-event-loss":
				if err := s.withWriteTx(ctx, func(tx *sql.Tx) error {
					n, err := nativedb.NewEventsSQLRepository(tx).DeleteAllForIDs(ctx, []string{"guard-target"}, domain.RecordEventOpts{})
					if err == nil && n == 0 {
						t.Fatal("actual event loss absent")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			case "domain-insert":
				issue, err := s.GetIssue(ctx, "guard-target")
				if err != nil {
					t.Fatal(err)
				}
				if err := s.withWriteTx(ctx, func(tx *sql.Tx) error {
					return nativedb.NewIssueSQLRepository(tx).Insert(ctx, issue, "ordinary", domain.InsertIssueOpts{})
				}); err != nil {
					t.Fatal(err)
				}
			case "domain-delete":
				if err := s.withWriteTx(ctx, func(tx *sql.Tx) error {
					return nativedb.NewIssueSQLRepository(tx).Delete(ctx, "guard-target", domain.IssueTableOpts{}, "ordinary")
				}); err != nil {
					t.Fatal(err)
				}
				guardedInitialCreate(t, ctx, s, "guard-target", true)
			case "domain-bulk-delete":
				if err := s.withWriteTx(ctx, func(tx *sql.Tx) error {
					n, err := nativedb.NewIssueSQLRepository(tx).DeleteByIDs(ctx, []string{"guard-target"}, domain.IssueTableOpts{}, "ordinary")
					if err == nil && n != 1 {
						t.Fatal("actual domain delete absent")
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				guardedInitialCreate(t, ctx, s, "guard-target", true)
			}
			var spent int
			if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id=?", guardops.NativeBirthSpentOperationID("guard-target")).Scan(&spent); err != nil || spent != 1 {
				t.Fatal("supported history-loss writer omitted permanent invalidator", spent, err)
			}
			// Exact original birth bytes are never rewritten by identity-loss work.
			stored := stringMustAuditQuery(t, ctx, s, "SELECT value FROM config WHERE `key`=?", "kv."+key)
			if stored != raw {
				t.Fatal("writer rewrote immutable birth")
			}
			r = guardedInitialRebind(t, ctx, m, r)
			before := guardedAuditObserveNullable(t, ctx, s)
			result, err := m.Apply(ctx, r)
			if err == nil && result.Outcome == "applied" {
				t.Fatal("identity loss authorized first hold")
			}
			if guardedAuditObserveNullable(t, ctx, s) != before {
				t.Fatal("first-hold refusal mutated native state")
			}
			role, _ := s.GuardedRecordAttester()
			proof, err := role.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: r.Expected, RecordKey: key, RecordValue: raw})
			if err == nil && proof.Outcome == "identified" && (proof.CurrentIncarnationIntact == nil || *proof.CurrentIncarnationIntact || proof.InitialHoldEligible == nil || *proof.InitialHoldEligible) {
				t.Fatal("historical birth falsely certified current incarnation")
			}
		})
	}
}
func TestGuardedNativeInitialHumanHoldNoWriteAndWispDoNotSpendOtherBirth(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	guardedInitialCreate(t, ctx, s, "guard-target", true)
	m, r, key, raw := guardedInitialRequest(t, ctx, s, "guard-target")
	before := guardedAuditObserveNullable(t, ctx, s)
	if err := s.SetConfig(ctx, "issue_prefix", "guard"); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := s.RestoreFromSnapshot(ctx, "guard-target"); err != nil || snapshot != nil {
		t.Fatal("no snapshot control mutated", err)
	}
	if err := s.withWriteTx(ctx, func(tx *sql.Tx) error {
		n, err := nativedb.NewEventsSQLRepository(tx).DeleteAllForIDs(ctx, []string{"guard-absent"}, domain.RecordEventOpts{})
		if err == nil && n != 0 {
			t.Fatal("rowless event wipe not empty")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.withWriteTx(ctx, func(tx *sql.Tx) error {
		n, err := nativedb.NewIssueSQLRepository(tx).DeleteByIDs(ctx, []string{"guard-absent"}, domain.IssueTableOpts{}, "ordinary")
		if err == nil && n != 0 {
			t.Fatal("rowless delete not empty")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if guardedAuditObserveNullable(t, ctx, s) != before {
		t.Fatal("true no-write controls changed token/history/ledger")
	}
	wisp := &types.Issue{ID: "guard-wisp", Title: "ignored wisp", Status: types.StatusOpen, Priority: 2, IssueType: types.TypeTask, Ephemeral: true}
	if err := s.CreateIssuesWithFullOptions(ctx, []*types.Issue{wisp}, "ordinary", storage.BatchCreateOptions{CreateOnly: true, SkipPrefixValidation: true}); err != nil {
		t.Fatal(err)
	}
	after := guardedAuditObserveNullable(t, ctx, s)
	if after.Head != before.Head || after.Commits != before.Commits || after.Operations != before.Operations || after.Token == before.Token {
		t.Fatal("ignored actual wisp writer changed birth/history or failed conflict stamp")
	}
	current, err := m.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	role, _ := s.GuardedRecordAttester()
	proof, err := role.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: current, RecordKey: key, RecordValue: raw})
	if err != nil || proof.Outcome != "identified" || proof.CurrentIncarnationIntact == nil || !*proof.CurrentIncarnationIntact || proof.InitialHoldEligible == nil || !*proof.InitialHoldEligible {
		t.Fatalf("unrelated ignored work spent genuine birth: %+v %v", proof, err)
	}
	_ = r
}

func TestGuardedNativeInitialHumanHoldAbsentLabelRemovalIsNativeEvidence(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	guardedInitialCreate(t, ctx, s, "guard-target", true)
	m, r, key, raw := guardedInitialRequest(t, ctx, s, "guard-target")
	role, err := s.GuardedRecordAttester()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := role.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: r.Expected, RecordKey: key, RecordValue: raw})
	if err != nil || proof.Outcome != "identified" || proof.CurrentIncarnationIntact == nil || !*proof.CurrentIncarnationIntact || proof.InitialHoldEligible == nil || !*proof.InitialHoldEligible {
		t.Fatalf("genuine initial control not eligible: %+v %v", proof, err)
	}
	requireNoHold := func() {
		t.Helper()
		for _, query := range []struct {
			sql string
			arg string
		}{
			{"SELECT COUNT(*) FROM labels WHERE issue_id=? AND label='human-required'", r.Expected.IssueID},
			{"SELECT COUNT(*) FROM config WHERE `key` LIKE ?", "kv.krewe.audit.v1." + strings.Repeat("b", 64) + ".%"},
		} {
			var n int
			if err := s.db.QueryRowContext(ctx, query.sql, query.arg).Scan(&n); err != nil || n != 0 {
				t.Fatal("ordinary removal/refused initial hold created label or hold history", n, err)
			}
		}
		if stored := stringMustAuditQuery(t, ctx, s, "SELECT value FROM config WHERE `key`=?", "kv."+key); stored != raw {
			t.Fatal("ordinary removal/refused initial hold rewrote immutable birth")
		}
	}
	requireNoHold()
	var priorRemovals int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='label_removed'", r.Expected.IssueID).Scan(&priorRemovals); err != nil || priorRemovals != 0 {
		t.Fatal("absent-label removal fixture already contains removal evidence", priorRemovals, err)
	}
	before := guardedAuditObserveNullable(t, ctx, s)
	// Ordinary native RemoveLabel records a removal event even when its DELETE
	// removes no label. Migrated events are ignored, so this is a real native
	// event/token change without a versioned label delta or HEAD commit.
	if err := s.RemoveLabel(ctx, r.Expected.IssueID, "human-required", "ordinary"); err != nil {
		t.Fatal(err)
	}
	after := guardedAuditObserveNullable(t, ctx, s)
	if after.Assignee != before.Assignee || after.Status != before.Status || after.RowVersion != before.RowVersion || after.Started != before.Started || after.LeaseJSON != before.LeaseJSON || after.Unclaimed != before.Unclaimed || after.Operations != before.Operations || after.Token == before.Token || after.Head != before.Head || after.Commits != before.Commits {
		t.Fatalf("ignored absent-label removal lost native evidence or changed lifecycle/versioned history/birth ledger: before=%+v after=%+v", before, after)
	}
	var removals int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='label_removed' AND actor='ordinary' AND comment='Removed label: human-required'", r.Expected.IssueID).Scan(&removals); err != nil || removals != 1 {
		t.Fatal("actual ordinary removal event not recorded exactly once", removals, err)
	}
	requireNoHold()
	r = guardedInitialRebind(t, ctx, m, r)
	proof, err = role.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: r.Expected, RecordKey: key, RecordValue: raw})
	if err != nil || proof.Outcome != "identified" || proof.CurrentIncarnationIntact == nil || !*proof.CurrentIncarnationIntact || proof.InitialHoldEligible == nil || *proof.InitialHoldEligible {
		t.Fatalf("ordinary removal lost authentic birth or certified untouched lifecycle: %+v %v", proof, err)
	}
	result, err := m.Apply(ctx, r)
	if err == nil || result.Outcome != "refused" || guardedAuditObserveNullable(t, ctx, s) != after {
		t.Fatalf("fresh first-hold permission ignored native removal or mutated refusal: %+v %v", result, err)
	}
	requireNoHold()
}

func TestGuardedNativeInitialHumanHoldHistoricalAgeContinuityRefusesAfterAcceptedUpsert(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	guardedInitialCreate(t, ctx, s, "guard-target", true)
	m, r, _, _ := guardedInitialRequest(t, ctx, s, "guard-target")
	applied, err := m.Apply(ctx, r)
	if err != nil || applied.Outcome != "applied" {
		t.Fatal("initial hold setup", err)
	}
	old, err := m.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	digest := guardedCapturedHumanLabelEventSetDigest(t, old)
	issue, err := s.GetIssue(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateIssue(ctx, issue, "ordinary"); err != nil {
		t.Fatal(err)
	}
	// Removing the mutable marker cannot remove the permanent ledger evidence.
	if err := s.DeleteConfig(ctx, guardops.NativeBirthSpentKey("guard-target")); err != nil {
		t.Fatal(err)
	}
	current, err := m.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	if guardedCapturedHumanLabelEventSetDigest(t, current) != digest {
		t.Fatal("control must preserve event IDs to isolate continuity refusal")
	}
	role, _ := s.GuardedRecordAttester()
	proof, err := role.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: current, RecordKey: r.Effect.HoldRecordKey, RecordValue: r.Effect.HoldRecordValue})
	if err != nil || proof.Outcome != "identified" || proof.Operation == nil || proof.Operation.ResultJSON != applied.ResultJSON || proof.CurrentIncarnationIntact == nil || *proof.CurrentIncarnationIntact {
		t.Fatalf("historical authentication granted current age after native import: %+v %v", proof, err)
	}
}

// This connector delegates all actual SQL and transaction handling. It faults
// one identified publication boundary, rather than manufacturing stored rows.
type guardedInitialCreateFault struct {
	phase     string
	calls     atomic.Int32
	tentative bool
	base      guardedReleaseCommentFault
}
type guardedInitialCreateFaultConnector struct {
	driver.Connector
	fault *guardedInitialCreateFault
}

func (c guardedInitialCreateFaultConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &guardedInitialCreateFaultConn{guardedReleaseCommentFaultConn: &guardedReleaseCommentFaultConn{Conn: conn, fault: &c.fault.base}, fault: c.fault}, nil
}

type guardedInitialCreateFaultConn struct {
	*guardedReleaseCommentFaultConn
	fault *guardedInitialCreateFault
}

var errGuardedInitialCreateFault = errors.New("private native birth publication fault")

func (c *guardedInitialCreateFaultConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if c.fault.phase == "birth-ledger" && q == "INSERT INTO bd_guard_operations(operation_id,request_digest,result_json) VALUES(?,?,?)" && len(args) == 3 && args[0].Value == guardops.NativeBirthOperationID("guard-new") {
		c.fault.calls.Add(1)
		rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, "SELECT (SELECT COUNT(*) FROM issues WHERE id='guard-new'),(SELECT COUNT(*) FROM events WHERE issue_id='guard-new' AND event_type='created'),(SELECT COUNT(*) FROM config WHERE `key` LIKE ?)", []driver.NamedValue{{Ordinal: 1, Value: "kv.krewe.audit.v1." + guardops.NativeBirthNamespace("guard-new") + ".%"}})
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		v := make([]driver.Value, 3)
		if err := rows.Next(v); err != nil {
			return nil, err
		}
		count := func(value driver.Value) bool {
			if b, ok := value.([]byte); ok {
				return string(b) == "1"
			}
			return value == int64(1)
		}
		c.fault.tentative = count(v[0]) && count(v[1]) && count(v[2])
		return nil, errGuardedInitialCreateFault
	}
	if c.fault.phase == "post-sql-history" && strings.HasPrefix(q, "CALL DOLT_COMMIT(") {
		c.fault.calls.Add(1)
		return nil, errGuardedInitialCreateFault
	}
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c *guardedInitialCreateFaultConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if c.fault.phase == "post-sql-history" && strings.HasPrefix(q, "CALL DOLT_COMMIT(") {
		c.fault.calls.Add(1)
		return nil, errGuardedInitialCreateFault
	}
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func TestGuardedNativeInitialHumanHoldCreateAtomicRollbackVersusTrailingHistoryFailure(t *testing.T) {
	for _, phase := range []string{"birth-ledger", "post-sql-history"} {
		t.Run(phase, func(t *testing.T) {
			ctx, s, _ := guardedNativeStore(t)
			if err := s.InitializeGuard(ctx); err != nil {
				t.Fatal(err)
			}
			guardedInitialCreate(t, ctx, s, "guard-target", true)
			before := guardedAuditObserveNullable(t, ctx, s)
			fault := &guardedInitialCreateFault{phase: phase}
			original := s.db
			s.db = sql.OpenDB(guardedInitialCreateFaultConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
			s.db.SetMaxOpenConns(1)
			if err := original.Close(); err != nil {
				t.Fatal(err)
			}
			role, err := s.IssueLifecycle()
			if err != nil {
				t.Fatal(err)
			}
			created, err := role.Create(ctx, publicops.CreateRequest{Actor: "birth-owner", Issue: &types.Issue{ID: "guard-new", Title: "genuine create", Status: types.StatusOpen, Priority: 2, IssueType: types.TypeTask}})
			if fault.calls.Load() == 0 {
				t.Fatal("real native publication fault was not reached")
			}
			var rows, events, births, operations int
			for _, check := range []struct {
				q    string
				args []any
				out  *int
			}{
				{"SELECT COUNT(*) FROM issues WHERE id=?", []any{"guard-new"}, &rows},
				{"SELECT COUNT(*) FROM events WHERE issue_id=? AND event_type='created'", []any{"guard-new"}, &events},
				{"SELECT COUNT(*) FROM config WHERE `key` LIKE ?", []any{"kv.krewe.audit.v1." + guardops.NativeBirthNamespace("guard-new") + ".%"}, &births},
				{"SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id=?", []any{guardops.NativeBirthOperationID("guard-new")}, &operations},
			} {
				if err := s.db.QueryRowContext(ctx, check.q, check.args...).Scan(check.out); err != nil {
					t.Fatal(err)
				}
			}
			after := guardedAuditObserveNullable(t, ctx, s)
			if phase == "birth-ledger" {
				if !errors.Is(err, errGuardedInitialCreateFault) || !fault.tentative || fault.base.commits.Load() != 0 || rows != 0 || events != 0 || births != 0 || operations != 0 || after != before {
					t.Fatalf("birth transaction did not roll back complete creation: err=%v tentative=%v commits=%d rows/events/births/ops=%d/%d/%d/%d", err, fault.tentative, fault.base.commits.Load(), rows, events, births, operations)
				}
			} else {
				// Native Create's existing contract returns applied SQL state while
				// logging a dropped trailing history publication. Do not retry it.
				if err != nil || created.Issue == nil || created.Issue.ID != "guard-new" || rows != 1 || events != 1 || births != 1 || operations != 1 || fault.base.commits.Load() != 1 || after.Head != before.Head || after.Commits != before.Commits || after.Token == before.Token || after.Operations != before.Operations+1 {
					t.Fatalf("ordinary post-SQL publication semantics changed: created=%+v err=%v commits=%d counts=%d/%d/%d/%d", created, err, fault.base.commits.Load(), rows, events, births, operations)
				}
				m, _, key, raw := guardedInitialRequest(t, ctx, s, "guard-new")
				current, err := m.Capture(ctx, "guard-new")
				if err != nil {
					t.Fatal(err)
				}
				attester, _ := s.GuardedRecordAttester()
				proof, err := attester.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: current, RecordKey: key, RecordValue: raw})
				if err != nil || proof.Outcome != "identified" || proof.CurrentIncarnationIntact == nil || !*proof.CurrentIncarnationIntact {
					t.Fatalf("durable SQL birth was not authentic after dropped history: %+v %v", proof, err)
				}
			}
		})
	}
}

func TestGuardedNativeInitialHumanHoldPublicationFaultRollsBackAndUnknownLookupAbsent(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	guardedInitialCreate(t, ctx, s, "guard-target", true)
	m, r, _, _ := guardedInitialRequest(t, ctx, s, "guard-target")
	before := guardedAuditObserveNullable(t, ctx, s)
	fault := &guardedInitialCreateFault{phase: "post-sql-history"}
	original := s.db
	s.db = sql.OpenDB(guardedInitialCreateFaultConnector{Connector: guardedReleaseCommentConnector(t, s), fault: fault})
	s.db.SetMaxOpenConns(1)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := m.Apply(ctx, r)
	if !errors.Is(err, errGuardedInitialCreateFault) || result.Outcome != "unknown" || fault.calls.Load() != 1 || fault.base.commits.Load() != 0 {
		t.Fatalf("publication uncertainty was retried or mislabeled: %+v %v calls=%d commits=%d", result, err, fault.calls.Load(), fault.base.commits.Load())
	}
	if guardedAuditObserveNullable(t, ctx, s) != before {
		t.Fatal("failed publication left label/history/token/operation")
	}
	var labels, records int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM labels WHERE issue_id='guard-target' AND label='human-required'").Scan(&labels); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM config WHERE `key`=?", "kv."+r.Effect.HoldRecordKey).Scan(&records); err != nil {
		t.Fatal(err)
	}
	saved, err := m.Lookup(ctx, guardops.LookupRequest{Protocol: guardops.Protocol, OperationID: r.OperationID, RequestDigest: guardops.Digest(r)})
	if err != nil || saved.Outcome != "absent" || labels != 0 || records != 0 {
		t.Fatalf("unknown rollback lookup fabricated success: %+v %v labels=%d records=%d", saved, err, labels, records)
	}
}

func TestGuardedNativeInitialHumanHoldInitialManualLabelCannotEnroll(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.SetConfig(ctx, "issue_prefix", "guard"); err != nil {
		t.Fatal(err)
	}
	issue := &types.Issue{ID: "guard-target", Title: "born already held manually", Status: types.StatusOpen, Priority: 2, IssueType: types.TypeTask, Labels: []string{"human-required"}}
	if err := s.CreateIssuesWithFullOptions(ctx, []*types.Issue{issue}, "ordinary", storage.BatchCreateOptions{CreateOnly: true, SkipPrefixValidation: true}); err != nil {
		t.Fatal(err)
	}
	var births, spent, labels int
	for _, check := range []struct {
		q    string
		args []any
		out  *int
	}{
		{"SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id=?", []any{guardops.NativeBirthOperationID(issue.ID)}, &births},
		{"SELECT COUNT(*) FROM bd_guard_operations WHERE operation_id=?", []any{guardops.NativeBirthSpentOperationID(issue.ID)}, &spent},
		{"SELECT COUNT(*) FROM labels WHERE issue_id=? AND label='human-required'", []any{issue.ID}, &labels},
	} {
		if err := s.db.QueryRowContext(ctx, check.q, check.args...).Scan(check.out); err != nil {
			t.Fatal(err)
		}
	}
	if births != 0 || spent != 1 || labels != 1 {
		t.Fatalf("initial manual hold got positive prospective enrollment: births/spent/labels=%d/%d/%d", births, spent, labels)
	}
}

func TestGuardedNativeInitialHumanHoldLaterIdentifiedClearPreservesStickyAndChangedRehold(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	if err := s.InitializeGuard(ctx); err != nil {
		t.Fatal(err)
	}
	guardedInitialCreate(t, ctx, s, "guard-target", true)
	m, initial, _, _ := guardedInitialRequest(t, ctx, s, "guard-target")
	if result, err := m.Apply(ctx, initial); err != nil || result.Outcome != "applied" {
		t.Fatalf("initial hold setup: %+v %v", result, err)
	}
	current, err := m.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	clear := guardops.Request{Protocol: guardops.Protocol, OperationID: "native-initial-clear", Actor: initial.Actor, Expected: current, ContextJSON: initial.ContextJSON}
	clearance := guardops.AuditClearance{ClearedBy: clear.Actor, ClearedAt: "2026-10-10T12:35:00Z", MaterialVersion: initial.Effect.MaterialVersion}
	c := guardedAuditRecord(t, strings.Repeat("a", 64), clearance)
	h := guardedAuditRecord(t, strings.Repeat("b", 64), map[string]any{"kind": "identified-clearance", "operationId": clear.OperationID, "guardGeneration": current.Generation, "originalToken": current.Token, "baseline": "unknown-legacy", "historyComplete": false, "clearance": clearance})
	clear.Effect = guardops.Effect{Kind: "clear-human-hold", ClearanceKey: c.Key, ClearanceValue: c.Value, HistoryKey: h.Key, HistoryValue: h.Value}
	if result, err := m.Apply(ctx, clear); err != nil || result.Outcome != "applied" {
		t.Fatalf("native identified clear of initial lineage failed: %+v %v", result, err)
	}
	current, err = m.Capture(ctx, "guard-target")
	if err != nil {
		t.Fatal(err)
	}
	attester, _ := s.GuardedRecordAttester()
	proof, err := attester.AttestRecord(ctx, guardops.RecordAttestationRequest{Protocol: guardops.Protocol, Expected: current, RecordKey: initial.Effect.HoldRecordKey, RecordValue: initial.Effect.HoldRecordValue})
	if err != nil || proof.Outcome != "identified" || proof.CurrentIncarnationIntact == nil || !*proof.CurrentIncarnationIntact {
		t.Fatalf("legitimate clearance spent initial lineage: %+v %v", proof, err)
	}
	for _, changed := range []bool{false, true} {
		material := initial.Effect.MaterialVersion
		if changed {
			if err := s.UpdateIssue(ctx, "guard-target", map[string]interface{}{"description": "new material after identified initial clear"}, clear.Actor); err != nil {
				t.Fatal(err)
			}
			material = "changed-material"
		}
		current, err = m.Capture(ctx, "guard-target")
		if err != nil {
			t.Fatal(err)
		}
		r := guardops.Request{Protocol: guardops.Protocol, OperationID: "native-initial-rehold", Actor: clear.Actor, Expected: current, ContextJSON: initial.ContextJSON}
		pairs, _ := json.Marshal([][2]string{{c.Key, c.Value}})
		digest := guardops.RecordValueDigest(string(pairs))
		record := guardedAuditRecord(t, strings.Repeat("b", 64), map[string]any{"kind": "bounded-unworkable-hold", "operationId": r.OperationID, "guardGeneration": current.Generation, "originalToken": current.Token, "actor": r.Actor, "heldAt": "2026-10-10T12:36:00Z", "materialVersion": material, "clearanceNamespace": strings.Repeat("a", 64), "clearanceContentDigest": digest, "baseline": "unknown-legacy", "historyComplete": false, "clearance": clearance})
		r.Effect = guardops.Effect{Kind: "add-human-hold", MaterialVersion: material, ClearanceNamespace: strings.Repeat("a", 64), ClearanceContentDigest: digest, HoldRecordKey: record.Key, HoldRecordValue: record.Value}
		before := guardedAuditObserveNullable(t, ctx, s)
		result, err := m.Apply(ctx, r)
		if !changed {
			if err == nil || result.Outcome != "refused" || guardedAuditObserveNullable(t, ctx, s) != before {
				t.Fatalf("unchanged identified clearance was not sticky: %+v %v", result, err)
			}
		} else if err != nil || result.Outcome != "applied" {
			t.Fatalf("native changed-material rehold lost initial lineage: %+v %v", result, err)
		}
	}
}
