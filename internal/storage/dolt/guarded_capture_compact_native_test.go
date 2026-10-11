package dolt

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
)

func TestGuardedNativeCompactCaptureLargeUnrelatedBodiesAndCompleteCommitment(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedNativeSeed(t, ctx, s)
	if _, e := s.db.ExecContext(ctx, `UPDATE issues SET description=REPEAT('x',?) WHERE id='guard-blocker'`, guardops.MaxStateBytes+1); e != nil {
		t.Fatal(e)
	}
	original, e := m.Capture(ctx, r.Expected.IssueID)
	if e != nil {
		t.Fatal(e)
	}
	if len(original.StateJSON) > 1<<20 {
		t.Fatal("unrelated body escaped projection")
	}
	again, e := m.Capture(ctx, r.Expected.IssueID)
	if e != nil || !reflect.DeepEqual(original, again) {
		t.Fatal("capture bytes not deterministic", e)
	}
	var state map[string]json.RawMessage
	if json.Unmarshal([]byte(original.StateJSON), &state) != nil || string(state["format"]) != `"native-graph-v1"` {
		t.Fatal("missing compact format")
	}
	var issues []map[string]string
	if json.Unmarshal(state["issues"], &issues) != nil {
		t.Fatal("invalid issues")
	}
	for _, issue := range issues {
		if issue["id"] == "guard-blocker" && len(issue) != 2 {
			t.Fatal("unrelated issue content shipped")
		}
	}
	for _, change := range []struct{ name, sql string }{
		{"omitted-body", `UPDATE issues SET description=CONCAT(description,'changed') WHERE id='guard-blocker'`},
		{"omitted-comment", `INSERT INTO comments(id,issue_id,author,text) VALUES(UUID(),'guard-blocker','other','unrelated')`},
		{"omitted-ignored-event", `INSERT INTO events(id,issue_id,event_type,actor,comment) VALUES(UUID(),'guard-blocker','commented','other','unrelated')`},
		{"schema", `ALTER TABLE issues ADD COLUMN compact_extra TEXT`},
	} {
		t.Run(change.name, func(t *testing.T) {
			before, e := m.Capture(ctx, r.Expected.IssueID)
			if e != nil {
				t.Fatal(e)
			}
			request := r
			request.OperationID = "compact-stale-" + change.name
			request.Expected = before
			if _, e = s.db.ExecContext(ctx, change.sql); e != nil {
				t.Fatal(e)
			}
			observed := guardedNativeObserve(t, ctx, s)
			result, e := m.Apply(ctx, request)
			if !errors.Is(e, guardtx.ErrConflict) || result.Outcome != "conflict" || guardedNativeObserve(t, ctx, s) != observed {
				t.Fatal("omitted state escaped commitment or stale apply wrote", result, e)
			}
		})
	}
}
func TestGuardedNativeCompactExactScalarsTamperAndAdmission(t *testing.T) {
	ctx, s, _ := guardedNativeStore(t)
	m, r := guardedNativeSeed(t, ctx, s)
	// Native JSON storage permits a scalar that the application metadata
	// decoder cannot interpret as an object. Preserve its exact SQL value.
	if _, e := s.db.ExecContext(ctx, `UPDATE issues SET row_lock=9007199254740993,metadata='"not-an-object"',description=REPEAT('x',1048576) WHERE id='guard-target'`); e != nil {
		t.Fatal(e)
	}
	snapshot, e := m.Capture(ctx, r.Expected.IssueID)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(snapshot.StateJSON, `"row_lock":"9007199254740993"`) || !strings.Contains(snapshot.StateJSON, `"metadata":"\"not-an-object\""`) {
		t.Fatal("native exact scalar changed")
	}
	var image struct {
		Issues []map[string]*string `json:"issues"`
	}
	if e := json.Unmarshal([]byte(snapshot.StateJSON), &image); e != nil {
		t.Fatal(e)
	}
	for _, row := range image.Issues {
		if row["id"] == nil || *row["id"] != "guard-target" {
			continue
		}
		for _, field := range []string{"created_at", "updated_at", "started_at"} {
			if row[field] == nil {
				t.Fatal("target clock missing", field)
			}
			if _, e := time.Parse(time.RFC3339Nano, *row[field]); e != nil {
				t.Fatal("SQL projection changed native clock typing", field, e)
			}
		}
	}
	for _, name := range []string{"marker", "material", "root"} {
		request := r
		request.OperationID = "compact-tamper-" + name
		request.Expected = snapshot
		switch name {
		case "marker":
			request.Expected.StateJSON = strings.Replace(snapshot.StateJSON, guardCaptureFormat, "unknown", 1)
		case "material":
			request.Expected.StateJSON = strings.Replace(snapshot.StateJSON, "not-an-object", "different", 1)
		case "root":
			request.Expected.Root += "tampered"
		}
		observed := guardedNativeObserve(t, ctx, s)
		result, e := m.Apply(ctx, request)
		if !errors.Is(e, guardtx.ErrConflict) || result.Outcome != "conflict" || guardedNativeObserve(t, ctx, s) != observed {
			t.Fatal("tamper applied or wrote", name, result, e)
		}
	}
	if _, e := s.db.ExecContext(ctx, `UPDATE issues SET description=REPEAT('x',?) WHERE id='guard-target'`, guardCaptureMaxRowBytes+1); e != nil {
		t.Fatal(e)
	}
	observed := guardedNativeObserve(t, ctx, s)
	_, e = m.Capture(ctx, r.Expected.IssueID)
	if !errors.Is(e, guardtx.ErrUnsupported) || guardedNativeObserve(t, ctx, s) != observed {
		t.Fatal("oversized target capture was not read-only refused", e)
	}
}
