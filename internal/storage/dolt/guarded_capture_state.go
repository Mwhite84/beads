package dolt

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
)

const guardCaptureFormat = "native-graph-v1"
const guardCaptureTimeout = 30 * time.Second
const guardCaptureMaxRows = 100_000
const guardCaptureMaxRowBytes = 2 << 20
const guardCaptureMaxColumns = 128

type guardCaptureBudget struct {
	rawBytes     int64
	encodedBytes int
	rows         map[string]int64
}

func captureGuardImage(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	b := &guardCaptureBudget{rows: make(map[string]int64)}
	state := map[string]any{"format": guardCaptureFormat, "issueId": id}
	target, err := boundedGuardRows(ctx, tx, b, "issues", nil, "id = ?", id)
	if err != nil {
		return "", err
	}
	graph, err := boundedGuardRows(ctx, tx, b, "issues", []string{"id", "status"}, "id <> ?", id)
	if err != nil {
		return "", err
	}
	issues := append(target, graph...)
	sortGuardRows(issues)
	state["issues"] = issues
	for _, table := range []string{"labels", "dependencies", "config", "events", "comments", "leases"} {
		where := ""
		var args []any
		if table == "events" || table == "comments" {
			where, args = "issue_id = ?", []any{id}
		}
		rows, err := boundedGuardRows(ctx, tx, b, table, nil, where, args...)
		if err != nil {
			return "", err
		}
		state[table] = rows
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	if len(encoded) > guardops.MaxStateBytes {
		return "", fmt.Errorf("%w: snapshot exceeds admission limit", guardtx.ErrUnsupported)
	}
	return string(encoded), ctx.Err()
}

func sortGuardRows(rows []json.RawMessage) {
	// Canonicalize each row once, rather than marshal inside the comparator.
	sort.Slice(rows, func(i, j int) bool { return bytes.Compare(rows[i], rows[j]) < 0 })
}

// Table/where/column identifiers are fixed server-selected literals. Aggregate
// admission precedes materialization. The inline size condition also prevents
// large cells crossing the driver boundary if rows differ from the preflight.
func boundedGuardRows(ctx context.Context, tx *sql.Tx, b *guardCaptureBudget, table string, columns []string, where string, args ...any) ([]json.RawMessage, error) {
	if columns == nil {
		rows, err := tx.QueryContext(ctx, `SELECT COLUMN_NAME FROM information_schema.columns
   WHERE table_schema=DATABASE() AND table_name=? ORDER BY ORDINAL_POSITION`, table)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				rows.Close()
				return nil, err
			}
			columns = append(columns, c)
			if len(columns) > guardCaptureMaxColumns {
				rows.Close()
				return nil, fmt.Errorf("%w: capture column limit", guardtx.ErrUnsupported)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("%w: capture schema unavailable", guardtx.ErrUnsupported)
	}
	var fields, lengths []string
	for _, column := range columns {
		if column == "__guard_capture_bytes" || !utf8.ValidString(column) {
			return nil, fmt.Errorf("%w: reserved capture column", guardtx.ErrUnsupported)
		}
		quoted := "`" + strings.ReplaceAll(column, "`", "``") + "`"
		fields = append(fields, quoted)
		lengths = append(lengths, "COALESCE(OCTET_LENGTH(CAST("+quoted+" AS BINARY)),0)")
	}
	suffix := " FROM `" + table + "`"
	if where != "" {
		suffix += " WHERE " + where
	}
	sized := "SELECT " + strings.Join(fields, ",") + ", (" + strings.Join(lengths, "+") + ") AS __guard_capture_bytes" + suffix
	var count, total, largest int64
	// Dolt's SUM result may use floating-point wire typing even for integral
	// byte lengths. Cast on the server so database/sql receives integer text,
	// including sizes beyond its scientific-notation formatting threshold.
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*), CAST(COALESCE(SUM(__guard_capture_bytes),0) AS UNSIGNED), CAST(COALESCE(MAX(__guard_capture_bytes),0) AS UNSIGNED) FROM ("+sized+") AS guard_size", args...).Scan(&count, &total, &largest); err != nil {
		return nil, err
	}
	if count < 0 || total < 0 || largest < 0 || b.rows[table]+count > guardCaptureMaxRows || largest > guardCaptureMaxRowBytes || b.rawBytes+total > guardops.MaxStateBytes {
		return nil, fmt.Errorf("%w: capture row or raw-byte admission limit", guardtx.ErrUnsupported)
	}
	b.rows[table] += count
	b.rawBytes += total
	selected := []string{"__guard_capture_bytes"}
	for _, field := range fields {
		selected = append(selected, fmt.Sprintf("CASE WHEN __guard_capture_bytes <= %d THEN %s ELSE NULL END AS %s", guardCaptureMaxRowBytes, field, field))
	}
	rows, err := tx.QueryContext(ctx, "SELECT "+strings.Join(selected, ",")+" FROM ("+sized+") AS guard_rows", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]json.RawMessage, 0)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var rawSize int64
		values := make([]any, len(columns))
		pointers := make([]any, len(columns)+1)
		pointers[0] = &rawSize
		for i := range values {
			pointers[i+1] = &values[i]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, err
		}
		if rawSize < 0 || rawSize > guardCaptureMaxRowBytes || len(result) >= guardCaptureMaxRows || int64(len(result)) >= count {
			return nil, fmt.Errorf("%w: capture row admission changed", guardtx.ErrUnsupported)
		}
		row := make(map[string]any, len(columns))
		for i, column := range columns {
			switch v := values[i].(type) {
			case nil:
				row[column] = nil
			case []byte:
				if !utf8.Valid(v) {
					return nil, fmt.Errorf("%w: capture scalar is not exact UTF-8", guardtx.ErrUnsupported)
				}
				row[column] = string(v)
			case string:
				if !utf8.ValidString(v) {
					return nil, fmt.Errorf("%w: capture scalar is not exact UTF-8", guardtx.ErrUnsupported)
				}
				row[column] = v
			case time.Time:
				row[column] = v.Format(time.RFC3339Nano)
			default:
				row[column] = fmt.Sprint(v)
			}
		}
		encoded, err := json.Marshal(row)
		if err != nil {
			return nil, err
		}
		// Reserve bounded envelope overhead, then enforce exact final bytes too.
		if b.encodedBytes+len(encoded)+1 > guardops.MaxStateBytes-1024 {
			return nil, fmt.Errorf("%w: snapshot exceeds admission limit", guardtx.ErrUnsupported)
		}
		b.encodedBytes += len(encoded) + 1
		result = append(result, encoded)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if int64(len(result)) != count {
		return nil, fmt.Errorf("%w: capture row admission changed", guardtx.ErrUnsupported)
	}
	sortGuardRows(result)
	return result, nil
}
