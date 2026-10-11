package dolt

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
)

type captureAdmissionDriver struct {
	count, total, largest int64
	values                [][]driver.Value
	columns               [][]driver.Value
	fetches               int
}

func (d *captureAdmissionDriver) Connect(context.Context) (driver.Conn, error) {
	return &captureAdmissionConn{d}, nil
}
func (d *captureAdmissionDriver) Driver() driver.Driver { return nil }

type captureAdmissionConn struct{ d *captureAdmissionDriver }

func (c *captureAdmissionConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *captureAdmissionConn) Close() error              { return nil }
func (c *captureAdmissionConn) Begin() (driver.Tx, error) { return captureAdmissionTx{}, nil }
func (c *captureAdmissionConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.HasPrefix(q, "SELECT COLUMN_NAME") {
		return &captureAdmissionRows{cols: []string{"COLUMN_NAME"}, values: c.d.columns}, nil
	}
	if strings.HasPrefix(q, "SELECT COUNT(*)") {
		return &captureAdmissionRows{cols: []string{"count", "total", "largest"}, values: [][]driver.Value{{c.d.count, c.d.total, c.d.largest}}}, nil
	}
	c.d.fetches++
	return &captureAdmissionRows{cols: []string{"__guard_capture_bytes", "id"}, values: c.d.values}, nil
}

func TestGuardCaptureSchemaAdmissionBeforeFetchingContents(t *testing.T) {
	for _, name := range []string{"column-count", "reserved-column", "invalid-column-utf8", "empty-schema"} {
		t.Run(name, func(t *testing.T) {
			d := &captureAdmissionDriver{}
			switch name {
			case "column-count":
				for range guardCaptureMaxColumns + 1 {
					d.columns = append(d.columns, []driver.Value{"a"})
				}
			case "reserved-column":
				d.columns = [][]driver.Value{{"__guard_capture_bytes"}}
			case "invalid-column-utf8":
				d.columns = [][]driver.Value{{string([]byte{0xff})}}
			}
			db := sql.OpenDB(d)
			defer db.Close()
			tx, e := db.BeginTx(context.Background(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			_, e = boundedGuardRows(context.Background(), tx, &guardCaptureBudget{rows: map[string]int64{}}, "issues", nil, "")
			if !errors.Is(e, guardtx.ErrUnsupported) || d.fetches != 0 {
				t.Fatalf("schema admission fetched content: fetches=%d err=%v", d.fetches, e)
			}
		})
	}
}

type captureAdmissionTx struct{}

func (captureAdmissionTx) Commit() error   { return nil }
func (captureAdmissionTx) Rollback() error { return nil }

type captureAdmissionRows struct {
	cols   []string
	values [][]driver.Value
	at     int
}

func (r *captureAdmissionRows) Columns() []string { return r.cols }
func (r *captureAdmissionRows) Close() error      { return nil }
func (r *captureAdmissionRows) Next(dest []driver.Value) error {
	if r.at >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.at])
	r.at++
	return nil
}

func TestGuardCaptureAdmissionBeforeFetchingContents(t *testing.T) {
	for _, s := range []struct {
		name                  string
		count, total, largest int64
	}{
		{"row-count", guardCaptureMaxRows + 1, 1, 1},
		{"large-cell", 1, guardCaptureMaxRowBytes + 1, guardCaptureMaxRowBytes + 1},
		{"total-raw", 10, guardops.MaxStateBytes + 1, 1},
	} {
		t.Run(s.name, func(t *testing.T) {
			d := &captureAdmissionDriver{count: s.count, total: s.total, largest: s.largest}
			db := sql.OpenDB(d)
			defer db.Close()
			tx, e := db.BeginTx(context.Background(), nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			_, e = boundedGuardRows(context.Background(), tx, &guardCaptureBudget{rows: map[string]int64{}}, "issues", []string{"id"}, "")
			if !errors.Is(e, guardtx.ErrUnsupported) || d.fetches != 0 {
				t.Fatalf("admission fetched content: fetches=%d err=%v", d.fetches, e)
			}
		})
	}
}
func TestGuardCaptureEncodingAndCancellationFailClosed(t *testing.T) {
	for _, name := range []string{"escaped-overflow", "invalid-utf8", "invalid-string-utf8", "cancelled", "changed-size", "malformed-json-preserved"} {
		t.Run(name, func(t *testing.T) {
			d := &captureAdmissionDriver{count: 1, total: 1, largest: 1, values: [][]driver.Value{{int64(1), []byte("<")}}}
			b := &guardCaptureBudget{rows: map[string]int64{}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			db := sql.OpenDB(d)
			defer db.Close()
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback()
			switch name {
			case "escaped-overflow":
				b.encodedBytes = guardops.MaxStateBytes - 1025
			case "invalid-utf8":
				d.values[0][1] = []byte{0xff}
			case "invalid-string-utf8":
				d.values[0][1] = string([]byte{0xff})
			case "cancelled":
				cancel()
			case "changed-size":
				d.values[0][0] = int64(guardCaptureMaxRowBytes + 1)
				d.values[0][1] = nil
			case "malformed-json-preserved":
				d.values[0][1] = []byte("{not-json")
			}
			rows, e := boundedGuardRows(ctx, tx, b, "issues", []string{"id"}, "")
			if name == "malformed-json-preserved" {
				if e != nil || len(rows) != 1 {
					t.Fatal(e)
				}
				var row map[string]string
				if json.Unmarshal(rows[0], &row) != nil || row["id"] != "{not-json" {
					t.Fatal("raw scalar changed")
				}
				return
			}
			if e == nil || len(rows) != 0 {
				t.Fatal("unsupported capture returned material", name, e)
			}
			if name == "cancelled" && (!errors.Is(e, context.Canceled) || d.fetches != 0) {
				t.Fatal("cancelled capture fetched contents", e, d.fetches)
			}
		})
	}
}
