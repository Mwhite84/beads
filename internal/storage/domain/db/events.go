package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/steveyegge/beads/internal/storage/dberrors"
	"github.com/steveyegge/beads/internal/storage/domain"
	"github.com/steveyegge/beads/internal/storage/guardbirth"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	"github.com/steveyegge/beads/internal/storage/issueops"
)

func NewEventsSQLRepository(runner Runner) domain.EventsSQLRepository {
	return &eventsSQLRepositoryImpl{runner: runner}
}

type eventsSQLRepositoryImpl struct {
	runner Runner
}

var _ domain.EventsSQLRepository = (*eventsSQLRepositoryImpl)(nil)

func (r *eventsSQLRepositoryImpl) Record(ctx context.Context, evt domain.Event, opts domain.RecordEventOpts) error {
	table := "events"
	if opts.UseWispsTable {
		table = "wisp_events"
	}
	if err := issueops.RecordFullEventInTable(ctx, r.runner, table, evt.IssueID, evt.Type, evt.Actor, evt.OldValue, evt.NewValue); err != nil {
		return fmt.Errorf("db: record event in %s: %w", table, err)
	}
	return nil
}

func (r *eventsSQLRepositoryImpl) DeleteAllForIDs(ctx context.Context, ids []string, opts domain.RecordEventOpts) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	table := "events"
	if opts.UseWispsTable {
		table = "wisp_events"
	}
	if !opts.UseWispsTable && guardtx.Bound(r.runner) {
		for _, id := range ids {
			var n int
			if err := r.runner.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE issue_id=?", id).Scan(&n); err != nil {
				return 0, err
			}
			if n != 0 {
				if _, err := guardbirth.Spend(ctx, r.runner, id, "", "domain-durable-event-loss"); err != nil {
					return 0, err
				}
			}
		}
	}
	total := 0
	for start := 0; start < len(ids); start += deleteBatchSize {
		end := start + deleteBatchSize
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[start:end]
		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for i, id := range batch {
			placeholders[i] = "?"
			args[i] = id
		}
		//nolint:gosec // G201: table is one of two hardcoded constants; ? placeholders only.
		res, err := r.runner.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE issue_id IN (%s)", table, strings.Join(placeholders, ",")),
			args...)
		if err != nil {
			if opts.UseWispsTable && dberrors.IsTableNotExist(err) {
				return total, nil
			}
			return total, fmt.Errorf("db: EventsSQLRepository.DeleteAllForIDs from %s: %w", table, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("db: EventsSQLRepository.DeleteAllForIDs rows affected: %w", err)
		}
		total += int(n)
	}
	return total, nil
}

func (r *eventsSQLRepositoryImpl) CountAllForIDs(ctx context.Context, ids []string, opts domain.RecordEventOpts) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	table := "events"
	if opts.UseWispsTable {
		table = "wisp_events"
	}
	count, err := issueops.CountRowsForIssueIDsInTx(ctx, r.runner, table, ids)
	if err != nil {
		if opts.UseWispsTable && dberrors.IsTableNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("db: EventsSQLRepository.CountAllForIDs: %w", err)
	}
	return count, nil
}
