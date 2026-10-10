package storage

import (
	"context"
	"fmt"

	"github.com/steveyegge/beads/guardops"
)

// GuardedMutator preserves the ordinary release completion hook for the
// optional role. A durable replay must not run that user script a second time.
func (h *HookFiringStore) GuardedMutator() (guardops.Mutator, error) {
	provider, ok := h.inner.(guardops.Provider)
	if !ok {
		provider, ok = UnwrapStore(h.inner).(guardops.Provider)
	}
	if !ok {
		return nil, fmt.Errorf("guard: storage does not expose guarded mutation")
	}
	inner, err := provider.GuardedMutator()
	if err != nil {
		return nil, err
	}
	return &hookGuardedMutator{inner: inner, hooks: h}, nil
}

type hookGuardedMutator struct {
	inner guardops.Mutator
	hooks issueOperationHooks
}

func (g *hookGuardedMutator) Capture(ctx context.Context, id string) (guardops.Snapshot, error) {
	return g.inner.Capture(ctx, id)
}

func (g *hookGuardedMutator) Lookup(ctx context.Context, r guardops.LookupRequest) (guardops.Result, error) {
	return g.inner.Lookup(ctx, r)
}

func (g *hookGuardedMutator) Apply(ctx context.Context, r guardops.Request) (guardops.Result, error) {
	result, err := g.inner.Apply(ctx, r)
	if err == nil && result.Outcome == "applied" && !result.Replayed {
		g.hooks.CompleteIssueOperationRelease(ctx, r.Expected.IssueID)
	}
	return result, err
}
