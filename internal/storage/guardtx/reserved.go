package guardtx

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// PrepareWithReservedToken publishes a native-generated token already named by
// immutable bookkeeping inserted in THIS transaction. The same root/CAS rules
// as Prepare apply; subsequent new writes still require another ordinary stamp.
func PrepareWithReservedToken(ctx context.Context, r Runner, token string) error {
	decoded, err := hex.DecodeString(token)
	entry, bound := scopes.Load(r)
	if !bound || err != nil || len(decoded) != 32 || strings.ToLower(token) != token {
		return ErrUnsupported
	}
	s := entry.(*scope)
	if s.failure != nil {
		return s.failure
	}
	var root string
	if err := r.QueryRowContext(ctx, "SELECT "+RootExpression).Scan(&root); err != nil {
		s.failure = fmt.Errorf("guard: inspect changed working root: %w", err)
		return s.failure
	}
	if root == "" || root == s.root || token == s.token {
		s.failure = fmt.Errorf("%w: reserved token requires changed native work", ErrUnsupported)
		return s.failure
	}
	result, err := r.ExecContext(ctx, `UPDATE bd_guard_state SET token = ?
		WHERE id = 1 AND token = ? AND generation = ?`, token, s.token, s.generation)
	if err != nil {
		s.failure = fmt.Errorf("guard: stamp protected transaction: %w", err)
		return s.failure
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		s.failure = errors.Join(ErrConflict, err)
		return s.failure
	}
	s.token = token
	if err := r.QueryRowContext(ctx, "SELECT "+RootExpression).Scan(&s.root); err != nil {
		s.failure = fmt.Errorf("guard: read stamped working root: %w", err)
		return s.failure
	}
	if s.root == "" {
		s.failure = fmt.Errorf("%w: empty stamped working root", ErrUnsupported)
		return s.failure
	}
	return nil
}
