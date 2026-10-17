package dolt

import (
	"context"
	"errors"

	"github.com/go-sql-driver/mysql"
	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
)

// Diagnostic classification only. Outcome, transaction ownership and retry
// policy remain with the existing guarded operation. Never inspect error text.
func guardedErrorCode(err error, publicationStarted bool) guardops.ErrorCode {
	switch {
	case publicationStarted || errors.Is(err, ErrCommitIndeterminate):
		return guardops.CodePublicationUnconfirmed
	case errors.Is(err, guardops.ErrValidation):
		return guardops.CodeInvalidRequest
	case errors.Is(err, guardtx.ErrConflict):
		return guardops.CodeExpectationConflict
	case errors.Is(err, guardtx.ErrUnsupported):
		return guardops.CodeUnsupportedState
	case errors.Is(err, context.DeadlineExceeded):
		return guardops.CodeDeadlineExceeded
	case errors.Is(err, context.Canceled):
		return guardops.CodeCancelled
	}
	var sqlError *mysql.MySQLError
	if errors.As(err, &sqlError) {
		switch sqlError.Number {
		case 1205, 1213:
			return guardops.CodeSerializationConflict
		case 1044, 1045, 1142, 1143, 1227:
			return guardops.CodePermissionDenied
		case 1049, 1054, 1146:
			return guardops.CodeSchemaUnavailable
		}
	}
	return guardops.CodeStorageFailure
}
