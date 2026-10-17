package dolt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/go-sql-driver/mysql"
	"github.com/steveyegge/beads/guardops"
	"github.com/steveyegge/beads/internal/storage/guardtx"
	"github.com/steveyegge/beads/internal/storage/issueops"
)

func diagnosticRequest() guardops.Request {
	return guardops.Request{Protocol: guardops.Protocol, OperationID: "diagnostic-op", Actor: "local-test",
		Expected: guardops.Snapshot{Protocol: guardops.Protocol, IssueID: "test-1", Database: "test", Branch: "main", Head: "head", Root: "root", Generation: "generation", Token: "token", StateJSON: "opaque"},
		Effect:   guardops.Effect{Kind: "release"}, ContextJSON: "{}"}
}

func TestGuardErrorCodeTypedClassificationAndPublicationPrecedence(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want guardops.ErrorCode
	}{
		{"invalid", guardops.ErrValidation, guardops.CodeInvalidRequest},
		{"unsupported", guardtx.ErrUnsupported, guardops.CodeUnsupportedState},
		{"expectation", guardtx.ErrConflict, guardops.CodeExpectationConflict},
		{"deadline", context.DeadlineExceeded, guardops.CodeDeadlineExceeded},
		{"cancelled", context.Canceled, guardops.CodeCancelled},
		{"deadlock", &mysql.MySQLError{Number: 1213, Message: "PRIVATE_PASSWORD"}, guardops.CodeSerializationConflict},
		{"lock timeout", &mysql.MySQLError{Number: 1205, Message: "PRIVATE_PASSWORD"}, guardops.CodeSerializationConflict},
		{"permission", &mysql.MySQLError{Number: 1142, Message: "PRIVATE_PASSWORD"}, guardops.CodePermissionDenied},
		{"schema", &mysql.MySQLError{Number: 1146, Message: "PRIVATE_PASSWORD"}, guardops.CodeSchemaUnavailable},
		{"untyped credentials", errors.New("permission denied password is PRIVATE_PASSWORD"), guardops.CodeStorageFailure},
		{"other sql", &mysql.MySQLError{Number: 1105, Message: "PRIVATE_PASSWORD"}, guardops.CodeStorageFailure},
		{"indeterminate", errors.Join(ErrCommitIndeterminate, &mysql.MySQLError{Number: 1142, Message: "PRIVATE_PASSWORD"}), guardops.CodePublicationUnconfirmed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := fmt.Errorf("wrapped PRIVATE_PASSWORD: %w", tc.err)
			if got := guardedErrorCode(err, false); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if got := guardedErrorCode(err, true); got != guardops.CodePublicationUnconfirmed {
				t.Fatalf("publication precedence lost: %q", got)
			}
		})
	}
}

func TestGuardErrorCodeApplyRefusalIsBoundAndDoesNotRetry(t *testing.T) {
	for _, number := range []uint16{1142, 1146, 1213} {
		t.Run(fmt.Sprint(number), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mock.ExpectBegin().WillReturnError(&mysql.MySQLError{Number: number, Message: "password is PRIVATE_PASSWORD"})
			request := diagnosticRequest()
			result, err := (&guardedMutator{store: &DoltStore{db: db}}).Apply(context.Background(), request)
			wantOutcome := "refused"
			if number == 1213 {
				wantOutcome = "conflict"
			}
			if err == nil || result.Outcome != wantOutcome || result.OperationID != request.OperationID || result.RequestDigest != guardops.Digest(request) || result.ErrorCode != guardedErrorCode(err, false) || result.Reason != "" || result.ResultJSON != "" {
				t.Fatalf("incorrect bound refusal: %+v %v", result, err)
			}
			raw, _ := json.Marshal(result)
			if strings.Contains(string(raw), "PRIVATE_PASSWORD") {
				t.Fatal("raw error leaked")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGuardErrorCodeAdmissionNeedsNoStorage(t *testing.T) {
	g := &guardedMutator{}
	request := diagnosticRequest()
	result, err := g.Apply(issueops.WithDeferredVersionCommit(context.Background()), request)
	if err == nil || result.Outcome != "refused" || result.ErrorCode != guardops.CodeHistoryPublicationRequired || result.Reason != "" {
		t.Fatalf("deferred result: %+v %v", result, err)
	}
	request.Protocol = "invalid"
	result, err = g.Apply(context.Background(), request)
	if err == nil || result.ErrorCode != guardops.CodeInvalidRequest || result.Reason != "" {
		t.Fatalf("validation result: %+v %v", result, err)
	}
}
