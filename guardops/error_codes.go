package guardops

// ErrorCode is optional diagnostic evidence, never permission to retry. Values
// contain no request data, SQL messages, identifiers, credentials or paths.
// Old results omit it; consumers must not backfill a historical cause.
type ErrorCode string

const (
	CodeInvalidRequest             ErrorCode = "invalid-request"
	CodeHistoryPublicationRequired ErrorCode = "history-publication-required"
	CodeCapabilityUnavailable      ErrorCode = "capability-unavailable"
	CodeContextUnavailable         ErrorCode = "context-unavailable"
	CodeUnsupportedState           ErrorCode = "unsupported-state"
	CodeExpectationConflict        ErrorCode = "expectation-conflict"
	CodeSerializationConflict      ErrorCode = "serialization-conflict"
	CodeRequestMismatch            ErrorCode = "request-mismatch"
	CodePermissionDenied           ErrorCode = "permission-denied"
	CodeSchemaUnavailable          ErrorCode = "schema-unavailable"
	CodeDeadlineExceeded           ErrorCode = "deadline-exceeded"
	CodeCancelled                  ErrorCode = "cancelled"
	CodeStorageFailure             ErrorCode = "storage-failure"
	CodePublicationUnconfirmed     ErrorCode = "publication-unconfirmed"
	CodeLookupUnconfirmed          ErrorCode = "lookup-unconfirmed"
)
