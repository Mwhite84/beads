// Package guardops declares the optional full-state guarded mutation role.
// It carries issue primitives; orchestration eligibility remains caller policy.
package guardops

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"
)

const Protocol = "beads.guard.v1"
const MaxStateBytes = 16 << 20
const MaxContextBytes = 1 << 20
const MaxCommentBytes = 1 << 20
const MaxClearanceRecordBytes = 64 << 10

type Snapshot struct {
	Protocol string `json:"protocol"`
	IssueID  string `json:"issueId"`
	Database string `json:"database"`
	Branch   string `json:"branch"`
	Head     string `json:"head"`
	// Root is the versioned working-root plus relevant lease-table hash.
	Root       string `json:"root"`
	Generation string `json:"generation"`
	Token      string `json:"token"`
	// StateJSON preserves exact server serialization, including int64 fields.
	// Callers must not parse and recompose it before guarded application.
	StateJSON string `json:"stateJson"`
}

type Effect struct {
	Kind                   string `json:"kind"`
	ClaimPointer           string `json:"claimPointer,omitempty"`
	Comment                string `json:"comment,omitempty"`
	ClearanceKey           string `json:"clearanceKey,omitempty"`
	ClearanceValue         string `json:"clearanceValue,omitempty"`
	HistoryKey             string `json:"historyKey,omitempty"`
	HistoryValue           string `json:"historyValue,omitempty"`
	ArchiveComment         string `json:"archiveComment,omitempty"`
	AcceptedDescription    string `json:"acceptedDescription,omitempty"`
	ReceiptRecordsJSON     string `json:"receiptRecordsJson,omitempty"`
	MaterialVersion        string `json:"materialVersion,omitempty"`
	ClearanceNamespace     string `json:"clearanceNamespace,omitempty"`
	ClearanceContentDigest string `json:"clearanceContentDigest,omitempty"`
	HoldRecordKey          string `json:"holdRecordKey,omitempty"`
	HoldRecordValue        string `json:"holdRecordValue,omitempty"`
	BirthRecordKey         string `json:"birthRecordKey,omitempty"`
	BirthRecordValueDigest string `json:"birthRecordValueDigest,omitempty"`
}
type Request struct {
	Protocol    string   `json:"protocol"`
	OperationID string   `json:"operationId"`
	Actor       string   `json:"actor"`
	Expected    Snapshot `json:"expected"`
	Effect      Effect   `json:"effect"`
	ContextJSON string   `json:"contextJson"`
}
type LookupRequest struct {
	Protocol      string `json:"protocol"`
	OperationID   string `json:"operationId"`
	RequestDigest string `json:"requestDigest"`
}
type Result struct {
	Protocol      string    `json:"protocol"`
	OperationID   string    `json:"operationId"`
	RequestDigest string    `json:"requestDigest"`
	Outcome       string    `json:"outcome"`
	ErrorCode     ErrorCode `json:"errorCode,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	ResultJSON    string    `json:"resultJson,omitempty"`
	// Replayed is local completion-hook bookkeeping, not a wire assertion.
	Replayed bool `json:"-"`
}

// Mutator is a separate optional capability. Do not append it to Lifecycle
// or Releaser: consumers of those stable roles did not request this contract.
type Mutator interface {
	Capture(context.Context, string) (Snapshot, error)
	Apply(context.Context, Request) (Result, error)
	Lookup(context.Context, LookupRequest) (Result, error)
}

// Provider exposes the optional role without widening existing storage roles.
type Provider interface {
	GuardedMutator() (Mutator, error)
}

var ErrValidation = errors.New("guard: invalid request")

func Digest(r Request) string {
	e := r.Expected
	fields := []string{r.Protocol, r.OperationID, r.Actor, e.Protocol,
		e.IssueID, e.Database, e.Branch, e.Head, e.Root, e.Generation, e.Token,
		e.StateJSON, r.Effect.Kind}
	if r.Effect.Kind == "release-retire-pointer" {
		fields = append(fields, r.Effect.ClaimPointer, r.Effect.Comment)
	} else if r.Effect.Kind == "release-with-comment" || r.Effect.Kind == "audit-comment" {
		fields = append(fields, r.Effect.Comment)
	} else if r.Effect.Kind == "clear-human-hold" {
		fields = append(fields, r.Effect.ClearanceKey, r.Effect.ClearanceValue, r.Effect.HistoryKey, r.Effect.HistoryValue)
	} else if r.Effect.Kind == "archive-replace" {
		fields = append(fields, r.Effect.ArchiveComment, r.Effect.AcceptedDescription, r.Effect.ReceiptRecordsJSON)
	} else if r.Effect.Kind == "validate" {
		fields = append(fields, r.Effect.ReceiptRecordsJSON)
	} else if r.Effect.Kind == "add-initial-human-hold" {
		fields = append(fields, r.Effect.MaterialVersion, r.Effect.ClearanceNamespace, r.Effect.ClearanceContentDigest, r.Effect.HoldRecordKey, r.Effect.HoldRecordValue, r.Effect.BirthRecordKey, r.Effect.BirthRecordValueDigest)
	} else if r.Effect.Kind == "add-human-hold" {
		fields = append(fields, r.Effect.MaterialVersion, r.Effect.ClearanceNamespace, r.Effect.ClearanceContentDigest, r.Effect.HoldRecordKey, r.Effect.HoldRecordValue)
	}
	return digestStrings(append(fields, r.ContextJSON))
}

func SnapshotDigest(e Snapshot) string {
	return digestStrings([]string{e.Protocol, e.IssueID, e.Database, e.Branch,
		e.Head, e.Root, e.Generation, e.Token, e.StateJSON})
}

func digestStrings(fields []string) string {
	h := sha256.New()
	var length [8]byte
	for _, s := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len([]byte(s))))
		h.Write(length[:])
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ValidateSnapshot(s Snapshot) error {
	if s.Protocol != Protocol || len(s.StateJSON) > MaxStateBytes {
		return ErrValidation
	}
	for _, v := range []string{s.IssueID, s.Database, s.Branch, s.Head, s.Root, s.Generation, s.Token, s.StateJSON} {
		if strings.TrimSpace(v) == "" || !utf8.ValidString(v) {
			return ErrValidation
		}
	}
	return nil
}

func ValidateRequest(r Request) error {
	if r.Protocol != Protocol ||
		strings.TrimSpace(r.OperationID) == "" || len(r.OperationID) > 128 ||
		strings.TrimSpace(r.Actor) == "" || len(r.Actor) > 256 || len(r.ContextJSON) > MaxContextBytes ||
		strings.TrimSpace(r.ContextJSON) == "" || !utf8.ValidString(r.OperationID) ||
		!utf8.ValidString(r.Actor) || !utf8.ValidString(r.ContextJSON) {
		return ErrValidation
	}
	if r.Effect.Kind != "add-initial-human-hold" && (r.Effect.BirthRecordKey != "" || r.Effect.BirthRecordValueDigest != "") {
		return ErrValidation
	}
	if r.Effect.Kind != "release-retire-pointer" && r.Effect.ClaimPointer != "" {
		return ErrValidation
	}
	switch r.Effect.Kind {
	case "release-retire-pointer":
		if hasAuditFields(r.Effect) || hasClearanceFields(r.Effect) || len(r.Actor) > 255 {
			return ErrValidation
		}
		if err := validateRetirePointer(r.Effect); err != nil {
			return err
		}
	case "release":
		if r.Effect.Comment != "" || hasClearanceFields(r.Effect) || hasAuditFields(r.Effect) {
			return ErrValidation
		}
	case "release-with-comment":
		if hasAuditFields(r.Effect) || hasClearanceFields(r.Effect) || strings.TrimSpace(r.Effect.Comment) == "" || len(r.Effect.Comment) > MaxCommentBytes || !utf8.ValidString(r.Effect.Comment) {
			return ErrValidation
		}
	case "audit-comment":
		if hasAuditFields(r.Effect) || hasClearanceFields(r.Effect) || len(r.Actor) > 255 {
			return ErrValidation
		}
		if err := validateAuditFailureComment(r.Effect.Comment); err != nil {
			return err
		}
	case "clear-human-hold":
		if hasAuditFields(r.Effect) || r.Effect.Comment != "" || len(r.Actor) > 255 {
			return ErrValidation
		}
		if err := validateClearanceEffect(r); err != nil {
			return err
		}
	case "add-initial-human-hold":
		if r.Effect.Comment != "" || hasClearanceFields(r.Effect) || r.Effect.ArchiveComment != "" || r.Effect.AcceptedDescription != "" || r.Effect.ReceiptRecordsJSON != "" || len(r.Actor) > 255 {
			return ErrValidation
		}
		if _, err := DecodeInitialAuditHoldRecord(r); err != nil {
			return err
		}
	case "archive-replace", "validate", "add-human-hold":
		if r.Effect.Comment != "" || hasClearanceFields(r.Effect) || len(r.Actor) > 255 {
			return ErrValidation
		}
		if err := validateAuditEffect(r); err != nil {
			return err
		}
	default:
		return ErrValidation
	}
	return ValidateSnapshot(r.Expected)
}

func ValidateLookup(r LookupRequest) error {
	if r.Protocol != Protocol || strings.TrimSpace(r.OperationID) == "" || len(r.OperationID) > 128 || !utf8.ValidString(r.OperationID) {
		return ErrValidation
	}
	b, err := hex.DecodeString(r.RequestDigest)
	if err != nil || len(b) != 32 || strings.ToLower(r.RequestDigest) != r.RequestDigest {
		return ErrValidation
	}
	return nil
}
