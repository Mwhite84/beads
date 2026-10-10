package guardops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"
)

type RecordAttestationRequest struct {
	Protocol    string   `json:"protocol"`
	Expected    Snapshot `json:"expected"`
	RecordKey   string   `json:"recordKey"`
	RecordValue string   `json:"recordValue"`
}
type RecordAttestationResult struct {
	Protocol          string  `json:"protocol"`
	RecordKey         string  `json:"recordKey"`
	RecordValueDigest string  `json:"recordValueDigest"`
	Outcome           string  `json:"outcome"`
	Operation         *Result `json:"operation,omitempty"`
	Reason            string  `json:"reason,omitempty"`
}

// Independent optional read capability; digest-required Lookup remains unchanged.
type RecordAttester interface {
	AttestRecord(context.Context, RecordAttestationRequest) (RecordAttestationResult, error)
}
type RecordAttestationProvider interface {
	GuardedRecordAttester() (RecordAttester, error)
}

func RecordValueDigest(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
func ValidateRecordAttestation(r RecordAttestationRequest) error {
	var envelope struct {
		Namespace string `json:"namespace"`
	}
	if !utf8.ValidString(r.RecordValue) || r.Protocol != Protocol || json.Unmarshal([]byte(r.RecordValue), &envelope) != nil || !validClearanceKey(r.RecordKey, envelope.Namespace, r.RecordValue) || len(r.RecordValue) > MaxAuditRecordBytes {
		return ErrValidation
	}
	return ValidateSnapshot(r.Expected)
}
func DecodeRecordAttestation(raw []byte) (RecordAttestationRequest, error) {
	var r RecordAttestationRequest
	if err := decodeExact(raw, &r); err != nil {
		return r, err
	}
	return r, ValidateRecordAttestation(r)
}
