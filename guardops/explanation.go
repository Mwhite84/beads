package guardops

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const ExplanationProtocol = "beads.guard.explanation.v1"
const explanationOperationPrefix = "audit-explanation-"

type ExplanationRequest struct {
	Protocol        string   `json:"protocol"`
	OperationID     string   `json:"operationId"`
	OriginalRequest Request  `json:"originalRequest"`
	Expected        Snapshot `json:"expected"`
	Comment         string   `json:"comment"`
}
type ExplanationLookupRequest struct {
	Protocol      string `json:"protocol"`
	OperationID   string `json:"operationId"`
	RequestDigest string `json:"requestDigest"`
}
type ExplanationResult struct {
	Protocol      string    `json:"protocol"`
	OperationID   string    `json:"operationId"`
	RequestDigest string    `json:"requestDigest"`
	Outcome       string    `json:"outcome"`
	ErrorCode     ErrorCode `json:"errorCode,omitempty"`
	CommentID     string    `json:"commentId,omitempty"`
	Reason        string    `json:"reason,omitempty"`
	Replayed      bool      `json:"-"`
}

// ExplanationDeliverer is independent of Apply: delivery identity binds the
// original applied operation, while a fresh permission snapshot only admits a
// first delivery. Exact historical lookup/replay never appends another comment.
type ExplanationDeliverer interface {
	Explain(context.Context, ExplanationRequest) (ExplanationResult, error)
	LookupExplanation(context.Context, ExplanationLookupRequest) (ExplanationResult, error)
}
type ExplanationProvider interface {
	GuardedExplanationDeliverer() (ExplanationDeliverer, error)
}

func ExplanationOperationID(originalID string) string {
	return explanationOperationPrefix + RecordValueDigest(originalID)
}
func ExplanationDigest(r ExplanationRequest) string {
	return digestStrings([]string{r.Protocol, r.OperationID, Digest(r.OriginalRequest), r.Comment})
}

func ValidateExplanation(r ExplanationRequest) error {
	if r.Protocol != ExplanationProtocol || r.OperationID != ExplanationOperationID(r.OriginalRequest.OperationID) || ValidateRequest(r.OriginalRequest) != nil || ValidateSnapshot(r.Expected) != nil || len(r.OriginalRequest.Actor) > 255 {
		return ErrValidation
	}
	old := r.OriginalRequest.Expected
	if old.IssueID != r.Expected.IssueID || old.Database != r.Expected.Database || old.Branch != r.Expected.Branch || old.Generation != r.Expected.Generation {
		return ErrValidation
	}
	switch r.OriginalRequest.Effect.Kind {
	case "validate", "archive-replace", "add-human-hold", "add-initial-human-hold":
	default:
		return ErrValidation
	}
	return validateExplanationComment(r)
}
func ValidateExplanationLookup(r ExplanationLookupRequest) error {
	if r.Protocol != ExplanationProtocol || !strings.HasPrefix(r.OperationID, explanationOperationPrefix) || !auditHash(strings.TrimPrefix(r.OperationID, explanationOperationPrefix)) {
		return ErrValidation
	}
	return ValidateLookup(LookupRequest{Protocol: Protocol, OperationID: r.OperationID, RequestDigest: r.RequestDigest})
}
func DecodeExplanation(raw []byte) (ExplanationRequest, error) {
	var r ExplanationRequest
	if err := decodeExplanationWire(raw, &r, wireShape{"protocol": nil, "operationId": nil, "originalRequest": nil, "expected": {"protocol": nil, "issueId": nil, "database": nil, "branch": nil, "head": nil, "root": nil, "generation": nil, "token": nil, "stateJson": nil}, "comment": nil}); err != nil {
		return r, err
	}
	var nested struct {
		Original json.RawMessage `json:"originalRequest"`
	}
	if json.Unmarshal(raw, &nested) != nil {
		return r, ErrValidation
	}
	original, err := DecodeRequest(nested.Original)
	if err != nil {
		return r, err
	}
	r.OriginalRequest = original
	return r, ValidateExplanation(r)
}
func DecodeExplanationLookup(raw []byte) (ExplanationLookupRequest, error) {
	var r ExplanationLookupRequest
	if err := decodeExplanationWire(raw, &r, wireShape{"protocol": nil, "operationId": nil, "requestDigest": nil}); err != nil {
		return r, err
	}
	return r, ValidateExplanationLookup(r)
}
func decodeExplanationWire(raw []byte, target any, shape wireShape) error {
	// Two independently bounded native snapshots occur in this new envelope.
	if len(raw) > 2*MaxWireBytes || !utf8.Valid(raw) || rejectUnpairedEscapes(raw) != nil {
		return ErrValidation
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if uniqueValue(d) != nil {
		return ErrValidation
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrValidation
	}
	if exactKeys(raw, shape) != nil {
		return ErrValidation
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrValidation
	}
	return nil
}
func validateExplanationComment(r ExplanationRequest) error {
	body := r.Comment
	if !utf8.ValidString(body) || len(body) > MaxAuditRecordBytes {
		return ErrValidation
	}
	normalized := strings.ReplaceAll(body, "\r\n", "\n")
	match := auditResultFence.FindStringSubmatch(normalized)
	if len(match) != 2 || len(auditAnyFence.FindAllStringIndex(normalized, -1)) != 2 {
		return ErrValidation
	}
	shape := wireShape{"outcome": nil, "materialVersion": nil, "planVersion": nil, "repository": nil, "reviewedSha": nil, "scope": nil, "findings": nil}
	var rawFields map[string]json.RawMessage
	if json.Unmarshal([]byte(match[1]), &rawFields) != nil {
		return ErrValidation
	}
	if _, ok := rawFields["transcriptUrl"]; ok {
		shape["transcriptUrl"] = nil
	}
	var result struct {
		Outcome         string   `json:"outcome"`
		MaterialVersion string   `json:"materialVersion"`
		PlanVersion     *string  `json:"planVersion"`
		Repository      string   `json:"repository"`
		ReviewedSHA     string   `json:"reviewedSha"`
		Scope           string   `json:"scope"`
		Findings        []string `json:"findings"`
		TranscriptURL   *string  `json:"transcriptUrl"`
	}
	if exactAuditRecord(match[1], shape, &result) != nil || result.Findings == nil || !nonblankAudit(result.MaterialVersion) || (result.PlanVersion != nil && !nonblankAudit(*result.PlanVersion)) {
		return ErrValidation
	}
	var findings []any
	if json.Unmarshal(rawFields["findings"], &findings) != nil {
		return ErrValidation
	}
	for _, finding := range findings {
		if _, ok := finding.(string); !ok {
			return ErrValidation
		}
	}
	if _, ok := rawFields["transcriptUrl"]; ok && (result.TranscriptURL == nil || !nonblankAudit(*result.TranscriptURL)) {
		return ErrValidation
	}
	var binding struct {
		Repository      string `json:"repository"`
		ReviewedSHA     string `json:"reviewedSha"`
		Scope           string `json:"scope"`
		MaterialVersion string `json:"materialVersion"`
	}
	if json.Unmarshal([]byte(r.OriginalRequest.ContextJSON), &binding) != nil || !nonblankAudit(binding.Repository) || !nonblankAudit(binding.ReviewedSHA) || !nonblankAudit(binding.MaterialVersion) || (binding.Scope != "bead" && binding.Scope != "plan") || result.Repository != binding.Repository || result.ReviewedSHA != binding.ReviewedSHA || result.Scope != binding.Scope {
		return ErrValidation
	}
	e := r.OriginalRequest.Effect
	if e.Kind == "add-human-hold" || e.Kind == "add-initial-human-hold" {
		if result.Outcome != "partial" || result.MaterialVersion != e.MaterialVersion || binding.MaterialVersion != e.MaterialVersion {
			return ErrValidation
		}
		return nil
	}
	if result.Outcome != "success" {
		return ErrValidation
	}
	records, err := DecodeAuditReceiptRecords(e.ReceiptRecordsJSON)
	if err != nil {
		return err
	}
	for _, record := range records {
		var receipt struct {
			Value AuditReceipt `json:"value"`
		}
		if json.Unmarshal([]byte(record.Value), &receipt) != nil {
			return ErrValidation
		}
		v := receipt.Value
		if v.Scope == result.Scope && v.Repository == result.Repository && v.ReviewedSHA == result.ReviewedSHA && v.MaterialVersion == result.MaterialVersion && sameOptionalString(v.PlanVersion, result.PlanVersion) {
			return nil
		}
	}
	return ErrValidation
}
func sameOptionalString(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
