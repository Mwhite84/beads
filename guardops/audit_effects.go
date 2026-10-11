package guardops

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var auditResultFence = regexp.MustCompile("(?s)^bead-audit-result\\n(?:[ \\t]*\\n)*```json[ \\t]*\\n(.*?)\\n```[ \\t]*(?:\\n|$)")
var auditAnyFence = regexp.MustCompile("(?m)^[ \\t]*```")

// An explanatory result is neither a successful receipt nor a lifecycle effect.
// Only its typed envelope is checked here; model and repository evidence remain
// the orchestration caller's responsibility under the ORIGINAL native capture.
func validateAuditFailureComment(body string) error {
	if !utf8.ValidString(body) || len(body) > MaxAuditRecordBytes {
		return ErrValidation
	}
	normalized := strings.ReplaceAll(body, "\r\n", "\n")
	match := auditResultFence.FindStringSubmatch(normalized)
	if len(match) != 2 || len(auditAnyFence.FindAllStringIndex(normalized, -1)) != 2 {
		return ErrValidation
	}
	shape := wireShape{"outcome": nil, "materialVersion": nil, "planVersion": nil, "repository": nil, "reviewedSha": nil, "scope": nil, "findings": nil}
	var fields map[string]json.RawMessage
	if json.Unmarshal([]byte(match[1]), &fields) != nil {
		return ErrValidation
	}
	if _, exists := fields["transcriptUrl"]; exists {
		shape["transcriptUrl"] = nil
	}
	var findings []any
	if json.Unmarshal(fields["findings"], &findings) != nil || findings == nil {
		return ErrValidation
	}
	for _, finding := range findings {
		if _, isString := finding.(string); !isString {
			return ErrValidation
		}
	}
	var result struct {
		Outcome, MaterialVersion, Repository, ReviewedSha, Scope string
		PlanVersion                                              *string
		Findings                                                 []string
		TranscriptURL                                            *string `json:"transcriptUrl"`
	}
	if exactAuditRecord(match[1], shape, &result) != nil || (result.Outcome != "failed" && result.Outcome != "partial") || (result.Scope != "bead" && result.Scope != "plan") || result.Findings == nil {
		return ErrValidation
	}
	for _, text := range []string{result.MaterialVersion, result.Repository, result.ReviewedSha} {
		if !nonblankAudit(text) {
			return ErrValidation
		}
	}
	if result.PlanVersion != nil && !nonblankAudit(*result.PlanVersion) {
		return ErrValidation
	}
	if _, exists := fields["transcriptUrl"]; exists && (result.TranscriptURL == nil || !nonblankAudit(*result.TranscriptURL)) {
		return ErrValidation
	}
	return nil
}

// Native config/event TEXT is byte bounded. No warnings or truncation may be
// acknowledged as an exact audit effect; publication also verifies readback.
const MaxAuditRecordBytes = 65535
const MaxAuditDescriptionBytes = 1 << 20

type AuditRecord struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
type AuditReceipt struct {
	Repository      string  `json:"repository"`
	ReviewedSHA     string  `json:"reviewedSha"`
	MaterialVersion string  `json:"materialVersion"`
	PlanVersion     *string `json:"planVersion"`
	Scope           string  `json:"scope"`
	Outcome         string  `json:"outcome"`
	RecordedAt      string  `json:"recordedAt"`
}
type AuditClearance = clearanceValue
type AuditHoldValue struct {
	Kind                   string         `json:"kind"`
	OperationID            string         `json:"operationId"`
	GuardGeneration        string         `json:"guardGeneration"`
	OriginalToken          string         `json:"originalToken"`
	Actor                  string         `json:"actor"`
	HeldAt                 string         `json:"heldAt"`
	MaterialVersion        string         `json:"materialVersion"`
	ClearanceNamespace     string         `json:"clearanceNamespace"`
	ClearanceContentDigest string         `json:"clearanceContentDigest"`
	Baseline               string         `json:"baseline"`
	HistoryComplete        *bool          `json:"historyComplete"`
	Clearance              AuditClearance `json:"clearance"`
}
type AuditHoldEnvelope struct {
	Version   int            `json:"version"`
	Namespace string         `json:"namespace"`
	Value     AuditHoldValue `json:"value"`
}

func hasAuditFields(e Effect) bool {
	return e.ArchiveComment != "" || e.AcceptedDescription != "" || e.ReceiptRecordsJSON != "" || e.MaterialVersion != "" || e.ClearanceNamespace != "" || e.ClearanceContentDigest != "" || e.HoldRecordKey != "" || e.HoldRecordValue != ""
}
func nonblankAudit(s string) bool { return strings.TrimSpace(s) != "" && utf8.ValidString(s) }
func auditHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && strings.ToLower(s) == s
}
func auditTime(s string) bool {
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil && strings.HasSuffix(s, "Z")
}
func exactAuditRecord(raw string, shape wireShape, target any) error {
	if len(raw) > MaxAuditRecordBytes {
		return ErrValidation
	}
	return decodeClearanceRecord(raw, shape, target)
}

func validateAuditEffect(r Request) error {
	e := r.Effect
	switch e.Kind {
	case "archive-replace", "validate":
		if e.MaterialVersion != "" || e.ClearanceNamespace != "" || e.ClearanceContentDigest != "" || e.HoldRecordKey != "" || e.HoldRecordValue != "" {
			return ErrValidation
		}
		if e.Kind == "validate" && (e.ArchiveComment != "" || e.AcceptedDescription != "") {
			return ErrValidation
		}
		if e.Kind == "archive-replace" {
			if !nonblankAudit(e.AcceptedDescription) || len(e.AcceptedDescription) > MaxAuditDescriptionBytes || len(e.ArchiveComment) > MaxAuditRecordBytes || !utf8.ValidString(e.ArchiveComment) {
				return ErrValidation
			}
			parts := strings.SplitN(e.ArchiveComment, "\n", 4)
			if len(parts) != 4 || parts[0] != "bead-audit-archive" || parts[2] != "" || !auditTime(parts[1]) {
				return ErrValidation
			}
		}
		_, err := DecodeAuditReceiptRecords(e.ReceiptRecordsJSON)
		return err
	case "add-human-hold":
		if e.ArchiveComment != "" || e.AcceptedDescription != "" || e.ReceiptRecordsJSON != "" {
			return ErrValidation
		}
		_, err := DecodeAuditHoldRecord(r)
		return err
	}
	return ErrValidation
}

// DecodeAuditReceiptRecords validates exact successful envelopes. Receipt
// material/repository bindings are caller policy; full native state is the CAS.
func DecodeAuditReceiptRecords(raw string) ([]AuditRecord, error) {
	if len(raw) > 2*MaxAuditRecordBytes+1024 || !utf8.ValidString(raw) || rejectUnpairedEscapes([]byte(raw)) != nil {
		return nil, ErrValidation
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	if uniqueValue(d) != nil {
		return nil, ErrValidation
	}
	var records []AuditRecord
	var items []json.RawMessage
	if json.Unmarshal([]byte(raw), &items) != nil || len(items) < 1 || len(items) > 2 {
		return nil, ErrValidation
	}
	seen := map[string]bool{}
	scopes := map[string]bool{}
	var first *AuditReceipt
	var ns string
	for _, item := range items {
		if exactKeys(item, wireShape{"key": nil, "value": nil}) != nil {
			return nil, ErrValidation
		}
		var record AuditRecord
		if json.Unmarshal(item, &record) != nil || seen[record.Key] {
			return nil, ErrValidation
		}
		seen[record.Key] = true
		var envelope struct {
			Version   int          `json:"version"`
			Namespace string       `json:"namespace"`
			Value     AuditReceipt `json:"value"`
		}
		shape := wireShape{"version": nil, "namespace": nil, "value": {"repository": nil, "reviewedSha": nil, "materialVersion": nil, "planVersion": nil, "scope": nil, "outcome": nil, "recordedAt": nil}}
		if exactAuditRecord(record.Value, shape, &envelope) != nil || envelope.Version != 1 || !validClearanceKey(record.Key, envelope.Namespace, record.Value) {
			return nil, ErrValidation
		}
		v := envelope.Value
		if !nonblankAudit(v.Repository) || !nonblankAudit(v.ReviewedSHA) || !nonblankAudit(v.MaterialVersion) || v.Outcome != "success" || !auditTime(v.RecordedAt) || (v.Scope != "bead" && v.Scope != "plan") || (v.Scope == "plan" && v.PlanVersion == nil) || (v.PlanVersion != nil && !nonblankAudit(*v.PlanVersion)) || scopes[v.Scope] {
			return nil, ErrValidation
		}
		scopes[v.Scope] = true
		if first != nil && (v.Repository != first.Repository || v.ReviewedSHA != first.ReviewedSHA || v.MaterialVersion != first.MaterialVersion || envelope.Namespace != ns) {
			return nil, ErrValidation
		}
		if first == nil {
			first = &v
			ns = envelope.Namespace
		}
		records = append(records, record)
	}
	return records, nil
}

func DecodeAuditHoldRecord(r Request) (AuditHoldEnvelope, error) {
	var h AuditHoldEnvelope
	e := r.Effect
	shape := wireShape{"version": nil, "namespace": nil, "value": {"kind": nil, "operationId": nil, "guardGeneration": nil, "originalToken": nil, "actor": nil, "heldAt": nil, "materialVersion": nil, "clearanceNamespace": nil, "clearanceContentDigest": nil, "baseline": nil, "historyComplete": nil, "clearance": {"clearedBy": nil, "clearedAt": nil, "materialVersion": nil}}}
	if exactAuditRecord(e.HoldRecordValue, shape, &h) != nil {
		return h, ErrValidation
	}
	v := h.Value
	if h.Version != 1 || !validClearanceKey(e.HoldRecordKey, h.Namespace, e.HoldRecordValue) || h.Namespace == e.ClearanceNamespace || v.Kind != "bounded-unworkable-hold" || v.OperationID != r.OperationID || v.GuardGeneration != r.Expected.Generation || v.OriginalToken != r.Expected.Token || v.Actor != r.Actor || !auditTime(v.HeldAt) || v.MaterialVersion != e.MaterialVersion || !nonblankAudit(e.MaterialVersion) || len(e.MaterialVersion) > 256 || v.ClearanceNamespace != e.ClearanceNamespace || v.ClearanceContentDigest != e.ClearanceContentDigest || !auditHash(e.ClearanceNamespace) || !auditHash(e.ClearanceContentDigest) || v.Baseline != "unknown-legacy" || v.HistoryComplete == nil || *v.HistoryComplete || !nonblankAudit(v.Clearance.ClearedBy) || !auditTime(v.Clearance.ClearedAt) || !nonblankAudit(v.Clearance.MaterialVersion) || v.Clearance.MaterialVersion == e.MaterialVersion {
		return h, ErrValidation
	}
	return h, nil
}

// ParseAuditClearance is deliberately strict; malformed matching records stay
// unknown instead of being discarded to manufacture permission for a hold.
func ParseAuditClearance(key, raw, namespace string) (AuditClearance, error) {
	var c clearanceEnvelope
	if exactAuditRecord(raw, wireShape{"version": nil, "namespace": nil, "value": {"clearedBy": nil, "clearedAt": nil, "materialVersion": nil}}, &c) != nil || c.Version != 1 || c.Namespace != namespace || !validClearanceKey(key, namespace, raw) || !nonblankAudit(c.Value.ClearedBy) || !nonblankAudit(c.Value.MaterialVersion) || !auditTime(c.Value.ClearedAt) {
		return c.Value, ErrValidation
	}
	return c.Value, nil
}

type AuditClearanceHistory = clearanceHistoryEnvelope

func ParseAuditClearanceHistory(key, raw, namespace string) (AuditClearanceHistory, error) {
	var h AuditClearanceHistory
	shape := wireShape{"version": nil, "namespace": nil, "value": {"kind": nil, "operationId": nil, "guardGeneration": nil, "originalToken": nil, "baseline": nil, "historyComplete": nil, "clearance": {"clearedBy": nil, "clearedAt": nil, "materialVersion": nil}}}
	if exactAuditRecord(raw, shape, &h) != nil || h.Version != 1 || h.Namespace != namespace || !validClearanceKey(key, namespace, raw) || h.Value.Kind != "identified-clearance" || !nonblankAudit(h.Value.OperationID) || !nonblankAudit(h.Value.GuardGeneration) || !nonblankAudit(h.Value.OriginalToken) || h.Value.Baseline != "unknown-legacy" || h.Value.HistoryComplete == nil || *h.Value.HistoryComplete || !nonblankAudit(h.Value.Clearance.ClearedBy) || !auditTime(h.Value.Clearance.ClearedAt) || !nonblankAudit(h.Value.Clearance.MaterialVersion) {
		return h, ErrValidation
	}
	return h, nil
}
