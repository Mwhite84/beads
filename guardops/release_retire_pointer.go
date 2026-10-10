package guardops

import (
	"encoding/json"
	"strings"
)

func validateRetirePointer(e Effect) error {
	if !nonblankAudit(e.ClaimPointer) || len(e.Comment) > MaxAuditRecordBytes {
		return ErrValidation
	}
	var comment struct{ Schema, Code, Reason, RetiredClaimPointer string }
	if exactAuditRecord(e.Comment, wireShape{"schema": nil, "code": nil, "reason": nil, "retiredClaimPointer": nil}, &comment) != nil || comment.Schema != "omg.bead-claim-release.v1" || !nonblankAudit(comment.Code) || !nonblankAudit(comment.Reason) || comment.RetiredClaimPointer != e.ClaimPointer {
		return ErrValidation
	}
	return nil
}

// Retirement rejects ambiguous metadata before native deletion can normalize it.
func RetirePointerMetadata(raw json.RawMessage, pointer string) (map[string]json.RawMessage, error) {
	var values map[string]json.RawMessage
	if strings.TrimSpace(string(raw)) == "" || json.Unmarshal(raw, &values) != nil || values == nil {
		return nil, ErrValidation
	}
	shape := wireShape{}
	for key := range values {
		shape[key] = nil
	}
	if exactAuditRecord(string(raw), shape, &values) != nil {
		return nil, ErrValidation
	}
	var saved string
	if json.Unmarshal(values["krewe_claim_run"], &saved) != nil || !nonblankAudit(saved) || saved != pointer {
		return nil, ErrValidation
	}
	delete(values, "krewe_claim_run")
	return values, nil
}
