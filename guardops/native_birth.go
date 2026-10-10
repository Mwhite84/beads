package guardops

import (
	"encoding/json"
	"regexp"
)

const NativeBirthScope = "native-incarnation-since-create"

var birthEventID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type NativeBirthValue struct {
	Kind                            string `json:"kind"`
	Protocol                        string `json:"protocol"`
	IssueID                         string `json:"issueId"`
	GuardGeneration                 string `json:"guardGeneration"`
	Incarnation                     string `json:"incarnation"`
	CreatedEventID                  string `json:"createdEventId"`
	Actor                           string `json:"actor"`
	InitialHumanLabelEventIDsDigest string `json:"initialHumanLabelEventIdsDigest"`
	Scope                           string `json:"scope"`
	HistoryComplete                 *bool  `json:"historyComplete"`
}
type NativeBirthEnvelope struct {
	Version   int              `json:"version"`
	Namespace string           `json:"namespace"`
	Value     NativeBirthValue `json:"value"`
}
type NativeBirthResult struct {
	IssueID                         string `json:"issueId"`
	Born                            bool   `json:"born"`
	GuardGeneration                 string `json:"guardGeneration"`
	Incarnation                     string `json:"incarnation"`
	CreatedEventID                  string `json:"createdEventId"`
	Actor                           string `json:"actor"`
	BirthRecordKey                  string `json:"birthRecordKey"`
	BirthRecordValueDigest          string `json:"birthRecordValueDigest"`
	InitialHumanLabelEventIDsDigest string `json:"initialHumanLabelEventIdsDigest"`
	Scope                           string `json:"scope"`
	HistoryComplete                 bool   `json:"historyComplete"`
}
type NativeBirthReference struct {
	RecordKey         string `json:"recordKey"`
	RecordValueDigest string `json:"recordValueDigest"`
	Incarnation       string `json:"incarnation"`
	CreatedEventID    string `json:"createdEventId"`
}
type InitialAuditHoldValue struct {
	Kind                   string               `json:"kind"`
	OperationID            string               `json:"operationId"`
	GuardGeneration        string               `json:"guardGeneration"`
	OriginalToken          string               `json:"originalToken"`
	Actor                  string               `json:"actor"`
	HeldAt                 string               `json:"heldAt"`
	MaterialVersion        string               `json:"materialVersion"`
	ClearanceNamespace     string               `json:"clearanceNamespace"`
	ClearanceContentDigest string               `json:"clearanceContentDigest"`
	Baseline               string               `json:"baseline"`
	Scope                  string               `json:"scope"`
	HistoryComplete        *bool                `json:"historyComplete"`
	Clearance              json.RawMessage      `json:"clearance"`
	Birth                  NativeBirthReference `json:"birth"`
}
type InitialAuditHoldEnvelope struct {
	Version   int                   `json:"version"`
	Namespace string                `json:"namespace"`
	Value     InitialAuditHoldValue `json:"value"`
}

func NativeBirthNamespace(id string) string {
	return RecordValueDigest("beads.guard.birth.v1\x00" + id)
}
func NativeBirthOperationID(id string) string {
	return "native-birth-reservation-" + RecordValueDigest(id)
}
func NativeBirthSpentOperationID(id string) string {
	return "native-birth-spent-" + RecordValueDigest(id)
}
func NativeBirthSpentKey(id string) string { return "bd.guard.birth.spent.v1." + RecordValueDigest(id) }
func AuditContentKey(namespace, raw string) string {
	return "krewe.audit.v1." + namespace + "." + RecordValueDigest(raw)
}
func NativeBirthDigest(v NativeBirthValue, key, raw string) string {
	return digestStrings([]string{Protocol, "native-create-birth", v.GuardGeneration, v.IssueID, v.Incarnation, v.CreatedEventID, v.Actor, key, raw})
}
func ParseNativeBirth(key, raw, id string) (NativeBirthEnvelope, error) {
	var b NativeBirthEnvelope
	shape := wireShape{"version": nil, "namespace": nil, "value": {"kind": nil, "protocol": nil, "issueId": nil, "guardGeneration": nil, "incarnation": nil, "createdEventId": nil, "actor": nil, "initialHumanLabelEventIdsDigest": nil, "scope": nil, "historyComplete": nil}}
	if exactAuditRecord(raw, shape, &b) != nil {
		return b, ErrValidation
	}
	v := b.Value
	if b.Version != 1 || b.Namespace != NativeBirthNamespace(id) || !validClearanceKey(key, b.Namespace, raw) || v.Kind != "native-create-birth" || v.Protocol != Protocol || v.IssueID != id || !nonblankAudit(v.GuardGeneration) || !auditHash(v.Incarnation) || !birthEventID.MatchString(v.CreatedEventID) || !nonblankAudit(v.Actor) || len(v.Actor) > 255 || v.InitialHumanLabelEventIDsDigest != RecordValueDigest("[]") || v.Scope != NativeBirthScope || v.HistoryComplete == nil || *v.HistoryComplete {
		return b, ErrValidation
	}
	return b, nil
}
func DecodeInitialAuditHoldRecord(r Request) (InitialAuditHoldEnvelope, error) {
	var h InitialAuditHoldEnvelope
	e := r.Effect
	shape := wireShape{"version": nil, "namespace": nil, "value": {"kind": nil, "operationId": nil, "guardGeneration": nil, "originalToken": nil, "actor": nil, "heldAt": nil, "materialVersion": nil, "clearanceNamespace": nil, "clearanceContentDigest": nil, "baseline": nil, "scope": nil, "historyComplete": nil, "clearance": nil, "birth": {"recordKey": nil, "recordValueDigest": nil, "incarnation": nil, "createdEventId": nil}}}
	if exactAuditRecord(e.HoldRecordValue, shape, &h) != nil {
		return h, ErrValidation
	}
	v := h.Value
	birthKey := "krewe.audit.v1." + NativeBirthNamespace(r.Expected.IssueID) + "." + e.BirthRecordValueDigest
	if h.Version != 1 || !validClearanceKey(e.HoldRecordKey, h.Namespace, e.HoldRecordValue) || h.Namespace == e.ClearanceNamespace || h.Namespace == NativeBirthNamespace(r.Expected.IssueID) || v.Kind != "initial-unworkable-hold" || v.OperationID != r.OperationID || v.GuardGeneration != r.Expected.Generation || v.OriginalToken != r.Expected.Token || v.Actor != r.Actor || !auditTime(v.HeldAt) || v.MaterialVersion != e.MaterialVersion || !nonblankAudit(e.MaterialVersion) || len(e.MaterialVersion) > 256 || v.ClearanceNamespace != e.ClearanceNamespace || v.ClearanceContentDigest != e.ClearanceContentDigest || !auditHash(e.ClearanceNamespace) || e.ClearanceNamespace == NativeBirthNamespace(r.Expected.IssueID) || e.ClearanceContentDigest != RecordValueDigest("[]") || v.Baseline != "native-create-birth" || v.Scope != NativeBirthScope || v.HistoryComplete == nil || *v.HistoryComplete || string(v.Clearance) != "null" || v.Birth.RecordKey != e.BirthRecordKey || e.BirthRecordKey != birthKey || v.Birth.RecordValueDigest != e.BirthRecordValueDigest || !auditHash(v.Birth.RecordValueDigest) || !auditHash(v.Birth.Incarnation) || !birthEventID.MatchString(v.Birth.CreatedEventID) {
		return h, ErrValidation
	}
	return h, nil
}

func ParseNativeBirthResult(raw string) (NativeBirthResult, error) {
	var b NativeBirthResult
	shape := wireShape{"issueId": nil, "born": nil, "guardGeneration": nil, "incarnation": nil, "createdEventId": nil, "actor": nil, "birthRecordKey": nil, "birthRecordValueDigest": nil, "initialHumanLabelEventIdsDigest": nil, "scope": nil, "historyComplete": nil}
	if exactAuditRecord(raw, shape, &b) != nil {
		return b, ErrValidation
	}
	return b, nil
}
