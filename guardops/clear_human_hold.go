package guardops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

type clearanceValue struct {
	ClearedBy       string `json:"clearedBy"`
	ClearedAt       string `json:"clearedAt"`
	MaterialVersion string `json:"materialVersion"`
}

type clearanceEnvelope struct {
	Version   int            `json:"version"`
	Namespace string         `json:"namespace"`
	Value     clearanceValue `json:"value"`
}

type clearanceHistoryEnvelope struct {
	Version   int    `json:"version"`
	Namespace string `json:"namespace"`
	Value     struct {
		Kind            string         `json:"kind"`
		OperationID     string         `json:"operationId"`
		GuardGeneration string         `json:"guardGeneration"`
		OriginalToken   string         `json:"originalToken"`
		Baseline        string         `json:"baseline"`
		HistoryComplete *bool          `json:"historyComplete"`
		Clearance       clearanceValue `json:"clearance"`
	} `json:"value"`
}

func hasClearanceFields(e Effect) bool {
	return e.ClearanceKey != "" || e.ClearanceValue != "" || e.HistoryKey != "" || e.HistoryValue != ""
}

func validateClearanceEffect(r Request) error {
	valueShape := wireShape{"clearedBy": nil, "clearedAt": nil, "materialVersion": nil}
	var c clearanceEnvelope
	if err := decodeClearanceRecord(r.Effect.ClearanceValue, wireShape{"version": nil, "namespace": nil, "value": valueShape}, &c); err != nil {
		return err
	}
	var h clearanceHistoryEnvelope
	if err := decodeClearanceRecord(r.Effect.HistoryValue, wireShape{"version": nil, "namespace": nil, "value": {
		"kind": nil, "operationId": nil, "guardGeneration": nil, "originalToken": nil,
		"baseline": nil, "historyComplete": nil, "clearance": valueShape,
	}}, &h); err != nil {
		return err
	}
	when, err := time.Parse(time.RFC3339Nano, c.Value.ClearedAt)
	if err != nil || when.UTC().Format(time.RFC3339Nano) != c.Value.ClearedAt ||
		c.Value.ClearedBy != r.Actor || strings.TrimSpace(c.Value.MaterialVersion) == "" || len(c.Value.MaterialVersion) > 256 ||
		c.Version != 1 || h.Version != 1 || c.Namespace == h.Namespace ||
		h.Value.Kind != "identified-clearance" || h.Value.OperationID != r.OperationID ||
		h.Value.GuardGeneration != r.Expected.Generation || h.Value.OriginalToken != r.Expected.Token ||
		h.Value.Baseline != "unknown-legacy" || h.Value.HistoryComplete == nil || *h.Value.HistoryComplete || h.Value.Clearance != c.Value ||
		!validClearanceKey(r.Effect.ClearanceKey, c.Namespace, r.Effect.ClearanceValue) ||
		!validClearanceKey(r.Effect.HistoryKey, h.Namespace, r.Effect.HistoryValue) {
		return ErrValidation
	}
	return nil
}

func validClearanceKey(key, namespace, raw string) bool {
	decoded, err := hex.DecodeString(namespace)
	if err != nil || len(decoded) != 32 || strings.ToLower(namespace) != namespace {
		return false
	}
	hash := sha256.Sum256([]byte(raw))
	return key == "krewe.audit.v1."+namespace+"."+hex.EncodeToString(hash[:])
}

func decodeClearanceRecord(raw string, shape wireShape, target any) error {
	if len(raw) > MaxClearanceRecordBytes || !utf8.ValidString(raw) || rejectUnpairedEscapes([]byte(raw)) != nil {
		return ErrValidation
	}
	keys := json.NewDecoder(bytes.NewBufferString(raw))
	if uniqueValue(keys) != nil {
		return ErrValidation
	}
	if _, err := keys.Token(); err != io.EOF || exactKeys([]byte(raw), shape) != nil {
		return ErrValidation
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return ErrValidation
	}
	return nil
}
