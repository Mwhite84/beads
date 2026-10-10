package guardops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// MaxWireBytes allows the worst-case JSON escaping of bounded opaque strings.
const MaxWireBytes = 6*(MaxStateBytes+MaxContextBytes) + (1 << 20)

func DecodeRequest(raw []byte) (Request, error) {
	var request Request
	if err := decodeExact(raw, &request); err != nil {
		return request, err
	}
	return request, ValidateRequest(request)
}

func DecodeLookup(raw []byte) (LookupRequest, error) {
	var request LookupRequest
	if err := decodeExact(raw, &request); err != nil {
		return request, err
	}
	return request, ValidateLookup(request)
}

func decodeExact(raw []byte, target any) error {
	if len(raw) > MaxWireBytes || !utf8.Valid(raw) {
		return fmt.Errorf("%w: invalid or oversized encoding", ErrValidation)
	}
	if err := rejectUnpairedEscapes(raw); err != nil {
		return err
	}
	// encoding/json normally accepts duplicate object keys and replaces invalid
	// escaped UTF-16. Neither is an exact byte-preserving protocol boundary.
	keys := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueValue(keys); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if _, err := keys.Token(); err != io.EOF {
		return fmt.Errorf("%w: exactly one object required", ErrValidation)
	}
	var shape wireShape
	switch target.(type) {
	case *Request:
		shape = wireShape{
			"protocol": nil, "operationId": nil, "actor": nil, "contextJson": nil,
			"expected": {"protocol": nil, "issueId": nil, "database": nil, "branch": nil,
				"head": nil, "root": nil, "generation": nil, "token": nil, "stateJson": nil},
			"effect": {"kind": nil},
		}
	case *LookupRequest:
		shape = wireShape{"protocol": nil, "operationId": nil, "requestDigest": nil}
	default:
		return ErrValidation
	}
	// encoding/json also matches case-insensitive aliases of tagged fields.
	// Require every canonical field by its exact spelling before typed decode.
	if err := exactKeys(raw, shape); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	return nil
}

type wireShape map[string]wireShape

func exactKeys(raw json.RawMessage, shape wireShape) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil || len(object) != len(shape) {
		return fmt.Errorf("%w: exact object shape required", ErrValidation)
	}
	for key, child := range shape {
		value, exists := object[key]
		if !exists {
			return fmt.Errorf("%w: canonical field %s required", ErrValidation, key)
		}
		if child != nil {
			if err := exactKeys(value, child); err != nil {
				return err
			}
		}
	}
	return nil
}

func uniqueValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("duplicate or invalid object key")
			}
			seen[name] = true
			if err := uniqueValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueValue(decoder); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func rejectUnpairedEscapes(raw []byte) error {
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			return ErrValidation
		}
		if raw[i+1] != 'u' {
			i++ // escaped quote or backslash cannot open/close a string
			continue
		}
		if i+6 > len(raw) {
			return ErrValidation
		}
		unit, err := strconv.ParseUint(string(raw[i+2:i+6]), 16, 16)
		if err != nil {
			return ErrValidation
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			if i+12 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
				return ErrValidation
			}
			low, err := strconv.ParseUint(string(raw[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return ErrValidation
			}
			i += 11
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return ErrValidation
		} else {
			i += 5
		}
	}
	return nil
}
