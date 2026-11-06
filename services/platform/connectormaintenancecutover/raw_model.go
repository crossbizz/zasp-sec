package connectormaintenancecutover

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"unicode/utf8"
)

// The existing owned-runtime adapter's exact descriptor-reviewed defaults.
// This roster applies only to this complete, pinned product model. It grants no
// generic unknown-field or empty-value tolerance.
//
//go:embed readback_defaults.json
var readbackDefaults []byte

func modelPath(value any, segments []any) any {
	for _, segment := range segments {
		switch key := segment.(type) {
		case string:
			object, ok := value.(map[string]any)
			if !ok {
				return nil
			}
			value = object[key]
		case json.Number:
			index, err := key.Int64()
			array, ok := value.([]any)
			if err != nil || !ok || index < 0 || index >= int64(len(array)) {
				return nil
			}
			value = array[index]
		default:
			return nil
		}
	}
	return value
}

func projectReadbackDefaults(expected, model any) error {
	roster, err := exactDocument(readbackDefaults)
	rows, ok := roster.([]any)
	if err != nil || !ok || len(rows) != 312 {
		return ErrRefused
	}
	for _, entry := range rows {
		row, ok := entry.(map[string]any)
		if !ok || len(row) != 2 {
			return ErrRefused
		}
		segments, ok := row["segments"].([]any)
		if !ok || len(segments) == 0 {
			return ErrRefused
		}
		field, ok := segments[len(segments)-1].(string)
		if !ok {
			return ErrRefused
		}
		fallback, ok := row["default"]
		if !ok {
			return ErrRefused
		}
		sourceParent, sourceOK := modelPath(expected, segments[:len(segments)-1]).(map[string]any)
		actualParent, actualOK := modelPath(model, segments[:len(segments)-1]).(map[string]any)
		if !sourceOK || !actualOK {
			continue
		}
		if _, present := sourceParent[field]; present {
			continue
		}
		if value, present := actualParent[field]; present && reflect.DeepEqual(value, fallback) {
			delete(actualParent, field)
		}
	}
	return nil
}

// Decode before the SDK: no duplicate members, trailing tokens or dropped fields.
func exactValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, ErrRefused
	}
	t, e := d.Token()
	if e != nil {
		return nil, ErrRefused
	}
	switch delim := t.(type) {
	case json.Delim:
		if delim == '{' {
			m := map[string]any{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return nil, ErrRefused
				}
				name, ok := key.(string)
				if !ok {
					return nil, ErrRefused
				}
				if _, ok = m[name]; ok {
					return nil, ErrRefused
				}
				v, e := exactValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[name] = v
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return nil, ErrRefused
			}
			return m, nil
		}
		if delim == '[' {
			a := []any{}
			for d.More() {
				v, e := exactValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return nil, ErrRefused
			}
			return a, nil
		}
		return nil, ErrRefused
	default:
		return t, nil
	}
}
func exactDocument(b []byte) (any, error) {
	if len(b) > 1<<20 || !utf8.Valid(b) {
		return nil, ErrRefused
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, e := exactValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrRefused
	}
	return v, nil
}
func wholeRawModel(response, source []byte, id string) error {
	_, err := normalizedRawModel(response, source, id)
	return err
}

func normalizedRawModel(response, source []byte, id string) ([]byte, error) {
	if fmt.Sprintf("%x", sha256.Sum256(source)) != "329f49e1f2effecbe1a0e9caf6c89be939b1e36e034155d74977bfc82c73cc2c" {
		return nil, ErrRefused
	}
	expected, e := exactDocument(source)
	if e != nil {
		return nil, ErrRefused
	}
	actual, e := exactDocument(response)
	if e != nil {
		return nil, ErrRefused
	}
	root, ok := actual.(map[string]any)
	if !ok || len(root) != 1 {
		return nil, ErrRefused
	}
	model, ok := root["authorization_model"].(map[string]any)
	if !ok || model["id"] != id || id == "" {
		return nil, ErrRefused
	}
	delete(model, "id")
	if projectReadbackDefaults(expected, model) != nil || !reflect.DeepEqual(expected, model) {
		return nil, ErrRefused
	}
	// The SDK must receive the exact validated sparse representation too: its
	// pointer fields distinguish absent values from emitted empty defaults.
	model["id"] = id
	data, err := json.Marshal(root)
	if err != nil {
		return nil, ErrRefused
	}
	return data, nil
}
