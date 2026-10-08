package connectormaintenancecutover

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"unicode/utf8"
)

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
	expected, e := exactDocument(source)
	if e != nil {
		return ErrRefused
	}
	actual, e := exactDocument(response)
	if e != nil {
		return ErrRefused
	}
	root, ok := actual.(map[string]any)
	if !ok || len(root) != 1 {
		return ErrRefused
	}
	model, ok := root["authorization_model"].(map[string]any)
	if !ok || model["id"] != id || id == "" {
		return ErrRefused
	}
	delete(model, "id")
	if !reflect.DeepEqual(expected, model) {
		return ErrRefused
	}
	return nil
}
