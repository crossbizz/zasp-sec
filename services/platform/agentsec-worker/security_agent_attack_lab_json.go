package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"time"
)

// SQL envelopes carry RFC3339 timestamps and embedded JSON objects. Validate
// every key before typed decoding, including duplicate keys inside raw JSON.
func decodeAttackLabJSON(raw []byte, target any) error {
	if target == nil || len(raw) == 0 || len(raw) > 64<<20 {
		return errRuntimeUnavailable
	}
	if !attackLabJSONKeys(json.NewDecoder(bytes.NewReader(raw)), reflect.TypeOf(target), 0) {
		return errRuntimeUnavailable
	}
	return decodeStrictWorkerJSON(raw, target)
}
func attackLabJSONKeys(d *json.Decoder, typ reflect.Type, depth int) bool {
	if depth > 24 {
		return false
	}
	nullable := false
	for typ != nil && typ.Kind() == reflect.Pointer {
		nullable = true
		typ = typ.Elem()
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		typ = nil
	}
	if token == nil {
		return typ == nil || nullable
	}
	if typ == reflect.TypeOf(time.Time{}) {
		s, ok := token.(string)
		if !ok {
			return false
		}
		_, err := time.Parse(time.RFC3339Nano, s)
		return err == nil
	}
	if typ == nil {
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !attackLabJSONKeys(d, nil, depth+1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case json.Delim('['):
			for d.More() {
				if !attackLabJSONKeys(d, nil, depth+1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			_, compound := token.(json.Delim)
			return !compound
		}
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return false
		}
		fields := map[string]reflect.Type{}
		required := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")
			if tag[0] == "" || tag[0] == "-" {
				continue
			}
			fields[tag[0]] = field.Type
			required[tag[0]] = true
			for _, option := range tag[1:] {
				if option == "omitempty" {
					delete(required, tag[0])
				}
			}
		}
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			field, exists := fields[name]
			if err != nil || !ok || !exists || seen[name] {
				return false
			}
			seen[name] = true
			delete(required, name)
			if !attackLabJSONKeys(d, field, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}') && len(required) == 0
	case reflect.Slice:
		if token != json.Delim('[') {
			return false
		}
		for d.More() {
			if !attackLabJSONKeys(d, typ.Elem(), depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	default:
		_, compound := token.(json.Delim)
		return !compound
	}
}
