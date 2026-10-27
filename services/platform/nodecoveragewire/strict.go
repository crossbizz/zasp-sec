package nodecoveragewire

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var timeType = reflect.TypeOf(time.Time{})

// strictDecode checks exact field spelling, required presence, duplicate keys and
// nulls before encoding/json can fold aliases or turn null into a zero value.
func strictDecode(raw []byte, dst any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) || !validEscapes(raw) {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if checkJSON(d, reflect.TypeOf(dst).Elem(), 0) != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func structFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			for k, v := range structFields(f.Type) {
				fields[k] = v
			}
			continue
		}
		key := strings.Split(f.Tag.Get("json"), ",")[0]
		if key != "" && key != "-" {
			fields[key] = f.Type
		}
	}
	return fields
}
func checkJSON(d *json.Decoder, t reflect.Type, depth int) error {
	if depth > 12 {
		return ErrInvalid
	}
	tok, e := d.Token()
	if e != nil || tok == nil {
		return ErrInvalid
	}
	if t == timeType {
		s, ok := tok.(string)
		if !ok {
			return ErrInvalid
		}
		v, e := time.Parse(time.RFC3339Nano, s)
		if e != nil || v.IsZero() || v.Location() != time.UTC || v.Format(time.RFC3339Nano) != s {
			return ErrInvalid
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		if tok != json.Delim('{') {
			return ErrInvalid
		}
		fields := structFields(t)
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			key, ok := k.(string)
			field, known := fields[key]
			if e != nil || !ok || !known || seen[key] {
				return ErrInvalid
			}
			seen[key] = true
			if checkJSON(d, field, depth+1) != nil {
				return ErrInvalid
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') || len(seen) != len(fields) {
			return ErrInvalid
		}
	case reflect.Map:
		if tok != json.Delim('{') || t.Key().Kind() != reflect.String {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			key, ok := k.(string)
			if e != nil || !ok || seen[key] || len(seen) >= 8 {
				return ErrInvalid
			}
			seen[key] = true
			if checkJSON(d, t.Elem(), depth+1) != nil {
				return ErrInvalid
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case reflect.Slice:
		if tok != json.Delim('[') {
			return ErrInvalid
		}
		n := 0
		max := 1000
		if t.Elem().Kind() == reflect.String {
			max = 32
		}
		for d.More() {
			n++
			if n > max || checkJSON(d, t.Elem(), depth+1) != nil {
				return ErrInvalid
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	case reflect.String:
		if s, ok := tok.(string); !ok || len(s) > 65536 {
			return ErrInvalid
		}
	case reflect.Bool:
		if _, ok := tok.(bool); !ok {
			return ErrInvalid
		}
	case reflect.Int64:
		n, ok := tok.(json.Number)
		if !ok {
			return ErrInvalid
		}
		if _, e := strconv.ParseInt(string(n), 10, 64); e != nil {
			return ErrInvalid
		}
	case reflect.Uint64:
		n, ok := tok.(json.Number)
		if !ok {
			return ErrInvalid
		}
		if _, e := strconv.ParseUint(string(n), 10, 64); e != nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// encoding/json replaces isolated UTF-16 surrogates; reject those before loss.
func validEscapes(raw []byte) bool {
	in := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			in = !in
			continue
		}
		if !in || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xDC00 && n <= 0xDFFF {
			return false
		}
		if n < 0xD800 || n > 0xDBFF {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if e != nil || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		i += 6
	}
	return !in
}
