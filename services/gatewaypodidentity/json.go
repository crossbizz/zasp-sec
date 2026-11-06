package gatewaypodidentity

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Only paths with security semantics have case-sensitive reserved fields.
// Arbitrary labels, annotations, extra keys and extension objects stay opaque.
func fields(path string) string {
	switch path {
	case "":
		return "apiVersion kind metadata spec status iss aud sub exp kubernetes.io"
	case "metadata":
		return "name namespace uid deletionTimestamp ownerReferences labels"
	case "metadata.ownerReferences.*":
		return "apiVersion kind name uid controller"
	case "spec":
		return "serviceAccountName nodeName template"
	case "spec.template":
		return "spec"
	case "spec.template.spec":
		return "serviceAccountName"
	case "status":
		return "authenticated error audiences user nodeInfo phase"
	case "status.user":
		return "username uid extra"
	case "status.nodeInfo":
		return "bootID"
	case "kubernetes.io":
		return "namespace serviceaccount pod"
	case "kubernetes.io.serviceaccount", "kubernetes.io.pod":
		return "name uid"
	}
	return ""
}
func alias(path, key string) bool {
	for _, known := range strings.Fields(fields(path)) {
		if key != known && strings.EqualFold(key, known) {
			return true
		}
	}
	return false
}
func parseJSON(raw []byte) (map[string]any, error) {
	if !utf8.Valid(raw) || !validEscapes(raw) {
		return nil, ErrDenied
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	budget := 100000
	value, e := jsonValue(d, "", 0, &budget)
	if e != nil {
		return nil, ErrDenied
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, ErrDenied
	}
	o, ok := value.(map[string]any)
	if !ok {
		return nil, ErrDenied
	}
	return o, nil
}
func jsonValue(d *json.Decoder, path string, depth int, budget *int) (any, error) {
	*budget--
	if depth > 32 || *budget < 0 {
		return nil, ErrDenied
	}
	t, e := d.Token()
	if e != nil {
		return nil, ErrDenied
	}
	delim, container := t.(json.Delim)
	if !container {
		return t, nil
	}
	switch delim {
	case '{':
		m := map[string]any{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return nil, ErrDenied
			}
			k, ok := key.(string)
			if !ok || alias(path, k) {
				return nil, ErrDenied
			}
			if _, exists := m[k]; exists {
				return nil, ErrDenied
			}
			next := k
			if path != "" {
				next = path + "." + k
			}
			v, e := jsonValue(d, next, depth+1, budget)
			if e != nil {
				return nil, ErrDenied
			}
			m[k] = v
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return nil, ErrDenied
		}
		return m, nil
	case '[':
		a := []any{}
		for d.More() {
			v, e := jsonValue(d, path+".*", depth+1, budget)
			if e != nil {
				return nil, ErrDenied
			}
			a = append(a, v)
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return nil, ErrDenied
		}
		return a, nil
	}
	return nil, ErrDenied
}

// encoding/json replaces invalid UTF-16 escapes. Reject them before decoding
// rather than silently changing the authenticated identity text.
func validEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		closed := false
		for i < len(raw) {
			if raw[i] == '"' {
				closed = true
				break
			}
			if raw[i] == '\\' {
				i++
				if i >= len(raw) {
					return false
				}
				if raw[i] == 'u' {
					if i+4 >= len(raw) {
						return false
					}
					n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
					if e != nil {
						return false
					}
					i += 4
					if n >= 0xd800 && n <= 0xdbff {
						if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
							return false
						}
						lo, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
						if e != nil || lo < 0xdc00 || lo > 0xdfff {
							return false
						}
						i += 6
					} else if n >= 0xdc00 && n <= 0xdfff {
						return false
					}
				}
			}
			i++
		}
		if !closed {
			return false
		}
	}
	return true
}
