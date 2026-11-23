// Package mcpschema compares local MCP tools/list captures without invoking any tool.
package mcpschema

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const version = "zasp.mcp-tool-contract.v1"
const limitBytes = 1 << 20
const maxTools = 256

var id = regexp.MustCompile(`^pid_[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$`)
var view = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var toolName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type Scope struct {
	Environment string `json:"environment_id"`
	Server      string `json:"server_id"`
	View        string `json:"view"`
}

func (s Scope) Valid() bool {
	return id.MatchString(s.Environment) && id.MatchString(s.Server) && view.MatchString(s.View)
}

type Tool struct {
	Name     string `json:"name"`
	Input    string `json:"input_digest"`
	Output   string `json:"output_digest,omitempty"`
	Metadata string `json:"metadata_digest"`
}

type Snapshot struct {
	Version string `json:"schema_version"`
	Source  string `json:"source"`
	Scope   Scope  `json:"scope"`
	Tools   []Tool `json:"tools"`
}
type Change struct {
	Name   string   `json:"tool"`
	Fields []string `json:"changes"`
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func fieldDigest(field string, value any) string {
	data, _ := json.Marshal(value) // All values are bounded JSON decoder tokens.
	return Digest(append([]byte(version+"/"+field+"\x00"), data...))
}

func bounded(input io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, limitBytes+1))
	if err != nil || len(data) > limitBytes || !utf8.Valid(data) {
		return nil, errors.New("input must be valid UTF-8 JSON within 1 MiB")
	}
	return data, nil
}

type tokenReader struct {
	d     *json.Decoder
	nodes int
}

func (r *tokenReader) value(depth int) (any, error) {
	r.nodes++
	if depth > 40 || r.nodes > 32768 {
		return nil, errors.New("JSON exceeds structural budget")
	}
	tok, err := r.d.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('{'):
		obj := map[string]any{}
		for r.d.More() {
			key, err := r.d.Token()
			if err != nil {
				return nil, err
			}
			name, ok := key.(string)
			if !ok {
				return nil, errors.New("invalid object key")
			}
			if _, dup := obj[name]; dup {
				return nil, errors.New("duplicate object key")
			}
			value, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			obj[name] = value
		}
		end, err := r.d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object")
		}
		return obj, nil
	case json.Delim('['):
		values := []any{}
		for r.d.More() {
			v, err := r.value(depth + 1)
			if err != nil {
				return nil, err
			}
			values = append(values, v)
		}
		end, err := r.d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array")
		}
		return values, nil
	case json.Delim('}'), json.Delim(']'):
		return nil, errors.New("unexpected delimiter")
	default:
		return tok, nil
	}
}

func rpcID(v any) bool {
	switch value := v.(type) {
	case string:
		return len(value) > 0 && len(value) <= 128
	case json.Number:
		_, err := value.Int64()
		return err == nil
	}
	return false
}

func checkedTool(value any) (Tool, error) {
	var tool Tool
	raw, ok := value.(map[string]any)
	if !ok {
		return tool, errors.New("invalid tool definition")
	}
	name, _ := raw["name"].(string)
	input, ok := raw["inputSchema"].(map[string]any)
	if !ok || input["type"] != "object" || !toolName.MatchString(name) {
		return tool, errors.New("unsupported tool name or missing input object schema")
	}
	tool.Name = name
	tool.Input = fieldDigest("input", input)
	if out, exists := raw["outputSchema"]; exists {
		o, ok := out.(map[string]any)
		if !ok || o["type"] != "object" {
			return tool, errors.New("invalid output object schema")
		}
		tool.Output = fieldDigest("output", o)
	}
	delete(raw, "name")
	delete(raw, "inputSchema")
	delete(raw, "outputSchema")
	tool.Metadata = fieldDigest("metadata", raw)
	return tool, nil
}

// Capture requires request/response pairs so a terminal page cannot be
// mistaken for a complete list if its request contained a starting cursor.
func Capture(scope Scope, input io.Reader) (Snapshot, error) {
	s := Snapshot{Version: version, Source: "operator_supplied_tools_list", Scope: scope, Tools: []Tool{}}
	if !scope.Valid() {
		return s, errors.New("invalid scope")
	}
	data, err := bounded(input)
	if err != nil {
		return s, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	reader := tokenReader{d: decoder}
	names := map[string]bool{}
	cursors := map[string]bool{}
	next := ""
	for page := 0; ; page++ {
		value, err := reader.value(0)
		if err == io.EOF {
			if page == 0 || next != "" {
				return s, errors.New("incomplete tools/list capture")
			}
			break
		}
		if err != nil || page >= 32 || (page > 0 && next == "") {
			return s, errors.New("invalid or oversized sequence of tools/list pages")
		}
		pair, ok := value.(map[string]any)
		if !ok || len(pair) != 2 {
			return s, errors.New("expected one JSON request/response pair per page")
		}
		req, ok1 := pair["request"].(map[string]any)
		answer, ok2 := pair["response"].(map[string]any)
		if !ok1 || !ok2 || req["jsonrpc"] != "2.0" || answer["jsonrpc"] != "2.0" || req["method"] != "tools/list" || !rpcID(req["id"]) || !rpcID(answer["id"]) || req["id"] != answer["id"] {
			return s, errors.New("mismatched JSON-RPC tools/list exchange")
		}
		if _, bad := answer["error"]; bad {
			return s, errors.New("JSON-RPC response reported an error")
		}
		var params map[string]any
		if p, exists := req["params"]; exists {
			params, ok = p.(map[string]any)
			if !ok {
				return s, errors.New("invalid tools/list parameters")
			}
		}
		for key := range params {
			if key != "cursor" && key != "_meta" {
				return s, errors.New("unsupported tools/list selection parameter")
			}
		}
		cursor, hasCursor := params["cursor"]
		if (page == 0 && hasCursor) || (page > 0 && cursor != next) {
			return s, errors.New("first page or cursor chain mismatch")
		}
		result, ok := answer["result"].(map[string]any)
		entries, okList := result["tools"].([]any)
		if !ok || !okList || len(entries) > maxTools-len(s.Tools) {
			return s, errors.New("missing or oversized tool list")
		}
		next = ""
		if v, present := result["nextCursor"]; present {
			next, ok = v.(string)
			if !ok || len(next) == 0 || len(next) > 2048 || cursors[next] {
				return s, errors.New("invalid or repeated continuation cursor")
			}
			cursors[next] = true
		}
		for _, entry := range entries {
			tool, err := checkedTool(entry)
			if err != nil {
				return s, err
			}
			if names[tool.Name] {
				return s, errors.New("duplicate tool name")
			}
			names[tool.Name] = true
			s.Tools = append(s.Tools, tool)
		}
	}
	slices.SortFunc(s.Tools, func(a, b Tool) int { return strings.Compare(a.Name, b.Name) })
	return s, nil
}

func Load(input io.Reader, expectedDigest string, scope Scope) (Snapshot, error) {
	var snap Snapshot
	data, err := bounded(input)
	if err != nil || !digest.MatchString(expectedDigest) || Digest(data) != expectedDigest {
		return snap, errors.New("baseline digest mismatch or unreadable baseline")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&snap) != nil || d.Decode(new(any)) != io.EOF || snap.Version != version || snap.Source != "operator_supplied_tools_list" || !scope.Valid() || snap.Scope != scope || snap.Tools == nil || len(snap.Tools) > maxTools {
		return snap, errors.New("unsupported baseline or mismatched Environment, server or view")
	}
	// Accept only our own canonical serialization, including the last newline.
	// This closes duplicate keys, reordered tools and silently ignored fields.
	canonical, _ := snap.Bytes()
	if !bytes.Equal(canonical, data) {
		return snap, errors.New("noncanonical baseline")
	}
	last := ""
	for _, t := range snap.Tools {
		if !toolName.MatchString(t.Name) || t.Name <= last || !digest.MatchString(t.Input) || !digest.MatchString(t.Metadata) || (t.Output != "" && !digest.MatchString(t.Output)) {
			return snap, errors.New("invalid baseline tool identity")
		}
		last = t.Name
	}
	return snap, nil
}

func (s Snapshot) Bytes() ([]byte, error) {
	data, err := json.Marshal(s)
	return append(data, '\n'), err
}

func Diff(base, current Snapshot) []Change {
	rows := []Change{}
	old := map[string]Tool{}
	for _, tool := range base.Tools {
		old[tool.Name] = tool
	}
	for _, tool := range current.Tools {
		fields := []string{}
		if previous, found := old[tool.Name]; !found {
			fields = append(fields, "added_to_view")
		} else {
			if previous.Input != tool.Input {
				fields = append(fields, "input_schema")
			}
			if previous.Output != tool.Output {
				fields = append(fields, "output_schema")
			}
			if previous.Metadata != tool.Metadata {
				fields = append(fields, "metadata")
			}
		}
		delete(old, tool.Name)
		if len(fields) > 0 {
			rows = append(rows, Change{tool.Name, fields})
		}
	}
	for name := range old {
		rows = append(rows, Change{name, []string{"removed_from_view"}})
	}
	slices.SortFunc(rows, func(a, b Change) int { return strings.Compare(a.Name, b.Name) })
	return rows
}
