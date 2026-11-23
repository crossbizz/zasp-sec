package mcpschema

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

var testScope = Scope{"pid_10000000-0000-4000-8000-000000000001", "pid_20000000-0000-4000-8000-000000000001", "pilot-monitor"}

func pair(cursor, next string, tools ...string) string {
	input := ""
	if cursor != "" {
		input = `,"params":{"cursor":` + strconv.Quote(cursor) + "}"
	}
	continuation := ""
	if next != "" {
		continuation = `,"nextCursor":` + strconv.Quote(next)
	}
	return `{"request":{"jsonrpc":"2.0","id":1,"method":"tools/list"` + input + `},"response":{"jsonrpc":"2.0","id":1,"result":{"tools":[` + strings.Join(tools, ",") + "]" + continuation + "}}}"
}

func tool(name, fields string) string {
	return `{"name":` + strconv.Quote(name) + `,"inputSchema":{"type":"object"}` + fields + "}"
}

func TestStablePrivateSnapshotAndBoundComparison(t *testing.T) {
	private := `,"description":"private supplier text","annotations":{"readOnlyHint":true}`
	first := pair("", "secret-cursor", tool("alpha", private)) + pair("secret-cursor", "", tool("beta", ""))
	base, err := Capture(testScope, strings.NewReader(first))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := base.Bytes()
	if strings.Contains(string(text), "private supplier") || strings.Contains(string(text), "secret-cursor") || strings.Contains(string(text), "readOnlyHint") {
		t.Fatal("private values escaped from snapshot")
	}
	second := pair("", "", tool("beta", ""), `{"annotations":{"readOnlyHint":true},"description":"private supplier text","inputSchema":{"type":"object"},"name":"alpha"}`)
	reordered, err := Capture(testScope, strings.NewReader(second))
	if err != nil {
		t.Fatal(err)
	}
	newText, _ := reordered.Bytes()
	if string(text) != string(newText) {
		t.Fatal("page boundaries, object order or listing order changed identity")
	}
	parsed, err := Load(strings.NewReader(string(text)), Digest(text), testScope)
	if err != nil {
		t.Fatal(err)
	}
	changed := pair("", "", `{"name":"alpha","inputSchema":{"type":"object","properties":{"part":{"type":"integer"}}},"outputSchema":{"type":"object"},"description":"Reworded"}`, tool("gamma", ""))
	next, err := Capture(testScope, strings.NewReader(changed))
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := json.Marshal(Diff(parsed, next))
	want := `[{"tool":"alpha","changes":["input_schema","output_schema","metadata"]},{"tool":"beta","changes":["removed_from_view"]},{"tool":"gamma","changes":["added_to_view"]}]`
	if string(rows) != want {
		t.Fatalf("comparison = %s", rows)
	}
	wrong := testScope
	wrong.View = "external"
	for _, check := range []struct {
		data, hash string
		scope      Scope
	}{
		{string(text), Digest([]byte("else")), testScope}, {string(text), Digest(text), wrong}, {string(append(text, ' ')), Digest(append(text, ' ')), testScope},
	} {
		if _, err := Load(strings.NewReader(check.data), check.hash, check.scope); err == nil {
			t.Fatal("accepted an invalid baseline")
		}
	}
}

func TestRejectsUntrustworthyCoverageAndUnboundedInputs(t *testing.T) {
	entry := tool("a", "")
	one := pair("", "", entry)
	large := make([]string, maxTools+1)
	for i := range large {
		large[i] = tool("t"+strconv.Itoa(i), "")
	}
	deep := strings.Repeat("[", 45) + "null" + strings.Repeat("]", 45)
	missingSchema := `{"name":"schema-less"}`
	cases := map[string]string{
		"missing first page": pair("cursor", "", entry), "missing last page": pair("", "cursor", entry),
		"different cursor": pair("", "cursor", entry) + pair("different", "", tool("b", "")),
		"repeated cursor":  pair("", "cursor", entry) + pair("cursor", "cursor", tool("b", "")),
		"trailing page":    one + one, "duplicate tool": pair("", "", entry, entry),
		"RPC error":               strings.Replace(one, `"result":`, `"error":`, 1),
		"unexpected method":       strings.Replace(one, "tools/list", "tools/call", 1),
		"unbound response":        strings.Replace(one, `"id":1,"result"`, `"id":"1","result"`, 1),
		"duplicate JSON property": strings.Replace(one, `"type":"object"`, `"type":"array","type":"object"`, 1),
		"missing schema":          pair("", "", missingSchema), "unknown selection": strings.Replace(one, `"method":"tools/list"`, `"method":"tools/list","params":{"filter":"partial"}`, 1),
		"too many tools": pair("", "", large...), "too many bytes": strings.Repeat(" ", limitBytes+1),
		"nesting budget": strings.Replace(one, `"type":"object"`, `"type":"object","extra":`+deep, 1),
		"no input":       "", "unknown JSON": `{"request":{},"response":{}}`,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Capture(testScope, strings.NewReader(data)); err == nil {
				t.Fatal("incomplete list accepted")
			}
		})
	}
}
