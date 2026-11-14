package compliancemap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// completionSQLData renders the two SQL functions of the AI framework section
// of completion.sql from the Go map, exactly as the section must hold them.
func completionSQLData() string {
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	var text strings.Builder
	text.WriteString("CREATE OR REPLACE FUNCTION public.zasp_compliance_ai_controls() RETURNS TABLE(framework text,control_id text,label text) LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $ai_controls$\n SELECT c.framework,c.control_id,c.label FROM (VALUES\n")
	for index, control := range Controls() {
		if index > 0 {
			text.WriteString(",\n")
		}
		text.WriteString("  (" + quote(control.Framework) + "," + quote(control.Control) + "," + quote(control.Title) + ")")
	}
	text.WriteString(") c(framework,control_id,label)\n$ai_controls$;\n")
	text.WriteString("CREATE OR REPLACE FUNCTION public.zasp_compliance_ai_rule_controls() RETURNS TABLE(rule text,framework text,control_id text) LANGUAGE sql IMMUTABLE SET search_path TO pg_catalog,public AS $ai_rule_controls$\n SELECT r.rule,r.framework,r.control_id FROM (VALUES\n")
	for index, mapping := range Mappings() {
		if index > 0 {
			text.WriteString(",\n")
		}
		text.WriteString("  (" + quote(mapping.Rule) + "," + quote(mapping.Framework) + "," + quote(mapping.Control) + ")")
	}
	text.WriteString(") r(rule,framework,control_id)\n$ai_rule_controls$;\n")
	return text.String()
}

// The compliance reads decide in SQL which findings are evidence for which
// control, and the finding detail decides it in Go. Both must hold the same
// data: completion.sql must contain exactly what the Go map renders to.
// Set ZASP_WRITE_COMPLIANCE_SQL to a file path to write the expected text.
func TestCompletionSQLHoldsTheGoMapping(t *testing.T) {
	completion, err := os.ReadFile(filepath.Join("..", "migrations", "baseline", "completion.sql"))
	if err != nil {
		t.Fatal(err)
	}
	want := completionSQLData()
	if path := os.Getenv("ZASP_WRITE_COMPLIANCE_SQL"); path != "" {
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(string(completion), want) {
		t.Fatalf("completion.sql does not hold the rule to control mapping of compliancemap; it must contain exactly:\n%s", want)
	}
}

func TestAccessorsCoverEveryControlAndRule(t *testing.T) {
	listed := Controls()
	if len(listed) != len(controls) {
		t.Fatalf("Controls() = %d, want %d", len(listed), len(controls))
	}
	seen := map[string]bool{}
	for index, control := range listed {
		if seen[control.Control] || !IsFramework(control.Framework) || FrameworkName(control.Framework) == "" {
			t.Fatalf("control %#v is repeated or of an unknown framework", control)
		}
		seen[control.Control] = true
		if found, ok := Control(control.Control); !ok || found != control {
			t.Fatalf("Control(%q) = %#v, %v", control.Control, found, ok)
		}
		if index > 0 && listed[index-1].Framework+"\x00"+listed[index-1].Control >= control.Framework+"\x00"+control.Control {
			t.Fatalf("controls are not in byte order at %d", index)
		}
	}
	total := 0
	for _, rule := range Rules() {
		total += len(References(rule))
	}
	if mappings := Mappings(); len(mappings) != total {
		t.Fatalf("Mappings() = %d, want %d", len(mappings), total)
	}
	if _, ok := Control("soc2_security-audit"); ok || IsFramework("hipaa") || FrameworkName("hipaa") != "" {
		t.Fatal("a product evidence framework was taken for an AI framework")
	}
}
