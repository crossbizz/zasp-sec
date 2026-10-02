package migrations

import (
	"regexp"
	"strings"
	"testing"
)

// A whole-row SQL alias cannot reuse a PL/pgSQL row variable: passing it to
// the typed serializer is ambiguous even when its field references are clear.
// This source guard supplements the actual application.read native regression.
func TestOrdered68WholeRowAliases(t *testing.T) {
	source, _ := authorizationWorkerProfileSource()
	headers := regexp.MustCompile(`CREATE FUNCTION zasp_authorization80_worker\.(ordered68_[a-z_]+)\([^;]+? AS \$([a-z_]+)\$`).FindAllStringSubmatchIndex(source, -1)
	declarations := regexp.MustCompile(`(?:DECLARE|;)\s*([a-z_]+)\s+[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*%ROWTYPE`)
	aliases := regexp.MustCompile(`\b(?:FROM|JOIN)\s+[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*\s+(?:AS\s+)?([a-z_]+)\b`)
	checked := 0
	for _, header := range headers {
		name, tag := source[header[2]:header[3]], source[header[4]:header[5]]
		body := strings.SplitN(source[header[1]:], "$"+tag+"$;", 2)[0]
		parts := strings.SplitN(body, "BEGIN", 2)
		if len(parts) != 2 {
			continue
		}
		rows := map[string]bool{}
		for _, match := range declarations.FindAllStringSubmatch(parts[0], -1) {
			rows[match[1]] = true
		}
		if len(rows) == 0 {
			continue
		}
		checked++
		for _, match := range aliases.FindAllStringSubmatch(parts[1], -1) {
			if rows[match[1]] {
				t.Errorf("%s SQL alias %s conflicts with a PL/pgSQL row variable", name, match[1])
			}
		}
	}
	if checked < 5 {
		t.Fatalf("expected connected row-bearing sources, checked %d", checked)
	}
}
