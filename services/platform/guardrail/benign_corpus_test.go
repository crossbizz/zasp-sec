package guardrail

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
)

// Each observation must reproduce its single heuristic match. A benign-only
// regression set cannot by itself qualify a deployment for active suppression.
func TestBenignQualificationCorpus(t *testing.T) {
	f, err := os.Open("../../../testdata/v3/benign-heuristic-matches.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	counts := map[string]int{}
	seen := map[string]bool{}
	for scanner.Scan() {
		var row struct {
			Input struct {
				Rule    string `json:"rule_id"`
				Snippet string `json:"snippet"`
			} `json:"input"`
			Positive *bool `json:"positive"`
		}
		if json.Unmarshal(scanner.Bytes(), &row) != nil || row.Positive == nil || *row.Positive || seen[row.Input.Snippet] {
			t.Fatal("invalid fixture", len(seen)+1)
		}
		rule, ok := RuleByID(row.Input.Rule)
		if !ok || rule.Class != RuleHeuristic {
			t.Fatal(row.Input.Rule)
		}
		matches, valid := Detect(row.Input.Snippet, DirectionInput)
		if !valid || len(matches) == 0 {
			t.Fatalf("missing match on line %d", len(seen)+1)
		}
		for _, m := range matches {
			if m.RuleID != row.Input.Rule {
				t.Fatalf("line %d matched %s", len(seen)+1, m.RuleID)
			}
		}
		seen[row.Input.Snippet] = true
		counts[row.Input.Rule]++
	}
	if scanner.Err() != nil || len(seen) < 60 || len(counts) != 4 {
		t.Fatal("incomplete corpus", counts)
	}
	for _, n := range counts {
		if n < 15 {
			t.Fatal("insufficient rule coverage", counts)
		}
	}
}
