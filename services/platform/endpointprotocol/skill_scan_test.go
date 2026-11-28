package endpointprotocol

import (
	"strings"
	"testing"
)

func TestSkillInventoryRequiresBoundedCatalogCountsAndEvidence(t *testing.T) {
	const ruleset = "zasp-static.v2"
	complete := true
	snapshot := Inventory{Partition: strings.Repeat("a", 64), Generation: 1, Complete: &complete}
	for _, test := range []struct {
		digest bool
		scan   *SkillScan
		valid  bool
	}{
		{true, nil, true}, // device reporting original inventory protocol
		{true, &SkillScan{ruleset, map[string]int{}, 0}, true},
		{false, &SkillScan{ruleset, map[string]int{"instruction.override": 1}, 2}, true},
		{true, &SkillScan{ruleset, map[string]int{"employee-path": 1}, 0}, false},
		{true, &SkillScan{ruleset, map[string]int{"script.network_access": 1025}, 0}, false},
		{false, &SkillScan{ruleset, map[string]int{}, 0}, false},
		{true, &SkillScan{ruleset, map[string]int{}, 1}, false},
	} {
		item := Installation{ID: strings.Repeat("b", 64), SkillScan: test.scan}
		if test.digest {
			item.Digest = "sha256:" + strings.Repeat("c", 64)
		}
		snapshot.Items = []Installation{item}
		if snapshot.Valid() != test.valid {
			t.Fatalf("unexpected validity for %+v", test)
		}
	}
}

func TestSkillScanRequiresExplicitCoverage(t *testing.T) {
	for _, field := range []string{`null`, `{"ruleset":"zasp-static.v2","rule_counts":{}}`, `{"ruleset":"zasp-static.v2","rule_counts":{},"skipped_count":null}`, `{"ruleset":"zasp-static.v2","rule_counts":{},"skipped_count":0,"contents":"unexpected"}`} {
		var value Installation
		if Strict([]byte(`{"installation_id":"`+strings.Repeat("a", 64)+`","skill_scan":`+field+`}`), &value) {
			t.Fatal("accepted malformed scan", field)
		}
	}
}
