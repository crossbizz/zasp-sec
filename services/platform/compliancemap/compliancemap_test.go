package compliancemap

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestEveryRuleMapsToKnownControlsOfAtLeastTwoFrameworks(t *testing.T) {
	for _, rule := range Rules() {
		references := References(rule)
		frameworks := map[string]bool{}
		seen := map[string]bool{}
		for _, reference := range references {
			if reference.Framework == "" || reference.Control == "" || reference.Title == "" || len(reference.Title) > 128 {
				t.Errorf("%s: a control key is not in the catalog: %+v", rule, reference)
			}
			if seen[reference.Framework+reference.Control] {
				t.Errorf("%s: duplicate %s %s", rule, reference.Framework, reference.Control)
			}
			seen[reference.Framework+reference.Control] = true
			frameworks[reference.Framework] = true
		}
		if len(frameworks) < 2 {
			t.Errorf("%s maps to %d framework(s)", rule, len(frameworks))
		}
	}
	if got := References("not_a_rule"); got == nil || len(got) != 0 {
		t.Fatalf("an unmapped rule = %v", got)
	}
}

// Every posture rule the database raises and every agent check the AWS
// collector raises has a mapping; a new rule without one fails here.
func TestEveryPostureRuleAndAgentCheckIsMapped(t *testing.T) {
	mapped := map[string]bool{}
	for _, rule := range Rules() {
		mapped[rule] = true
	}
	migration, err := os.ReadFile("../migrations/sql/0014_typed_inventory_cutover.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	posture := regexp.MustCompile(`\('([a-z_]+)','[^']+',agent\.state=`).FindAllStringSubmatch(string(migration), -1)
	if len(posture) != 12 {
		t.Fatalf("found %d posture rules in the migration", len(posture))
	}
	for _, match := range posture {
		if !mapped[match[1]] {
			t.Errorf("posture rule %s has no framework mapping", match[1])
		}
	}
	collector, err := os.ReadFile("../connectors/awsdiscovery/inventory_agents.go")
	if err != nil {
		t.Fatal(err)
	}
	checks := regexp.MustCompile(`AgentCheck[A-Za-z]+\s+= "([a-z0-9_]+)"`).FindAllStringSubmatch(string(collector), -1)
	if len(checks) != 3 {
		t.Fatalf("found %d agent checks in the collector", len(checks))
	}
	for _, match := range checks {
		if !mapped[match[1]] {
			t.Errorf("agent check %s has no framework mapping", match[1])
		}
	}
	if !strings.HasPrefix(References("ownerless_agent")[0].Framework, "owasp_agentic") {
		t.Fatal("references are not ordered by framework")
	}
}
