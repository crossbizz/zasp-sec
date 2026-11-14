package evidencepack_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/evidencepack"
	"github.com/zasp-ai/zasp-sec/services/platform/evidencepack/evidencepacktest"
)

func TestDecodeBindsEveryRecordToThePack(t *testing.T) {
	raw := string(evidencepacktest.Pack())
	pack, err := evidencepack.Decode(json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	if pack.Agent.Summary.ID != evidencepacktest.Agent || len(pack.Findings) != 1 || len(pack.Runs) != 1 || len(pack.Runs[0].Approvals) != 1 || pack.RunsStatus != "partial" || len(pack.RedTeamTests) != 1 || len(pack.RedTeamRuns) != 1 {
		t.Fatalf("pack = %#v", pack)
	}
	for name, changed := range map[string]string{
		"another schema version":           strings.Replace(raw, `"agent-evidence-pack-v1"`, `"agent-evidence-pack-v2"`, 1),
		"an object that is not an agent":   strings.Replace(raw, `"kind":"agent"`, `"kind":"identity"`, 1),
		"a run of a finding not in it":     strings.Replace(raw, `"finding_id":"`+evidencepacktest.Finding, `"finding_id":"`+evidencepacktest.Run, 1),
		"a test run of a test not in it":   strings.Replace(raw, `"definition_id":"`+evidencepacktest.Test, `"definition_id":"`+evidencepacktest.Run, 1),
		"runs claimed complete":            strings.Replace(raw, `"security_agent_runs":{"status":"partial"`, `"security_agent_runs":{"status":"complete"`, 1),
		"an unknown section status":        strings.Replace(raw, `"findings":{"status":"complete"`, `"findings":{"status":"not_permitted"`, 1),
		"an unknown member of a finding":   strings.Replace(raw, `"severity":"high"`, `"severity":"high","prompt":"secret"`, 1),
		"an unknown member of the pack":    strings.Replace(raw, `{"schema_version"`, `{"signature":"none","schema_version"`, 1),
		"a missing section":                strings.Replace(raw, `"red_team_tests":{"status":"complete","items":[`, `"red_team_checks":{"status":"complete","items":[`, 1),
		"a finding without a title":        strings.Replace(raw, `"title":"=Agent has no owner | review"`, `"title":""`, 1),
		"a malformed time":                 strings.Replace(raw, `"decided_at":"2026-11-02T00:30:00.000000Z"`, `"decided_at":"yesterday"`, 1),
		"a repeated finding":               strings.Replace(raw, `"findings":{"status":"complete","items":[`, `"findings":{"status":"complete","items":[`+findingJSON(raw)+`,`, 1),
		"an agent without source evidence": strings.Replace(raw, `"sources":[{`, `"sources":[],"unused":[{`, 1),
	} {
		if changed == raw {
			t.Fatalf("%s: the fixture did not change", name)
		}
		if _, err := evidencepack.Decode(json.RawMessage(changed)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func findingJSON(raw string) string {
	start := strings.Index(raw, `{"id":"`+evidencepacktest.Finding)
	end := strings.Index(raw[start:], `}]}]}`)
	return raw[start : start+end+3]
}

func TestRenderings(t *testing.T) {
	pack, err := evidencepack.Decode(evidencepacktest.Pack())
	if err != nil {
		t.Fatal(err)
	}
	markdown := evidencepack.Markdown(pack, "org", "workspace", "environment", time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC))
	for _, want := range []string{
		"# Agent evidence pack: Support &lt;agent&gt;", "- Captured: 2026-11-14T09:00:00Z", "(retained export)", "`invoke:bedrock_model`", "Activity: active, last activity 2026-11-09T00:00:00Z",
		"### =Agent has no owner \\| review", "owasp\\_agentic\\_top10\\_2026 ASI10: Rogue Agents",
		"Runs owned by the Temporal executor are not in a retained pack", "### Run `" + evidencepacktest.Run + "`", "Step 1: update\\_finding\\_response, authorization approval\\_required, state succeeded",
		"decided by `" + evidencepacktest.Approver + "` at 2026-11-02T00:30:00.000000Z",
		"| `" + evidencepacktest.Test + "` | Prompt injection sweep | agent\\_endpoint | prompt\\_injection, tool\\_abuse |",
		"| `" + evidencepacktest.TestRun + "` | Prompt injection sweep | complete | fail | 2026-11-05T00:10:00.000000Z |",
	} {
		if !strings.Contains(markdown, want) {
			t.Errorf("the rendering lacks %q:\n%s", want, markdown)
		}
	}
	if strings.Contains(markdown, "<agent>") {
		t.Fatal("the rendering holds raw markup")
	}
	records, err := evidencepack.CSV(pack)
	if err != nil {
		t.Fatal(err)
	}
	// A title a spreadsheet would evaluate is neutralized.
	for _, want := range []string{"record,id,related_id,name,state,detail,at", "agent," + evidencepacktest.Agent, `finding,` + evidencepacktest.Finding + `,` + evidencepacktest.Agent + `,'=Agent has no owner | review,open,high ownerless_agent [owasp_agentic_top10_2026 ASI10]`, "security_agent_run," + evidencepacktest.Run + "," + evidencepacktest.Finding, "approval,pid_42000001-0000-4000-8000-000000000001," + evidencepacktest.Run + "," + evidencepacktest.Approver + ",approved", "red_team_test," + evidencepacktest.Test, "red_team_run," + evidencepacktest.TestRun + "," + evidencepacktest.Test + ",,complete,fail"} {
		if !strings.Contains(string(records), want) {
			t.Errorf("the CSV lacks %q:\n%s", want, records)
		}
	}
}
