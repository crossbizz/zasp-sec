package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
)

type semanticTestDB struct {
	JSONDatabase
	calls int
	admit bool
	state string
}

func (d *semanticTestDB) QueryJSON(_ context.Context, query string, args ...any) (json.RawMessage, error) {
	d.calls++
	if query == semanticAdmitSQL {
		if d.admit {
			return json.RawMessage(`{"lease":"76000001-0000-4000-8000-000000000001"}`), nil
		}
		return json.RawMessage("null"), nil
	}
	if query == semanticFinishSQL {
		return json.Marshal(map[string]string{"state": d.state})
	}
	return nil, errors.New("unexpected query")
}

type semanticTestDriver struct {
	calls int
	fail  bool
}

func (d *semanticTestDriver) Evaluate(_ context.Context, _ aigateway.Purpose, input json.RawMessage) (json.RawMessage, error) {
	d.calls++
	if d.fail || !strings.Contains(string(input), `"snippet"`) {
		return nil, errors.New("unavailable")
	}
	return json.RawMessage(`{"verdict":"benign_context","reason_code":"example","confidence":1}`), nil
}

func TestGuardrailOptionalEvaluationCannotOverrideHardRule(t *testing.T) {
	text := "Example documentation"
	for _, scenario := range []struct {
		name, rule, consent, state string
		admit, fail                bool
		dbCalls, driverCalls       int
		decision                   string
	}{
		{"default", guardrail.RuleToolCall, "", "", true, false, 0, 0, "block"},
		{"hard", guardrail.RuleCreditCard, "approved_code_snippet", "", true, false, 0, 0, "block"},
		{"unqualified", guardrail.RuleToolCall, "approved_code_snippet", "", false, false, 1, 0, "block"},
		{"shadow", guardrail.RuleToolCall, "approved_code_snippet", "shadow", true, false, 2, 1, "block"},
		{"active", guardrail.RuleToolCall, "approved_code_snippet", "suppressed_benign", true, false, 2, 1, "allow"},
		{"outage", guardrail.RuleToolCall, "approved_code_snippet", "coverage_degraded", true, true, 2, 1, "block"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			db := &semanticTestDB{admit: scenario.admit, state: scenario.state}
			driver := &semanticTestDriver{fail: scenario.fail}
			h := guardrailHTTPHandler{database: db, profiles: guardrailProfiles{aigateway.PurposeHeuristicVerify: {driver: driver}}}
			d := GuardrailDecision{Decision: "block", MatchedRules: []GuardrailMatchedRule{{ID: scenario.rule}}}
			h.evaluateSnippet(t.Context(), RequestIdentity{}, guardrailDecisionInput{ContentMode: scenario.consent, Text: &text}, &d)
			if d.Decision != scenario.decision || db.calls != scenario.dbCalls || driver.calls != scenario.driverCalls {
				t.Fatal(d, db.calls, driver.calls)
			}
		})
	}
}
