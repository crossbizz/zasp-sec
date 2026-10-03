package apiserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestTemporaryPolicyModeArgumentsClosedBoundary(t *testing.T) {
	const target = "pid_81000001-0000-4000-8000-000000000001"
	const prefix = `{"target_id":"` + target + `","scope":"` + target + `","ttl_seconds":600,`
	for _, tc := range []struct {
		name, mode string
		valid      bool
	}{
		{"monitor", `"mode":"monitor"`, true}, {"block", `"mode":"block"`, true},
		{"null", `"mode":null`, false}, {"empty", `"mode":""`, false}, {"allow", `"mode":"allow"`, false},
		{"alias", `"Mode":"monitor"`, false}, {"duplicate", `"mode":"block","mode":"monitor"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSecurityAgentActionArguments("create_temporary_policy", json.RawMessage(prefix+tc.mode+`}`))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v got=%#v err=%v", tc.valid, got, err)
			}
		})
	}
	for _, ttl := range []string{"0", "59", "3601", "null"} {
		raw := strings.Replace(prefix+`"mode":"monitor"}`, `"ttl_seconds":600`, `"ttl_seconds":`+ttl, 1)
		if got, err := decodeSecurityAgentActionArguments("create_temporary_policy", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted ttl=%s: %#v", ttl, got)
		}
	}
}

func TestTemporaryPolicyModeDefinitionClosedBoundary(t *testing.T) {
	const base = `{"name":"Monitor","trigger_kind":"finding","trigger_source":"credential","environment_ids":["pid_81000001-0000-4000-8000-000000000001"],"autonomy":"supervised","max_steps":1,"max_duration_seconds":300,"temporary_policy_seconds":600,"ai_token_budget":1000,"concurrency_limit":1,"allowed_actions":["create_temporary_policy"],"verification_kind":"policy_state","definition_version":1,"enabled":false}`
	for _, mode := range []string{"monitor", "block"} {
		raw := strings.TrimSuffix(base, "}") + `,"temporary_policy_mode":"` + mode + `"}`
		if err := validateSecurityAgentDefinitionObject(json.RawMessage(raw)); err != nil {
			t.Fatalf("mode %s rejected: %v", mode, err)
		}
	}
	if err := validateSecurityAgentDefinitionObject(json.RawMessage(base)); err != nil {
		t.Fatalf("legacy absent-mode rejected: %v", err)
	}
	for _, mode := range []string{`null`, `""`, `"allow"`, `42`} {
		raw := strings.TrimSuffix(base, "}") + `,"temporary_policy_mode":` + mode + `}`
		if err := validateSecurityAgentDefinitionObject(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted mode=%s", mode)
		}
	}
	monitor := strings.TrimSuffix(base, "}") + `,"temporary_policy_mode":"monitor"}`
	for _, mutation := range [][2]string{
		{`"autonomy":"supervised"`, `"autonomy":"autonomous"`},
		{`"max_steps":1`, `"max_steps":2`},
		{`"allowed_actions":["create_temporary_policy"]`, `"allowed_actions":["create_temporary_policy","run_test"]`},
		{`"verification_kind":"policy_state"`, `"verification_kind":"test"`},
		{`"temporary_policy_seconds":600`, `"temporary_policy_seconds":0`},
	} {
		if err := validateSecurityAgentDefinitionObject(json.RawMessage(strings.Replace(monitor, mutation[0], mutation[1], 1))); err == nil {
			t.Fatalf("accepted Monitor mutation=%v", mutation)
		}
	}
}

func TestTemporaryPolicyModeApprovalTruthfulBoundIntent(t *testing.T) {
	approval, wire := approvalContextFixture("create_temporary_policy")
	approval.ExpectedEffect = "Apply temporary monitoring policy"
	wire["arguments"].(map[string]any)["mode"] = "monitor"
	raw, _ := json.Marshal(wire)
	got, err := decodeSecurityAgentApprovalContext(raw, approval)
	if err != nil || got == nil || got.Risk.Class != "containment" {
		t.Fatalf("Monitor approval projection=%#v err=%v", got, err)
	}
	approval.Context = got
	if !validSecurityAgentApproval(approval) {
		t.Fatal("typed Monitor operator approval refused")
	}
	wire["arguments"].(map[string]any)["mode"] = "block"
	raw, _ = json.Marshal(wire)
	if got, err := decodeSecurityAgentApprovalContext(raw, approval); err == nil || got != nil {
		t.Fatal("Monitor approval accepted Block parameters")
	}
}

// Draft persistence never implies admission to the legacy Block executor.
type temporaryModeAdmissionDatabase struct {
	JSONDatabase
	body  json.RawMessage
	calls int
}

func (d *temporaryModeAdmissionDatabase) QueryJSON(_ context.Context, statement string, _ ...any) (json.RawMessage, error) {
	d.calls++
	if statement != postgresSecurityAgentDefinitionValueSQL {
		return nil, errors.New("unexpected admission query")
	}
	return json.Marshal(WorkflowValue{Body: d.body, Version: 1})
}
func TestTemporaryPolicyModeUnadmittedWriteAndActivation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		body, _ := json.Marshal(map[string]any{"temporary_policy_mode": "monitor", "enabled": enabled})
		db := &temporaryModeAdmissionDatabase{}
		err := requireAutomaticDefinitionBody(context.Background(), db, body)
		if enabled && err == nil {
			t.Error("unadmitted enabled Monitor reached legacy write")
		}
		if !enabled && err != nil {
			t.Errorf("disabled Monitor draft refused: %v", err)
		}
		if db.calls != 0 {
			t.Error("source-only mode attempted database admission")
		}
	}
	id := "pid_81000001-0000-4000-8000-000000000001"
	body, _ := json.Marshal(map[string]any{"id": id, "temporary_policy_mode": "monitor", "enabled": false})
	db := &temporaryModeAdmissionDatabase{body: body}
	if err := requireAutomaticDefinitionActivation(context.Background(), db, fixtureRequestIdentity(t), id); err == nil {
		t.Error("unadmitted Monitor draft could activate legacy Block executor")
	}
	for _, body := range []json.RawMessage{json.RawMessage(`{"enabled":true}`), json.RawMessage(`{"temporary_policy_mode":"block","enabled":true}`)} {
		if err := requireAutomaticDefinitionBody(context.Background(), &temporaryModeAdmissionDatabase{}, body); err != nil {
			t.Errorf("legacy Block changed: %v", err)
		}
	}
}
