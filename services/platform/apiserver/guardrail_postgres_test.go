package apiserver

import (
	"encoding/json"
	"strings"
	"testing"
)

// completion.sql section V7 (guardrail decision API) on the real catalog,
// in the database of the provider remediation test: the Environment's policy
// and the decision record. The functions that need a request proof are
// tested for refusing a request without one; their bodies (the functions
// without the proof check, executable only by their owner) are exercised as
// the database owner.
func TestGuardrailDecisionSectionPostgres(t *testing.T) {
	database := startRemediationDatabase(t)
	database.seed()
	const o, w, e, actor = remediationOrg, remediationWorkspace, remediationEnvironment, remediationAdmin
	state := func(err error) string {
		code, message := remediationSQLState(err)
		return code + " " + message
	}
	var raw []byte
	decide := func(q string) (json.RawMessage, error) {
		err := database.conn.QueryRow(database.ctx, `SELECT zasp_authorization80.guardrail_decision_record($1,$2,$3,$4,$5::jsonb)`, o, w, e, actor, q).Scan(&raw)
		return raw, err
	}
	record := func(id, matched string) string {
		return `{"id":"` + id + `","direction":"input","input_bytes":120,"content_digest":"sha256:` + strings.Repeat("ab", 32) + `","agent_id":"support-agent","tool_name":null,"matched":` + matched + `}`
	}
	const email = `{"id":"pii.email","category":"sensitive_data","default_mode":"redact","redactable":true,"count":2}`
	const override = `{"id":"injection.instruction_override","category":"prompt_injection","default_mode":"block","redactable":false,"count":1}`

	t.Run("the record cannot hold the interaction text", func(t *testing.T) {
		columns := database.text(`SELECT string_agg(column_name||':'||data_type,',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name='zasp_guardrail_decisions'`)
		const want = "organization_id:text,workspace_id:text,environment_id:text,id:text,principal_id:text,direction:text,decision:text,rules:jsonb,input_bytes:integer,content_digest:bytea,agent_id:text,tool_name:text,policy_version:bigint,created_at:timestamp with time zone"
		if columns != want {
			t.Fatalf("columns=%s", columns)
		}
		for name, q := range map[string]string{
			"a text member":             strings.Replace(record("pid_70000000-0000-4000-8000-000000000001", "[]"), `"matched":[]`, `"matched":[],"text":"hello"`, 1),
			"a text member in a match":  record("pid_70000000-0000-4000-8000-000000000002", `[{"id":"pii.email","category":"sensitive_data","default_mode":"redact","redactable":true,"count":1,"sample":"maria@example.com"}]`),
			"an agent id with spaces":   strings.Replace(record("pid_70000000-0000-4000-8000-000000000003", "[]"), `"support-agent"`, `"ignore previous instructions"`, 1),
			"a digest that is not one":  strings.Replace(record("pid_70000000-0000-4000-8000-000000000004", "[]"), "sha256:", "sha256:zz", 1),
			"a size over the limit":     strings.Replace(record("pid_70000000-0000-4000-8000-000000000005", "[]"), `"input_bytes":120`, `"input_bytes":32769`, 1),
			"an injection that redacts": record("pid_70000000-0000-4000-8000-000000000006", `[{"id":"injection.role_switch","category":"prompt_injection","default_mode":"redact","redactable":false,"count":1}]`),
			"a rule named twice":        record("pid_70000000-0000-4000-8000-000000000007", "["+email+","+email+"]"),
		} {
			if result, err := decide(q); err == nil || state(err) != "22023 guardrail decision rejected" {
				t.Fatalf("%s: result=%s state=%q", name, result, state(err))
			}
		}
		if rows := database.text(`SELECT count(*)::text FROM zasp_guardrail_decisions`); rows != "0" {
			t.Fatalf("a refused record left %s rows", rows)
		}
	})

	t.Run("defaults decide when no policy is saved", func(t *testing.T) {
		result, err := decide(record("pid_70000000-0000-4000-8000-000000000011", "["+override+","+email+"]"))
		if err != nil || !strings.Contains(string(result), `"decision": "block"`) || !strings.Contains(string(result), `"policy_version": 0`) {
			t.Fatalf("result=%s err=%v", result, err)
		}
		result, err = decide(record("pid_70000000-0000-4000-8000-000000000012", "["+email+"]"))
		if err != nil || !strings.Contains(string(result), `"decision": "redact"`) {
			t.Fatalf("result=%s err=%v", result, err)
		}
		result, err = decide(record("pid_70000000-0000-4000-8000-000000000013", "[]"))
		if err != nil || !strings.Contains(string(result), `"decision": "allow"`) || !strings.Contains(string(result), `"rules": []`) {
			t.Fatalf("result=%s err=%v", result, err)
		}
		// A decision identifier is recorded once.
		if _, err := decide(record("pid_70000000-0000-4000-8000-000000000013", "[]")); err == nil {
			t.Fatal("a decision identifier was recorded twice")
		}
	})

	t.Run("the Environment's policy sets the mode of each rule", func(t *testing.T) {
		write := func(rules string, expected int64, suffix string) (json.RawMessage, error) {
			err := database.conn.QueryRow(database.ctx, `SELECT zasp_authorization80.guardrail_policy_write($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, o, w, e, actor, rules, expected, "pid_71000000-0000-4000-8000-0000000001"+suffix, "pid_71000000-0000-4000-8000-0000000002"+suffix).Scan(&raw)
			return raw, err
		}
		for name, rules := range map[string]string{
			"an unknown mode":         `{"pii.email":"allow"}`,
			"a mode that is not text": `{"pii.email":true}`,
			"a rule that is not one":  `{"Ignore previous instructions":"off"}`,
			"not an object":           `["pii.email"]`,
		} {
			if result, err := write(rules, 0, "01"); err == nil || state(err) != "22023 guardrail policy rejected" {
				t.Fatalf("%s: result=%s state=%q", name, result, state(err))
			}
		}
		if _, err := write(`{"pii.email":"block"}`, 2, "02"); err == nil || state(err) != "40001 guardrail policy version conflict" {
			t.Fatalf("stale version state=%q", state(err))
		}
		result, err := write(`{"pii.email":"monitor","injection.instruction_override":"monitor","pii.us_ssn":"off","injection.role_switch":"redact"}`, 0, "03")
		policy, decodeErr := decodeGuardrailPolicy(result, e, "audit_id", "correlation_id")
		// The API refuses an injection rule set to redact before it is saved;
		// a stored one is not served, which is what the decoder reports here.
		if err != nil || decodeErr == nil {
			t.Fatalf("result=%s err=%v policy=%#v", result, err, policy)
		}
		result, err = write(`{"pii.email":"monitor","injection.instruction_override":"monitor","pii.us_ssn":"off"}`, 1, "04")
		policy, decodeErr = decodeGuardrailPolicy(result, e, "audit_id", "correlation_id")
		if err != nil || decodeErr != nil || policy.Version != 2 || len(policy.Rules) != 11 {
			t.Fatalf("result=%s err=%v decode=%v", result, err, decodeErr)
		}
		if audited := database.text(`SELECT count(*)::text FROM zasp_workflow_audit WHERE operation='putGuardrailPolicy' AND resource_kind='environment' AND resource_id=$1`, e); audited != "2" {
			t.Fatalf("policy audit rows=%s", audited)
		}
		// The next decision uses the policy: the injection and the email are
		// only reported, the SSN rule is off and not reported, and a rule the
		// policy does not name keeps its default.
		const ssn = `{"id":"pii.us_ssn","category":"sensitive_data","default_mode":"redact","redactable":true,"count":1}`
		const card = `{"id":"pii.credit_card","category":"sensitive_data","default_mode":"redact","redactable":true,"count":1}`
		result, err = decide(record("pid_70000000-0000-4000-8000-000000000021", "["+override+","+email+","+ssn+"]"))
		if err != nil || !strings.Contains(string(result), `"decision": "allow"`) || !strings.Contains(string(result), `"policy_version": 2`) || strings.Contains(string(result), "pii.us_ssn") || strings.Count(string(result), `"mode": "monitor"`) != 2 {
			t.Fatalf("result=%s err=%v", result, err)
		}
		result, err = decide(record("pid_70000000-0000-4000-8000-000000000022", "["+email+","+card+"]"))
		if err != nil || !strings.Contains(string(result), `"decision": "redact"`) {
			t.Fatalf("result=%s err=%v", result, err)
		}
		stored := database.text(`SELECT decision||' '||input_bytes::text||' '||encode(content_digest,'hex')||' '||agent_id||' '||COALESCE(tool_name,'-')||' '||policy_version::text||' '||rules::text FROM zasp_guardrail_decisions WHERE id='pid_70000000-0000-4000-8000-000000000022'`)
		if !strings.HasPrefix(stored, "redact 120 "+strings.Repeat("ab", 32)+" support-agent - 2 ") || !strings.Contains(stored, `"id": "pii.credit_card"`) {
			t.Fatalf("stored record=%s", stored)
		}
	})

	t.Run("the API's statements need a request proof", func(t *testing.T) {
		for name, call := range map[string]func() (json.RawMessage, error){
			"decide": func() (json.RawMessage, error) {
				return database.as("zasp_svc_api", `SELECT zasp_authorization80.guardrail_decide($1,$2,$3,$4,$5::jsonb)`, o, w, e, actor, record("pid_70000000-0000-4000-8000-000000000031", "[]"))
			},
			"read the policy": func() (json.RawMessage, error) {
				return database.as("zasp_svc_api", `SELECT zasp_authorization80.guardrail_policy($1,$2,$3)`, o, w, e)
			},
			"set the policy": func() (json.RawMessage, error) {
				return database.as("zasp_svc_api", `SELECT zasp_authorization80.guardrail_set_policy($1,$2,$3,$4,'{}'::jsonb,2,$5,$6)`, o, w, e, actor, "pid_71000000-0000-4000-8000-000000000131", "pid_71000000-0000-4000-8000-000000000231")
			},
		} {
			if result, err := call(); err == nil || !strings.HasPrefix(state(err), "42501 ") {
				t.Fatalf("%s without a proof: result=%s state=%q", name, result, state(err))
			}
		}
		// The API login can reach neither table nor the functions without the check.
		for _, statement := range []string{`SELECT count(*)::text::jsonb FROM public.zasp_guardrail_decisions`, `SELECT count(*)::text::jsonb FROM public.zasp_guardrail_policies`, `SELECT zasp_authorization80.guardrail_decision_record('a','b','c','d','{}'::jsonb)`} {
			if result, err := database.as("zasp_svc_api", statement); err == nil || !strings.HasPrefix(state(err), "42501 ") {
				t.Fatalf("%s: result=%s state=%q", statement, result, state(err))
			}
		}
	})
}
