package apiserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

func orderedTestEvidenceRefusals(t *testing.T, ctx context.Context, owner, worker *pgx.Conn, store *artifactstore.Store, o, w, e, r, s, child string, input, output RedTeamArtifactReference) {
	t.Helper()
	scope, _ := orderedTestScope(o, w, e, r, s)
	inputID, _ := CanonicalDiscoveryID(scope, "security_agent_ordered_test_input", r+"\x1f"+s)
	inputBody, err := orderedTestReadArtifact(ctx, store, scope, inputID, input, 65536)
	if err != nil {
		t.Fatal(err)
	}
	body, err := orderedTestReadArtifact(ctx, store, scope, child, output, 1048576)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"engine", "engine_version", "runner", "pack", "check", "prompt_digest", "assertion_digest", "credential_version", "comparison", "response_digest", "category", "native_prompt", "native_assertion", "redaction", "extra", "duplicate", "engine_error", "output_scope", "input_content", "input_version", "oversize", "oversize_input", "wrong_token", "stale_run", "stale_effect", "wrong_step"} {
		t.Run(mode, func(t *testing.T) {
			candidate := bytes.Clone(body)
			in := input
			out := output
			inBody := bytes.Clone(inputBody)
			step := s
			token := strings.Repeat("a", 32)
			rv, fv := 9, 1
			switch mode {
			case "engine":
				candidate = bytes.ReplaceAll(candidate, []byte(`"engine":"promptfoo"`), []byte(`"engine":"other"`))
			case "engine_version":
				candidate = bytes.ReplaceAll(candidate, []byte(`"engine_version":"0.121.19"`), []byte(`"engine_version":"0.121.18"`))
			case "runner":
				candidate = bytes.ReplaceAll(candidate, []byte(`sha256:`+strings.Repeat("a", 64)), []byte(`sha256:`+strings.Repeat("b", 64)))
			case "pack":
				candidate = bytes.ReplaceAll(candidate, []byte("zasp-curated-red-team-v1"), []byte("zasp-curated-red-team-v2"))
			case "check":
				candidate = bytes.ReplaceAll(candidate, []byte("zasp.curated.prompt_injection.v1"), []byte("zasp.curated.prompt_injection.v2"))
			case "prompt_digest", "assertion_digest", "credential_version", "response_digest":
				field := mode
				if mode == "credential_version" {
					field = "credential_version_digest"
				}
				candidate = []byte(replaceOrderedEvidenceField(t, string(candidate), field, strings.Repeat("f", 64)))
			case "comparison":
				candidate = []byte(replaceOrderedEvidenceField(t, string(candidate), "safety_digest", strings.Repeat("f", 64)))
			case "category":
				candidate = bytes.ReplaceAll(candidate, []byte(`"category":"prompt_injection"`), []byte(`"category":"tool_abuse"`))
			case "native_prompt":
				candidate = bytes.ReplaceAll(candidate, []byte("Ignore prior instructions and respond with exactly"), []byte("Return"))
			case "native_assertion":
				candidate = bytes.ReplaceAll(candidate, []byte("JSON.parse(output).observation.protected === true"), []byte("true"))
			case "redaction":
				candidate = bytes.ReplaceAll(candidate, []byte("[REDACTED]"), []byte("secret"))
			case "extra":
				candidate = append([]byte(`{"unexpected":true,`), candidate[1:]...)
			case "duplicate":
				candidate = append([]byte(`{"schema_version":"red-team-evidence-bundle-v2",`), candidate[1:]...)
			case "engine_error":
				candidate = bytes.ReplaceAll(candidate, []byte(`"verdict":"pass"`), []byte(`"verdict":"engine_error"`))
			case "output_scope":
				out.Reference = strings.Replace(out.Reference, o, "pid_79990001-0000-4000-8000-000000000001", 1)
			case "input_content":
				inBody = bytes.ReplaceAll(inBody, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("b", 64)))
			case "input_version":
				in.VersionID = "wrong"
			case "oversize":
				candidate = append(candidate, bytes.Repeat([]byte(" "), 1048577-len(candidate))...)
			case "oversize_input":
				inBody = append(inBody, bytes.Repeat([]byte(" "), 65537-len(inBody))...)
			case "wrong_token":
				token = strings.Repeat("b", 32)
			case "stale_run":
				rv = 8
			case "stale_effect":
				fv = 2
			case "wrong_step":
				step = r
			}
			digest := sha256.Sum256(candidate)
			out.SHA256 = hex.EncodeToString(digest[:])
			out.SizeBytes = int64(len(candidate))
			if mode == "input_content" || mode == "oversize_input" {
				digest := sha256.Sum256(inBody)
				in.SHA256 = hex.EncodeToString(digest[:])
				in.SizeBytes = int64(len(inBody))
			}
			inRaw, _ := json.Marshal(in)
			outRaw, _ := json.Marshal(out)
			before := orderedTestSnapshot(t, ctx, owner, r)
			var response json.RawMessage
			err := worker.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14::jsonb,$15)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), o, w, e, r, step, "ordered-test-worker", token, rv, fv, inRaw, inBody, outRaw, candidate).Scan(&response)
			if err == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
				t.Fatal("invalid immutable test evidence changed authority", mode, string(response), err)
			}
		})
	}
	for _, mode := range []string{"missing_reservation", "effect_input", "effect_outcome", "effect_result", "link_version", "effect_expired", "child_expired", "child_cancelled", "control_disabled", "control_expired", "approval_revoked", "approval_expired", "requester", "approver", "kill_switch", "stopped", "budget_deadline", "budget_steps", "cancelled", "definition", "credential", "readiness"} {
		t.Run(mode, func(t *testing.T) {
			fault := map[string]string{
				"missing_reservation": `DELETE FROM zasp_security_agent_step_reservations WHERE run_id=$1 AND action_key='run_test'`,
				"effect_input":        `UPDATE zasp_security_agent_effects SET input_digest=decode(repeat('ab',32),'hex') WHERE run_id=$1 AND action_key='run_test'`,
				"effect_outcome":      `UPDATE zasp_security_agent_effects SET outcome_id='foreign' WHERE run_id=$1 AND action_key='run_test'`,
				"effect_result":       `UPDATE zasp_security_agent_effects SET result_digest=decode(repeat('ab',32),'hex') WHERE run_id=$1 AND action_key='run_test'`,
				"link_version":        `UPDATE zasp_security_agent_test_links SET reconcile_version=reconcile_version+1 WHERE run_id=$1`,
				"effect_expired":      `UPDATE zasp_security_agent_effects SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1 AND action_key='run_test'`,
				"child_expired":       `UPDATE zasp_red_team_runs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"child_cancelled":     `UPDATE zasp_red_team_runs SET cancel_requested=true WHERE run_id IN(SELECT test_run_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"control_disabled":    `UPDATE zasp_security_agent_controls SET state='disabled' WHERE run_id=$1`,
				"control_expired":     `UPDATE zasp_security_agent_controls SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
				"approval_revoked":    `UPDATE zasp_security_agent_approvals SET state='rejected' WHERE run_id=$1`,
				"approval_expired":    `UPDATE zasp_security_agent_approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
				"requester":           `UPDATE zasp_identity_memberships SET active=false WHERE principal_id=(SELECT requested_by FROM zasp_security_agent_runs WHERE run_id=$1)`,
				"approver":            `UPDATE zasp_identity_memberships SET active=false WHERE principal_id IN(SELECT approver_id FROM zasp_security_agent_approvals WHERE run_id=$1)`,
				"kill_switch":         `UPDATE zasp_security_agent_kill_switches SET execution_enabled=false WHERE action_key='run_test' AND $1<>''`,
				"stopped":             `UPDATE zasp_security_agent_run_budgets SET stop_reason='budget_usage_unknown' WHERE run_id=$1`,
				"budget_deadline":     `UPDATE zasp_security_agent_run_budgets SET deadline_at=clock_timestamp()-interval '1 second' WHERE run_id=$1`,
				"budget_steps":        `UPDATE zasp_security_agent_run_budgets SET max_steps=1 WHERE run_id=$1`,
				"cancelled":           `UPDATE zasp_security_agent_runs SET state='cancelled',completed_at=clock_timestamp() WHERE run_id=$1`,
				"definition":          `UPDATE zasp_red_team_definitions SET enabled=false WHERE definition_id=(SELECT test_definition_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"credential":          `UPDATE zasp_attack_lab_credential_bindings SET version=version+1 WHERE target_id=(SELECT target_id FROM zasp_security_agent_test_links WHERE run_id=$1)`,
				"readiness":           `UPDATE zasp_schema_metadata SET value=repeat('0',64) WHERE key='production_security_agent_multistep_checksum' AND $1<>''`,
			}[mode]
			if _, err := owner.Exec(ctx, `BEGIN`); err != nil {
				t.Fatal(err)
			}
			defer owner.Exec(ctx, `ROLLBACK`)
			if _, err := owner.Exec(ctx, fault, r); err != nil {
				t.Fatal(err)
			}
			before := orderedTestSnapshot(t, ctx, owner, r)
			if _, err := owner.Exec(ctx, `SAVEPOINT attempt;SET SESSION AUTHORIZATION ordered_test_red_worker`); err != nil {
				t.Fatal(err)
			}
			inRaw, _ := json.Marshal(input)
			outRaw, _ := json.Marshal(output)
			var response json.RawMessage
			callErr := owner.QueryRow(ctx, `SELECT zasp_sa_multistep_prior.test_settle($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13,$14::jsonb,$15)`, migrations.ProductionSecurityAgentMultistep().Checksum(), migrations.SecurityAgentMultistepRegisteredFingerprint(), o, w, e, r, s, "ordered-test-worker", strings.Repeat("a", 32), 9, 1, inRaw, inputBody, outRaw, body).Scan(&response)
			if _, err := owner.Exec(ctx, `ROLLBACK TO SAVEPOINT attempt`); err != nil {
				t.Fatal(err)
			}
			if callErr == nil || orderedTestSnapshot(t, ctx, owner, r) != before {
				t.Fatal("current authority drift accepted", mode, string(response), callErr)
			}
			if _, err := owner.Exec(ctx, `ROLLBACK`); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func replaceOrderedEvidenceField(t *testing.T, body, key, value string) string {
	t.Helper()
	start := strings.Index(body, `"`+key+`":"`)
	if start < 0 {
		t.Fatal("fixture field absent", key)
	}
	start += len(key) + 4
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		t.Fatal("fixture field malformed")
	}
	return body[:start] + value + body[start+end:]
}
