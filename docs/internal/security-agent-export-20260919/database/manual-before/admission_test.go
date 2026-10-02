package apiserver

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catch source-free admission that fabricates provenance, duplicates a run on
// retry, or borrows a revoked requester's authority. Only definition/control
// prerequisites are owner-seeded; API authority must create every run/receipt.
func TestSecurityAgentManualAdmissionPostgres(t *testing.T) {
	runVersionedExistingTestFixture(t, func(ctx context.Context, owner, api *pgx.Conn, o, w, e, _ string, actor string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentAttackLab(ctx); err != nil {
			t.Fatal(err)
		}
		applyExport58(t, ctx, owner)
		if _, err := owner.Exec(ctx, `
 UPDATE zasp_security_agent_definitions SET activation='supervised',body=(body-'existing_test')||jsonb_build_object('enabled',true,'autonomy','supervised','allowed_actions',jsonb_build_array('create_evidence_export'),'verification_kind','export','concurrency_limit',10,'max_ai_cost_nano_credits',1000000) WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3);
 INSERT INTO zasp_security_agent_definition_versions(organization_id,workspace_id,environment_id,definition_id,version,activation,definition,definition_digest,actor_id)
 SELECT organization_id,workspace_id,environment_id,definition_id,version,activation,body,digest(convert_to(body::text,'UTF8'),'sha256'),$4 FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)
 ON CONFLICT(organization_id,workspace_id,environment_id,definition_id,version) DO UPDATE SET activation=excluded.activation,definition=excluded.definition,definition_digest=excluded.definition_digest,actor_id=excluded.actor_id;
 INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role,active) VALUES($4,$1,'manual-admission-org','manual-admission-actor','security_admin',true) ON CONFLICT(principal_id,organization_id) DO UPDATE SET active=true,role=excluded.role;
 INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Manual admission','["view","manage_workflows","view_audit"]') ON CONFLICT(principal_id,organization_id,workspace_id,environment_id) DO UPDATE SET permissions=excluded.permissions;
 INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES($1,$2,$3,'create_evidence_export',true,$4) ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=true`, pgx.QueryExecModeSimpleProtocol, o, w, e, actor); err != nil {
			t.Fatal(err)
		}
		var definition, scheduledKind string
		var version int64
		if err := owner.QueryRow(ctx, `SELECT definition_id,version,body->>'trigger_kind' FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=($1,$2,$3)`, o, w, e).Scan(&definition, &version, &scheduledKind); err != nil {
			t.Fatal(err)
		}
		counts := func() [4]int {
			t.Helper()
			var count [4]int
			if err := owner.QueryRow(ctx, `SELECT (SELECT count(*) FROM zasp_security_agent_runs WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_request_receipts WHERE organization_id=$1),(SELECT count(*) FROM zasp_security_agent_audit WHERE organization_id=$1)`, o).Scan(&count[0], &count[1], &count[2], &count[3]); err != nil {
				t.Fatal(err)
			}
			return count
		}
		if initial := counts(); initial != [4]int{} {
			t.Fatalf("manual admission fixture already has execution authority: %v", initial)
		}
		const run = "pid_8e190001-0000-4000-8000-000000000001"
		const replacement = "pid_8e190002-0000-4000-8000-000000000002"
		const audit = "pid_8e190003-0000-4000-8000-000000000003"
		const correlation = "pid_8e190004-0000-4000-8000-000000000004"
		const receipt = "pid_8e190005-0000-4000-8000-000000000005"
		invoke := func(env, key, runID, auditID, receiptID string, expected int64) (SecurityAgentRunResult, error) {
			var raw json.RawMessage
			err := api.QueryRow(ctx, postgresSecurityAgentManualRunSQL, o, w, env, definition, actor, key, expected, runID, auditID, correlation, receiptID, migrations.ProductionSecurityAgentExports().Checksum(), migrations.SecurityAgentExportsFingerprint()).Scan(&raw)
			var value SecurityAgentRunResult
			if err == nil {
				err = json.Unmarshal(raw, &value)
			}
			return value, err
		}
		value, err := invoke(e, "manual-admission-0001", run, audit, receipt, version)
		if err != nil {
			t.Fatalf("registered manual admission: %v", err)
		}
		if !validSecurityAgentRunResult(value, SecurityAgentRunRequest{DefinitionID: definition, ExpectedVersion: version, TriggerKind: "manual"}) || value.ID != run || value.Replayed || value.AuditID != audit || value.ReceiptID != receipt || value.State != "queued" {
			t.Fatalf("invalid admitted manual result: %#v", value)
		}
		if got := counts(); got != [4]int{1, 1, 1, 1} {
			t.Fatalf("admission not atomic/singular: %v", got)
		}
		var bound bool
		if err = owner.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM zasp_security_agent_runs r JOIN zasp_security_agent_trigger_receipts t ON (t.organization_id,t.workspace_id,t.environment_id,t.run_id,t.definition_id,t.trigger_id)=(r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.definition_id,r.trigger_id) JOIN zasp_security_agent_request_receipts q ON (q.organization_id,q.workspace_id,q.environment_id,q.principal_id,q.resource_id,q.operation,q.idempotency_key)=(r.organization_id,r.workspace_id,r.environment_id,r.requested_by,r.definition_id,'runSecurityAgent','manual-admission-0001') WHERE (r.organization_id,r.workspace_id,r.environment_id,r.run_id,r.requested_by) = ($1,$2,$3,$4,$5) AND t.trigger_kind='manual' AND t.trigger_version=1 AND t.trigger_id=encode(t.trigger_digest,'hex') AND 'sha256:'||t.trigger_id=$6 AND q.response->>'id'=r.run_id AND q.response->'manual_trigger'->>'intent_digest'=$6) AND EXISTS(SELECT 1 FROM zasp_security_agent_definitions WHERE definition_id=$7 AND body->>'trigger_kind'=$8)`, o, w, e, run, actor, value.ManualTrigger.IntentDigest, definition, scheduledKind).Scan(&bound); err != nil || !bound {
			t.Fatalf("original scoped manual intent not bound: %v %v", bound, err)
		}
		replayed, err := invoke(e, "manual-admission-0001", replacement, replacement, replacement, version)
		if err != nil || !replayed.Replayed || replayed.ID != run || replayed.AuditID != audit || replayed.ReceiptID != receipt || !sameSecurityAgentManualTrigger(replayed.ManualTrigger, value.ManualTrigger) {
			t.Fatalf("lost reply changed authority: %#v %v", replayed, err)
		}
		refuse := func(label, env, key string, v int64) {
			t.Helper()
			before := counts()
			if _, err := invoke(env, key, replacement, replacement, replacement, v); err == nil {
				t.Fatalf("%s admitted", label)
			}
			if after := counts(); after != before {
				t.Fatalf("%s left writes: %v -> %v", label, before, after)
			}
		}
		refuse("changed-version replay", e, "manual-admission-0001", version+1)
		refuse("foreign scope", replacement, "manual-admission-0002", version)
		if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		refuse("revoked requester replay", e, "manual-admission-0001", version)
		refuse("revoked requester new intent", e, "manual-admission-0002", version)
		if _, err = owner.Exec(ctx, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2)`, o, actor); err != nil {
			t.Fatal(err)
		}
		next, err := invoke(e, "manual-admission-0002", replacement, replacement, replacement, version)
		if err != nil || next.ManualTrigger == nil || next.ManualTrigger.IntentDigest == value.ManualTrigger.IntentDigest || !strings.HasPrefix(next.ManualTrigger.IntentDigest, "sha256:") {
			t.Fatalf("new explicit intent did not get distinct receipt: %#v %v", next, err)
		}
		if got := counts(); got != [4]int{2, 2, 2, 2} {
			t.Fatalf("replay/refusal duplicated admission: %v", got)
		}
	})
}
