package apiserver

import (
	"context"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProductionTypedInventoryCutoverPostgresRefreshesAllEvidenceBackedPostureFindings(t *testing.T) {
	dsn := startDisposablePostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	migrateToTypedInventoryCutover(t, ctx, connection)

	identity := fixtureRequestIdentity(t)
	scope := identity.Scope
	agentID := "pid_74400001-0000-4000-8000-000000000001"
	evidenceID := "pid_74400002-0000-4000-8000-000000000002"
	foreignAgentID := "pid_74400003-0000-4000-8000-000000000003"
	foreignFindingID := "pid_74400004-0000-4000-8000-000000000004"
	foreignOrganizationID := "pid_74400005-0000-4000-8000-000000000005"
	sharedAgentID := "pid_74400006-0000-4000-8000-000000000006"
	zombieAgentID := "pid_74400007-0000-4000-8000-000000000007"
	sharedEvidenceID := "pid_74400008-0000-4000-8000-000000000008"
	zombieEvidenceID := "pid_74400009-0000-4000-8000-000000000009"
	posture := `{"human_credential":true,"credential_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","untrusted_input":true,"production_write":true,"shell_execution":true,"production_credential":true,"unrestricted_egress":true,"sensitive_data_reach":true,"unapproved_remote_tool":true,"destructive_tool":true,"runtime_control":false,"production_agent":true,"runtime_policy_supported":false,"host_filesystem":true,"privileged":true,"cicd_write":true,"production_secret_reach":true,"credential_active":true}`
	quietPosture := `{"human_credential":false,"credential_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","untrusted_input":false,"production_write":false,"shell_execution":false,"production_credential":false,"unrestricted_egress":false,"sensitive_data_reach":false,"unapproved_remote_tool":false,"destructive_tool":false,"runtime_control":true,"production_agent":false,"runtime_policy_supported":true,"host_filesystem":false,"privileged":false,"cicd_write":false,"production_secret_reach":false,"credential_active":true}`
	zombiePosture := `{"human_credential":false,"credential_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","untrusted_input":false,"production_write":false,"shell_execution":false,"production_credential":false,"unrestricted_egress":false,"sensitive_data_reach":false,"unapproved_remote_tool":false,"destructive_tool":false,"runtime_control":true,"production_agent":false,"runtime_policy_supported":true,"host_filesystem":false,"privileged":false,"cicd_write":false,"production_secret_reach":false,"credential_active":true}`
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_entities(
		organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,state,first_seen_at,last_seen_at,tombstoned_at,
		product_kind,winning_evidence_id,observed_at,fresh_until,winning_attributes
	) VALUES
		($1,$2,$3,$4,'agent','Production agent','{}','active',$8,$8,NULL,'agent',$5,$8,$9,jsonb_build_object('posture',$10::jsonb)),
		($1,$2,$3,$11,'agent','Shared credential agent','{}','active',$8,$8,NULL,'agent',$12,$8,$9,jsonb_build_object('posture',$13::jsonb)),
		($1,$2,$3,$14,'agent','Inactive agent','{}','tombstoned',$8,$8,$8,'agent',$15,$8,$9,jsonb_build_object('posture',$16::jsonb)),
		($6,$2,$3,$7,'agent','Foreign agent','{}','active',$8,$8,NULL,'agent',$5,$8,$9,'{}')`,
		scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), agentID, evidenceID,
		foreignOrganizationID, foreignAgentID, now, now.Add(time.Hour), posture, sharedAgentID, sharedEvidenceID, quietPosture, zombieAgentID, zombieEvidenceID, zombiePosture); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_annotations(organization_id,workspace_id,environment_id,entity_id,owner_value) VALUES($1,$2,$3,$4,'security-team')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), sharedAgentID); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `INSERT INTO zasp_risk_findings(
		organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,agent_id,compliance_context
	) VALUES($1,$2,$3,$4,'posture','ownerless_agent','Agent has no owner','high','open',$5,'zasp-posture:ownerless_agent')`,
		foreignOrganizationID, scope.WorkspaceID().String(), scope.EnvironmentID().String(), foreignFindingID, foreignAgentID); err != nil {
		t.Fatal(err)
	}

	var result []byte
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_refresh_posture_findings($1,$2,$3)`,
		scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&result); err != nil {
		t.Fatalf("refresh ownerless posture: %v", err)
	}
	var findingID, source, rule, title, severity, status, storedAgentID, storedEvidenceID string
	if err := connection.QueryRow(ctx, `SELECT finding.id,finding.source,finding.rule,finding.title,finding.severity,finding.status,finding.agent_id,evidence.evidence_id
		FROM zasp_risk_findings finding
		JOIN zasp_risk_finding_evidence evidence ON
		 (evidence.organization_id,evidence.workspace_id,evidence.environment_id,evidence.finding_id)=
		 (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id)
		WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.rule)=($1,$2,$3,'ownerless_agent')`,
		scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(
		&findingID, &source, &rule, &title, &severity, &status, &storedAgentID, &storedEvidenceID); err != nil {
		t.Fatal(err)
	}
	if !validProductID(findingID) || source != "posture" || rule != "ownerless_agent" || title != "Agent has no owner" || severity != "high" || status != "open" || storedAgentID != agentID || storedEvidenceID != evidenceID {
		t.Fatalf("ownerless finding=%s %s %s %s %s %s %s %s result=%s", findingID, source, rule, title, severity, status, storedAgentID, storedEvidenceID, result)
	}
	rows, err := connection.Query(ctx, `SELECT DISTINCT rule FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,source,status)=($1,$2,$3,'posture','open') ORDER BY rule`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String())
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rules = append(rules, value)
	}
	rows.Close()
	wantRules := []string{"ownerless_agent", "human_credential", "shared_credential", "untrusted_production_write", "shell_credential", "egress_sensitive", "unapproved_tool", "destructive_no_control", "no_runtime_coverage", "weak_runtime_isolation", "cicd_production_secret", "zombie_credential"}
	sort.Strings(wantRules)
	if string(mustJSON(t, rules)) != string(mustJSON(t, wantRules)) {
		t.Fatalf("posture rules=%v want=%v", rules, wantRules)
	}
	var evidenceCount int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_risk_finding_evidence evidence JOIN zasp_risk_findings finding ON (finding.organization_id,finding.workspace_id,finding.environment_id,finding.id)=(evidence.organization_id,evidence.workspace_id,evidence.environment_id,evidence.finding_id) WHERE (finding.organization_id,finding.workspace_id,finding.environment_id,finding.source) = ($1,$2,$3,'posture')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&evidenceCount); err != nil || evidenceCount != 13 {
		t.Fatalf("posture evidence count=%d err=%v", evidenceCount, err)
	}

	if _, err := connection.Exec(ctx, `INSERT INTO zasp_inventory_annotations(organization_id,workspace_id,environment_id,entity_id,owner_value)
		VALUES($1,$2,$3,$4,'security-team')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), agentID); err != nil {
		t.Fatal(err)
	}
	falsePosture := `{"human_credential":false,"credential_fingerprint":"","untrusted_input":false,"production_write":false,"shell_execution":false,"production_credential":false,"unrestricted_egress":false,"sensitive_data_reach":false,"unapproved_remote_tool":false,"destructive_tool":false,"runtime_control":true,"production_agent":false,"runtime_policy_supported":true,"host_filesystem":false,"privileged":false,"cicd_write":false,"production_secret_reach":false,"credential_active":false}`
	if _, err := connection.Exec(ctx, `UPDATE zasp_inventory_entities SET winning_attributes=jsonb_build_object('posture',$1::jsonb) WHERE (organization_id,workspace_id,environment_id,id) IN (($2,$3,$4,$5),($2,$3,$4,$6),($2,$3,$4,$7))`, falsePosture, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), agentID, sharedAgentID, zombieAgentID); err != nil {
		t.Fatal(err)
	}
	if err := connection.QueryRow(ctx, `SELECT zasp_inventory_refresh_posture_findings($1,$2,$3)`,
		scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&result); err != nil {
		t.Fatalf("refresh owned posture: %v", err)
	}
	if err := connection.QueryRow(ctx, `SELECT status FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`,
		scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), findingID).Scan(&status); err != nil || status != "resolved" {
		t.Fatalf("resolved ownerless finding status=%q err=%v", status, err)
	}
	var foreignStatus string
	if err := connection.QueryRow(ctx, `SELECT status FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,id)=($1,$2,$3,$4)`,
		foreignOrganizationID, scope.WorkspaceID().String(), scope.EnvironmentID().String(), foreignFindingID).Scan(&foreignStatus); err != nil || foreignStatus != "open" {
		t.Fatalf("foreign finding status=%q err=%v", foreignStatus, err)
	}
	var unresolved int
	if err := connection.QueryRow(ctx, `SELECT count(*) FROM zasp_risk_findings WHERE (organization_id,workspace_id,environment_id,source,status)=($1,$2,$3,'posture','open')`, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String()).Scan(&unresolved); err != nil || unresolved != 0 {
		t.Fatalf("unresolved posture findings=%d err=%v", unresolved, err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
