package apiserver

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
)

// Catch an unregistered release, a broken exact predecessor upgrade or missing
// source authority through the real canonical migration chain.
func TestComplianceRegisteredSourceAuthorityPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, dsn string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		registered, ok := any(runner).(interface{ UpProductionCompliance(context.Context) error })
		if !ok {
			t.Fatal("release56 compliance source authority is not registered")
		}
		if err := registered.UpProductionCompliance(ctx); err != nil {
			t.Fatal(err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 56 {
			t.Fatalf("release=%d: %v", version, err)
		}
		var present bool
		if err := owner.QueryRow(ctx, `SELECT to_regprocedure('public.zasp_compliance_read(text,text,text,text,bytea,text,jsonb,text,text)') IS NOT NULL`).Scan(&present); err != nil || !present {
			t.Fatalf("scoped source authority absent: %v", err)
		}
		exerciseComplianceSources(t, ctx, owner, dsn)
		for _, mutation := range []string{
			`UPDATE zasp_schema_versions SET checksum=repeat('f',64) WHERE version=53`,
			`UPDATE zasp_schema_versions SET checksum=repeat('f',64) WHERE version=54`,
			`ALTER FUNCTION zasp_compliance_configuration(text,text,text) OWNER TO zasp_discovery_authority`,
			`GRANT EXECUTE ON FUNCTION zasp_compliance_configuration(text,text,text) TO zasp_discovery_api`,
			`INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(57,'unknown',repeat('0',64))`,
			`UPDATE zasp_schema_metadata SET value=repeat('f',64) WHERE key='production_security_agent_existing_tests_checksum'`,
			`ALTER FUNCTION zasp_production_security_agent_existing_tests_client_ready(text,text) RESET search_path`,
			`GRANT EXECUTE ON FUNCTION zasp_compliance_sources(text,text,text) TO PUBLIC`,
			`ALTER FUNCTION zasp_compliance_read(text,text,text,text,bytea,text,jsonb,text,text) RESET search_path`,
		} {
			if _, err := owner.Exec(ctx, "BEGIN"); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Exec(ctx, mutation); err != nil {
				t.Fatal(err)
			}
			var ready bool
			err := owner.QueryRow(ctx, `SELECT zasp_compliance_readiness($1,$2)`, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&ready)
			if _, e := owner.Exec(ctx, "ROLLBACK"); e != nil {
				t.Fatal(e)
			}
			if err != nil || ready {
				t.Fatalf("catalog drift accepted %s: %v", mutation, err)
			}
		}
		if err := runner.DownProductionCompliance(ctx); err != nil {
			t.Fatalf("rollback: %v", err)
		}
		if version, err := runner.Version(ctx); err != nil || version != 55 {
			t.Fatalf("rollback version%d: %v", version, err)
		}
	})
}

const complianceOrg = "pid_6a000001-0000-4000-8000-000000000001"
const complianceWorkspace = "pid_6a000002-0000-4000-8000-000000000002"
const complianceEnvironment = "pid_6a000003-0000-4000-8000-000000000003"
const compliancePrincipal = "pid_6a000009-0000-4000-8000-000000000009"

func exerciseComplianceSources(t *testing.T, ctx context.Context, owner *pgx.Conn, dsn string) {
	t.Helper()
	digest := sha256.Sum256([]byte("owned-compliance-session"))
	seed := func(sql string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, sql, append([]any{pgx.QueryExecModeSimpleProtocol}, args...)...); err != nil {
			t.Fatalf("source fixture: %v", err)
		}
	}
	seed(`INSERT INTO zasp_identity_memberships(principal_id,organization_id,organization_reference,member_reference,role) VALUES($4,$1,'compliance-fixture','compliance-reviewer','compliance_viewer');
INSERT INTO zasp_authorized_scopes(principal_id,organization_id,workspace_id,environment_id,label,permissions) VALUES($4,$1,$2,$3,'Compliance fixture','["view","view_audit","view_compliance"]');
INSERT INTO zasp_product_sessions(token_digest,principal_id,organization_id,workspace_id,environment_id,permissions,csrf_token,expires_at,authenticated_at) VALUES($5,$4,$1,$2,$3,'["view","view_audit","view_compliance"]',repeat('c',32),clock_timestamp()+interval '1 hour',clock_timestamp());
INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled,migration_seeded) VALUES($1,$2,$3,'staging','metadata_only',30,true,true);
INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body,created_at,updated_at) SELECT $1,$2,$3,'policy','policy-'||lpad(n::text,3,'0'),7,'{"secret":"DO_NOT_EXPORT"}','2026-01-01','2026-01-02' FROM generate_series(1,105) n;
INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,version,body) VALUES($1,$2,'pid_56000003-0000-4000-8000-000000000003','policy','policy-001',99,'{}');
INSERT INTO zasp_compliance_controls(organization_id,id,framework,name,fresh_until) VALUES($1,'legacy-control','SOC 2','Legacy seed',clock_timestamp()+interval '1 day');
INSERT INTO zasp_compliance_evidence(organization_id,control_id,id,asset_id,source,at) VALUES($1,'legacy-control','legacy-seed','asset-seed','runtime',clock_timestamp());
INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,title,severity,status,version,created_at,updated_at) VALUES($1,$2,$3,'pid_56000004-0000-4000-8000-000000000004','posture','safe title','high','open',3,'2026-01-01','2026-01-03');
INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES($1,$2,$3,'pid_56000004-0000-4000-8000-000000000004',1,'pid_56000005-0000-4000-8000-000000000005');
INSERT INTO zasp_admin_audit(organization_id,workspace_id,environment_id,id,actor_id,action,target_id,outcome,metadata,occurred_at) VALUES($1,$2,$3,'pid_56000006-0000-4000-8000-000000000006',$4,'fixture.review',$4,'succeeded','{"secret":"DO_NOT_EXPORT"}','2026-01-04');
INSERT INTO zasp_workflow_audit(organization_id,workspace_id,environment_id,audit_id,principal_id,operation,resource_kind,resource_id,resource_version,correlation_id,created_at) VALUES($1,$2,$3,'pid_56000007-0000-4000-8000-000000000007',$4,'updatePolicy','policy','policy-001',7,'pid_56000008-0000-4000-8000-000000000008','2026-01-05');`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, digest[:])
	seedComplianceCompletedTests(t, ctx, owner)
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User = "security_agent_v33_discovery_api_login"
	api, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close(context.Background())
	database, err := NewPostgresJSONDatabase(&integrationPostgresDriver{connection: api})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := NewComplianceRepository(database)
	if err != nil {
		t.Fatalf("registered adapter: %v", err)
	}
	o, _ := domain.ParseProductID(complianceOrg)
	w, _ := domain.ParseProductID(complianceWorkspace)
	e, _ := domain.ParseProductID(complianceEnvironment)
	p, _ := domain.ParseProductID(compliancePrincipal)
	scope, _ := domain.NewScope(o, w, e)
	identity := RequestIdentity{Scope: scope, PrincipalID: p, CredentialKind: CredentialBrowserSession, Permissions: []string{"view", "view_audit", "view_compliance"}}
	if _, err := repository.ListEvidence(ctx, identity, digest[:], ComplianceListOptions{Limit: 100}); err != nil {
		t.Fatalf("registered typed list: %v", err)
	}
	first, err := repository.ListEvidence(ctx, identity, digest[:], ComplianceListOptions{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.ListEvidence(ctx, identity, digest[:], ComplianceListOptions{Limit: 100, Cursor: first.NextCursor})
	if err != nil || len(first.Items) != 100 || len(second.Items) != 12 || len(second.NextCursor) != 0 {
		t.Fatalf("typed keyset traversal first%d second%d: %v", len(first.Items), len(second.Items), err)
	}
	if _, err := repository.ListControls(ctx, identity, digest[:], ComplianceListOptions{Framework: "soc2_security"}); err != nil {
		t.Fatalf("registered typed controls: %v", err)
	}
	if _, err := repository.GetEvidence(ctx, identity, digest[:], ComplianceTarget{SourceKind: "policy", SourceID: "policy-001", SourceVersion: 6}); !errors.Is(err, ErrComplianceSourceChanged) {
		t.Fatalf("typed source_changed: %v", err)
	}
	if _, err := api.Exec(ctx, `SELECT * FROM zasp_compliance_configuration($1,$2,$3)`, complianceOrg, complianceWorkspace, complianceEnvironment); auditExportSQLState(err) != "42501" {
		t.Fatalf("private configuration helper callable: %v", err)
	}
	if _, err := api.Exec(ctx, `SELECT zasp_compliance_read($1,$2,$3,$4,$5,NULL,'{}',$6,$7)`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, digest[:], migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()); auditExportSQLState(err) != "22023" {
		t.Fatalf("NULL operation accepted: %v", err)
	}
	read := func(op string, params any) (json.RawMessage, error) {
		body, _ := json.Marshal(params)
		var raw json.RawMessage
		err := api.QueryRow(ctx, `SELECT zasp_compliance_read($1,$2,$3,$4,$5,$6,$7,$8,$9)`, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, digest[:], op, body, migrations.ProductionCompliance().Checksum(), migrations.ComplianceFingerprint()).Scan(&raw)
		return raw, err
	}
	var cursor json.RawMessage
	seen := map[string]bool{}
	kinds := map[string]bool{}
	pages := 0
	for {
		params := map[string]any{"limit": 100}
		if cursor != nil {
			params["cursor"] = cursor
		}
		raw, err := read("listEvidence", params)
		if err != nil {
			t.Fatalf("scoped list: %v", err)
		}
		if strings.Contains(string(raw), "DO_NOT_EXPORT") || strings.Contains(string(raw), "legacy-seed") || strings.Contains(string(raw), "s3://") {
			t.Fatalf("unsafe source projection: %s", raw)
		}
		var page struct {
			Items []struct {
				ID             string `json:"id"`
				OrganizationID string `json:"organization_id"`
				WorkspaceID    string `json:"workspace_id"`
				EnvironmentID  string `json:"environment_id"`
				Target         struct {
					Kind    string `json:"source_kind"`
					ID      string `json:"source_id"`
					Version int64  `json:"source_version"`
				} `json:"target"`
				Timestamp string         `json:"timestamp"`
				Metadata  map[string]any `json:"metadata"`
			} `json:"items"`
			Next json.RawMessage `json:"next_cursor"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatal(err)
		}
		for _, item := range page.Items {
			if item.OrganizationID != complianceOrg || item.WorkspaceID != complianceWorkspace || item.EnvironmentID != complianceEnvironment {
				t.Fatalf("foreign scope projection: %+v", item)
			}
			if item.Target.Kind != "policy" && item.Target.Kind != "configuration" {
				want := map[string]struct {
					id, stamp string
					version   int64
				}{
					"administration":    {"pid_56000006-0000-4000-8000-000000000006", "2026-01-04T00:00:00.000000Z", 1},
					"workflow_policy":   {"pid_56000007-0000-4000-8000-000000000007", "2026-01-05T00:00:00.000000Z", 1},
					"red_team_mutation": {"pid_56000015-0000-4000-8000-000000000015", "2026-01-07T00:00:00.000000Z", 1},
					"finding":           {"pid_56000004-0000-4000-8000-000000000004", "2026-01-03T00:00:00.000000Z", 3},
					"red_team_test":     {"pid_56000012-0000-4000-8000-000000000012", "2026-01-06T00:00:00.000000Z", 1},
					"attack_lab_test":   {"pid_56000013-0000-4000-8000-000000000013", "2026-01-06T00:00:00.000000Z", 1},
				}[item.Target.Kind]
				if item.Target.ID != want.id || item.Target.Version != want.version || item.Timestamp != want.stamp {
					t.Fatalf("source identity/version/time: %+v", item)
				}
			}
			key := item.Target.Kind + ":" + item.Target.ID
			if seen[key] {
				t.Fatalf("duplicate page key%s", key)
			}
			seen[key] = true
			kinds[item.Target.Kind] = true
			if item.Target.Kind == "policy" && (item.Target.Version != 7 || item.Timestamp != "2026-01-02T00:00:00.000000Z") {
				t.Fatalf("sibling/version/time leaked: %+v", item)
			}
			if item.Target.Kind == "configuration" && (item.Metadata["migration_seeded"] != true || item.Metadata["verification"] != "unverified") {
				t.Fatalf("seeded config misrepresented: %+v", item)
			}
			if strings.HasSuffix(item.Target.Kind, "_test") && (item.Target.Version != 1 || item.Metadata["definition_version"] != float64(1)) {
				t.Fatalf("completed history rebound: %+v", item)
			}
		}
		pages++
		if string(page.Next) == "null" {
			break
		}
		cursor = page.Next
		if pages > 5 {
			t.Fatal("cursor did not terminate")
		}
	}
	if pages != 2 || len(seen) != 112 {
		t.Fatalf("incomplete source traversal pages%d records%d: %v", pages, len(seen), kinds)
	}
	for _, kind := range []string{"administration", "workflow_policy", "red_team_mutation", "finding", "policy", "red_team_test", "attack_lab_test", "configuration"} {
		if !kinds[kind] {
			t.Errorf("missing source%s", kind)
		}
	}
	for _, tc := range []struct {
		params any
		code   string
	}{
		{map[string]any{"source_kind": "policy", "source_id": "policy-001", "source_version": 6}, "40001"},
		{map[string]any{"source_kind": "policy", "source_id": "policy-missing"}, "P0002"},
		{map[string]any{"source_kind": "unknown", "source_id": "policy-001"}, "22023"},
		{map[string]any{"source_kind": "policy", "source_id": "policy-001", "organization_id": complianceOrg}, "22023"},
	} {
		if _, err := read("getEvidence", tc.params); auditExportSQLState(err) != tc.code {
			t.Errorf("target rejection%s: %v", tc.code, err)
		}
	}
	if raw, err := read("getEvidence", map[string]any{"source_kind": "policy", "source_id": "policy-001", "source_version": 7}); err != nil || !strings.Contains(string(raw), `"freshness": "stale"`) {
		t.Fatalf("typed policy detail=%s %v", raw, err)
	}
	for _, params := range []any{map[string]any{"cursor": map[string]any{}}, map[string]any{"limit": 101}, map[string]any{"framework": "unknown"}, map[string]any{"environment_id": complianceEnvironment}} {
		if _, err := read("listEvidence", params); auditExportSQLState(err) != "22023" {
			t.Errorf("bad page accepted: %v", err)
		}
	}
	var foreign map[string]any
	_ = json.Unmarshal(cursor, &foreign)
	foreign["environment_id"] = "pid_56000003-0000-4000-8000-000000000003"
	if _, err := read("listEvidence", map[string]any{"cursor": foreign}); auditExportSQLState(err) != "22023" {
		t.Fatalf("foreign cursor accepted: %v", err)
	}
	if raw, err := read("listControls", map[string]any{"framework": "soc2_security"}); err != nil || !strings.Contains(string(raw), `"freshness": "missing"`) || !strings.Contains(string(raw), `"freshness": "stale"`) {
		t.Fatalf("control freshness=%s %v", raw, err)
	}
	for _, tc := range []struct {
		sql    string
		op     string
		params any
		code   string
	}{
		{`UPDATE zasp_identity_memberships SET active=false WHERE organization_id=$1`, "listEvidence", map[string]any{}, "42501"},
		{`UPDATE zasp_identity_memberships SET role='read_only_viewer' WHERE organization_id=$1`, "listEvidence", map[string]any{}, "42501"},
		{`UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE organization_id=$1`, "listEvidence", map[string]any{}, "28000"},
		{`UPDATE zasp_workflow_records SET deleted_at=clock_timestamp() WHERE organization_id=$1 AND id='policy-001'`, "getEvidence", map[string]any{"source_kind": "policy", "source_id": "policy-001"}, "P0002"},
		{`UPDATE zasp_workflow_audit SET resource_version=0 WHERE organization_id=$1`, "listEvidence", map[string]any{"control_id": "soc2_security-configuration"}, "55000"},
	} {
		// Visibility to the API requires committed fixture edits; save and restore
		// the affected rows using a database transaction on this API connection.
		seed("BEGIN")
		seed(tc.sql, complianceOrg)
		seed("COMMIT")
		_, err := read(tc.op, tc.params)
		if auditExportSQLState(err) != tc.code {
			t.Errorf("revocation/source rejection%s SQL%s: %v", tc.code, tc.sql, err)
		}
		seed(`UPDATE zasp_identity_memberships SET active=true,role='compliance_viewer' WHERE organization_id=$1;
UPDATE zasp_authorized_scopes SET permissions='["view","view_audit","view_compliance"]' WHERE organization_id=$1;
UPDATE zasp_product_sessions SET revoked_at=NULL WHERE organization_id=$1;
UPDATE zasp_workflow_records SET deleted_at=NULL WHERE organization_id=$1;
UPDATE zasp_workflow_audit SET resource_version=7 WHERE organization_id=$1;`, complianceOrg)
	}
	assertComplianceRevokedWhileBlocked(t, ctx, owner, api, repository, identity, digest[:])
	var ready bool
	if err := api.QueryRow(ctx, `SELECT zasp_production_security_agent_existing_tests_client_ready($1,$2)`, migrations.ProductionSecurityAgentExistingTests().Checksum(), migrations.SecurityAgentExistingTestsFingerprint()).Scan(&ready); err != nil || !ready {
		t.Fatalf("predecessor55 API readiness: %v", err)
	}
}

// Catch authorization from a pre-wait snapshot: revocation commits only after
// PostgreSQL proves the registered reader is blocked behind the authority row.
func assertComplianceRevokedWhileBlocked(t *testing.T, ctx context.Context, owner, api *pgx.Conn, repository *ComplianceRepository, identity RequestIdentity, digest []byte) {
	t.Helper()
	for _, tc := range []struct {
		name, revoke, restore string
		want                  error
	}{
		{"session", `UPDATE zasp_product_sessions SET revoked_at=clock_timestamp() WHERE token_digest=$1`, `UPDATE zasp_product_sessions SET revoked_at=NULL WHERE token_digest=$1`, ErrRepositoryAuthentication},
		{"membership", `UPDATE zasp_identity_memberships SET active=false WHERE (organization_id,principal_id)=($1,$2)`, `UPDATE zasp_identity_memberships SET active=true WHERE (organization_id,principal_id)=($1,$2)`, ErrComplianceForbidden},
	} {
		t.Run("revoked_while_blocked_"+tc.name, func(t *testing.T) {
			waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			blocker, err := pgx.ConnectConfig(waitCtx, owner.Config().Copy())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cleanupCancel()
				if err := blocker.Close(cleanupCtx); err != nil {
					t.Errorf("close authority blocker: %v", err)
				}
			}()
			tx, err := blocker.Begin(waitCtx)
			if err != nil {
				t.Fatal(err)
			}
			args := []any{complianceOrg, compliancePrincipal}
			if tc.name == "session" {
				args = []any{digest}
			}
			defer func() {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cleanupCancel()
				if err := tx.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
					t.Errorf("release authority lock: %v", err)
				}
				if _, err := owner.Exec(cleanupCtx, tc.restore, args...); err != nil {
					t.Errorf("restore owned authority fixture: %v", err)
				}
			}()
			if tag, err := tx.Exec(waitCtx, tc.revoke, args...); err != nil || tag.RowsAffected() != 1 {
				t.Fatalf("hold exact authority update: rows=%d err=%v", tag.RowsAffected(), err)
			}
			type result struct {
				page ComplianceEvidencePage
				err  error
			}
			done := make(chan result, 1)
			joined := false
			defer func() {
				if !joined {
					cancel()
					cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cleanupCancel()
					_ = tx.Rollback(cleanupCtx)
					select {
					case <-done:
					case <-cleanupCtx.Done():
						t.Error("blocked compliance reader did not join after cancellation")
					}
				}
			}()
			go func() {
				page, err := repository.ListEvidence(waitCtx, identity, digest, ComplianceListOptions{Limit: 100})
				done <- result{page: page, err: err}
			}()
			readerPID, blockerPID := api.PgConn().PID(), blocker.PgConn().PID()
			for {
				var blocked bool
				if err := owner.QueryRow(waitCtx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer)) AND EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$2::integer AND wait_event_type='Lock')`, blockerPID, readerPID).Scan(&blocked); err != nil {
					t.Fatalf("observe exact authority lock wait: %v", err)
				}
				if blocked {
					break
				}
				select {
				case got := <-done:
					joined = true
					t.Fatalf("reader returned before observed authority wait: evidence=%d err=%v", len(got.page.Items), got.err)
				default:
				}
			}
			if err := tx.Commit(waitCtx); err != nil {
				t.Fatalf("commit concurrent authority revocation: %v", err)
			}
			select {
			case got := <-done:
				joined = true
				if !errors.Is(got.err, tc.want) || got.page.Items != nil || got.page.CollectedAt != "" || got.page.MappingRevision != "" || len(got.page.NextCursor) != 0 {
					t.Fatalf("post-wait authority returned evidence: page=%+v err=%v want=%v", got.page, got.err, tc.want)
				}
				t.Logf("observed reader PID %d blocked by %s updater PID %d; committed revocation denied without evidence", readerPID, tc.name, blockerPID)
			case <-waitCtx.Done():
				t.Fatalf("revoked reader failed to finish: %v", waitCtx.Err())
			}
		})
	}
}

func seedComplianceCompletedTests(t *testing.T, ctx context.Context, owner *pgx.Conn) {
	t.Helper()
	const target = "pid_56000010-0000-4000-8000-000000000010"
	const definition = "pid_56000011-0000-4000-8000-000000000011"
	const run = "pid_56000012-0000-4000-8000-000000000012"
	const lab = "pid_56000013-0000-4000-8000-000000000013"
	const binding = "pid_56000014-0000-4000-8000-000000000014"
	_, err := owner.Exec(ctx, `UPDATE zasp_environments SET environment_class='staging' WHERE id=$3;
INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes) VALUES($1,$2,$3,$5,'agent_endpoint','Compliance test target','active',now(),now(),'agent',now(),now()+interval '1 hour','{}');
INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,name,target_id,target_kind,categories,safety,created_by) VALUES($1,$2,$3,$6,'Compliance test',$5,'agent_endpoint','["prompt_injection"]','{"environment":"staging","credential_class":"read_only","expected_side_effects":[]}', $4);
INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,requested_by,state,attempt,input_digest,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) VALUES($1,$2,$3,$7,$6,1,$4,'complete',1,digest('input','sha256'),'pass','s3://fixture/output','output','version-one',digest('output','sha256'),100,'2026-01-06');
INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) SELECT organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,'Controlled test','Controlled behavior','[]',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at FROM zasp_red_team_runs WHERE run_id=$7;
INSERT INTO zasp_attack_lab_credential_bindings(organization_id,workspace_id,environment_id,binding_id,target_id,credential_reference,credential_class,version,reference_digest,state,valid_until) VALUES($1,$2,$3,$9,$5,'ref:red-team/compliance_test','read_only',1,digest('credential','sha256'),'active',clock_timestamp()+interval '1 hour');
INSERT INTO zasp_attack_lab_runs(organization_id,workspace_id,environment_id,run_id,source_run_id,definition_id,definition_version,target_id,target_kind,environment,credential_class,destination,credential_binding_id,credential_binding_version,credential_binding_digest,requested_by,state,attempt,attempt_started_at,input_digest,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at,cleanup_state) SELECT $1,$2,$3,$8,$7,$6,1,$5,'agent_endpoint','staging','read_only','fixture.invalid',$9,1,digest('credential','sha256'),$4,'complete',1,clock_timestamp(),input_digest,'not_reproduced',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at,'complete' FROM zasp_red_team_runs WHERE run_id=$7;
INSERT INTO zasp_attack_lab_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,evidence_state,verdict,criterion_observed,canary_touched,cleanup_completed,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at) SELECT $1,$2,$3,$8,1,input_digest,'complete','not_reproduced',false,false,true,'["semantic:ok","gateway:ok","egress:ok","kubernetes:ok","cloud:ok"]',evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at FROM zasp_red_team_runs WHERE run_id=$7;
INSERT INTO zasp_red_team_audit(organization_id,workspace_id,environment_id,audit_id,correlation_id,receipt_id,actor_id,event_kind,resource_id,event_digest,body,created_at) VALUES($1,$2,$3,'pid_56000015-0000-4000-8000-000000000015','pid_56000016-0000-4000-8000-000000000016','pid_56000017-0000-4000-8000-000000000017',$4,'red_team_definition_updated',$6,digest('event','sha256'),'{}','2026-01-07');
UPDATE zasp_red_team_definitions SET version=2 WHERE definition_id=$6;`, pgx.QueryExecModeSimpleProtocol, complianceOrg, complianceWorkspace, complianceEnvironment, compliancePrincipal, target, definition, run, lab, binding)
	if err != nil {
		t.Fatal(fmt.Errorf("completed test fixtures: %w", err))
	}
}

// Calibration observes an owned fixture. Runtime callers only use compiled pins.
func TestComplianceCompiledFingerprintPostgres(t *testing.T) {
	runSecurityAgentBudgetFixture(t, func(ctx context.Context, owner *pgx.Conn, _ string) {
		runner := precisionMigrationRunner(t, owner)
		if err := runner.UpProductionSecurityAgentRunContext(ctx); err != nil {
			t.Fatal(err)
		}
		if err := runner.UpProductionSecurityAgentExistingTests(ctx); err != nil {
			t.Fatal(err)
		}
		metadata := migrations.ProductionCompliance()
		if _, err := owner.Exec(ctx, metadata.UpSQL()); err != nil {
			var pg *pgconn.PgError
			if errors.As(err, &pg) {
				t.Logf("postgres diagnostic: %#v", pg)
				if pg.Position > 0 {
					p := int(pg.Position) - 1
					t.Logf("near: %s", metadata.UpSQL()[max(0, p-250):min(len(metadata.UpSQL()), p+250)])
				}
			}
			t.Fatalf("compliance migration: %v", err)
		}
		if _, err := owner.Exec(ctx, `INSERT INTO zasp_schema_metadata(key,value) VALUES('production_compliance_checksum',$1),('production_compliance_fingerprint',$2); INSERT INTO zasp_schema_versions(version,name,checksum) VALUES(56,'production_compliance',$1)`, pgx.QueryExecModeSimpleProtocol, metadata.Checksum(), migrations.ComplianceFingerprint()); err != nil {
			t.Fatal(err)
		}
		var live string
		if err := owner.QueryRow(ctx, `SELECT zasp_compliance_live_fingerprint()`).Scan(&live); err != nil {
			t.Fatal(err)
		}
		if live != migrations.ComplianceFingerprint() {
			t.Fatalf("compiled compliance fingerprint differs: actual=%s", live)
		}
		t.Logf("release56 checksum=%s fingerprint=%s", metadata.Checksum(), live)
	})
}
